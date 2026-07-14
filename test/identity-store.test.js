import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { MemoryIdentityStore, publicUser } from '../src/repositories/identity-store.js';

function userInput(overrides = {}) {
  return {
    realm: 'master',
    username: 'alice',
    email: 'alice@example.test',
    passwordHash: 'argon2-hash-placeholder',
    roles: ['member'],
    groups: ['/engineering'],
    clientRoles: { console: ['read'] },
    ...overrides,
  };
}

test('users and login lookups are isolated by realm', async () => {
  const store = new MemoryIdentityStore();
  const sharedId = 'c60f017b-a586-4106-9914-217d586e3300';
  const masterUser = await store.createUser(userInput({ id: sharedId }));
  const staffUser = await store.createUser(userInput({ id: sharedId, realm: 'staff' }));

  assert.equal((await store.findUserById('master', sharedId)).realm, 'master');
  assert.equal((await store.findUserById('staff', sharedId)).realm, 'staff');
  assert.equal(await store.findUserById('other', sharedId), null);
  assert.equal((await store.findUserByLogin('master', ' ALICE ')).id, masterUser.id);
  assert.equal((await store.findUserByLogin('staff', 'Alice@Example.Test')).id, staffUser.id);
  assert.deepEqual((await store.listUsers('master')).map((user) => user.realm), ['master']);
  assert.deepEqual((await store.listUsers('staff')).map((user) => user.realm), ['staff']);
});

test('identity uniqueness is case-insensitive inside a realm but independent across realms', async () => {
  const store = new MemoryIdentityStore();
  await store.createUser(userInput());

  await assert.rejects(
    store.createUser(userInput({ username: 'ALICE', email: 'another@example.test' })),
    (error) => error.code === 'USER_EXISTS',
  );
  await assert.rejects(
    store.createUser(userInput({ username: 'another', email: 'ALICE@EXAMPLE.TEST' })),
    (error) => error.code === 'USER_EXISTS',
  );
  await assert.rejects(
    store.createUser(userInput({ username: 'another', email: 'ALICE' })),
    (error) => error.code === 'USER_EXISTS',
  );
  await assert.rejects(
    store.createUser(userInput({ username: 'ALICE@EXAMPLE.TEST', email: 'third@example.test' })),
    (error) => error.code === 'USER_EXISTS',
  );
  await assert.doesNotReject(
    store.createUser(userInput({ realm: 'staff', username: 'ALICE', email: 'ALICE@EXAMPLE.TEST' })),
  );

  const fixedId = '171d7d76-a5aa-466c-bf74-b83e8cc539b2';
  await store.createUser(userInput({ id: fixedId, username: 'first', email: 'first@example.test' }));
  await assert.rejects(
    store.createUser(userInput({ id: fixedId, username: 'second', email: 'second@example.test' })),
    (error) => error.code === 'USER_EXISTS',
  );

  const second = await store.createUser(userInput({ username: 'second', email: 'second@example.test' }));
  await assert.rejects(
    store.updateUser('master', second.id, { email: ' ALICE@EXAMPLE.TEST ' }),
    (error) => error.code === 'USER_EXISTS',
  );
});

test('create, read, list, and update operations return defensive copies', async () => {
  const store = new MemoryIdentityStore();
  const created = await store.createUser(userInput({
    id: '0115435c-b1f7-47f0-8fe2-1f8712e7744c',
    recoveryCodeHashes: ['recovery-a'],
  }));

  created.roles.push('mutated-outside-store');
  created.clientRoles.console.push('write');
  created.recoveryCodeHashes.length = 0;

  const fetched = await store.findUserById('master', created.id);
  assert.deepEqual(fetched.roles, ['member']);
  assert.deepEqual(fetched.clientRoles, { console: ['read'] });
  assert.deepEqual(fetched.recoveryCodeHashes, ['recovery-a']);

  const patch = {
    email: 'new-alice@example.test',
    roles: ['member', 'operator'],
    clientRoles: { console: ['read', 'write'] },
    username: 'attempted-rename',
    realm: 'other',
    failedAttempts: 99,
  };
  const updated = await store.updateUser('master', created.id, patch);
  patch.roles.push('mutated-after-update');
  patch.clientRoles.console.length = 0;

  assert.equal(updated.email, 'new-alice@example.test');
  assert.deepEqual(updated.roles, ['member', 'operator']);
  assert.deepEqual(updated.clientRoles, { console: ['read', 'write'] });
  assert.equal(updated.username, 'alice');
  assert.equal(updated.realm, 'master');
  assert.equal(updated.failedAttempts, 0);
  assert.equal(await store.updateUser('other', created.id, { enabled: false }), null);

  const afterPatchMutation = await store.findUserById('master', created.id);
  assert.deepEqual(afterPatchMutation.roles, ['member', 'operator']);
  assert.deepEqual(afterPatchMutation.clientRoles, { console: ['read', 'write'] });

  const listed = await store.listUsers('master');
  listed[0].groups.push('/outside');
  assert.deepEqual((await store.findUserById('master', created.id)).groups, ['/engineering']);
});

test('password rehash is a compare-and-set that cannot overwrite a reset', async () => {
  const store = new MemoryIdentityStore();
  const user = await store.createUser(userInput({ passwordHash: 'hash-before-login' }));

  assert.equal(
    await store.rehashPasswordIfCurrent('master', user.id, 'wrong-expected-hash', 'unwanted-hash'),
    false,
  );
  assert.equal((await store.findUserById('master', user.id)).passwordHash, 'hash-before-login');

  await store.updateUser('master', user.id, { passwordHash: 'hash-from-admin-reset' });
  assert.equal(
    await store.rehashPasswordIfCurrent('master', user.id, 'hash-before-login', 'rehash-of-old-password'),
    false,
  );
  assert.equal((await store.findUserById('master', user.id)).passwordHash, 'hash-from-admin-reset');

  assert.equal(
    await store.rehashPasswordIfCurrent('master', user.id, 'hash-from-admin-reset', 'current-rehash'),
    true,
  );
  assert.equal((await store.findUserById('master', user.id)).passwordHash, 'current-rehash');
  assert.equal(
    await store.rehashPasswordIfCurrent('other', user.id, 'current-rehash', 'cross-realm'),
    false,
  );
});

test('public user views remove authentication secrets and expose MFA counts', async () => {
  const store = new MemoryIdentityStore();
  const created = await store.createUser(userInput({
    totpSecret: 'encrypted-secret',
    totpConfirmed: true,
    recoveryCodeHashes: ['one', 'two'],
  }));

  const safe = publicUser(created);
  assert.equal(safe.passwordHash, undefined);
  assert.equal(safe.totpSecret, undefined);
  assert.equal(safe.recoveryCodeHashes, undefined);
  assert.equal(safe.securityVersion, undefined);
  assert.equal(safe.mfaEnabled, true);
  assert.equal(safe.recoveryCodesRemaining, 2);
  assert.equal(publicUser(null), null);
});

test('five failures lock an account and a successful login clears lockout state', async () => {
  const store = new MemoryIdentityStore();
  const created = await store.createUser(userInput());

  await store.recordLoginFailure('other', created.id);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    await store.recordLoginFailure('master', created.id);
  }
  let current = await store.findUserById('master', created.id);
  assert.equal(current.failedAttempts, 4);
  assert.equal(current.lockedUntil, null);

  const beforeLock = Date.now();
  await store.recordLoginFailure('master', created.id);
  const afterLock = Date.now();
  current = await store.findUserById('master', created.id);
  assert.equal(current.failedAttempts, 5);
  assert.ok(Date.parse(current.lockedUntil) >= beforeLock + 15 * 60_000);
  assert.ok(Date.parse(current.lockedUntil) <= afterLock + 15 * 60_000);

  const fixedLock = current.lockedUntil;
  await store.recordLoginFailure('master', created.id);
  current = await store.findUserById('master', created.id);
  assert.equal(current.failedAttempts, 5);
  assert.equal(current.lockedUntil, fixedLock);

  await store.recordLoginSuccess('master', created.id);
  current = await store.findUserById('master', created.id);
  assert.equal(current.failedAttempts, 0);
  assert.equal(current.lockedUntil, null);
  assert.ok(Number.isFinite(Date.parse(current.lastLoginAt)));

  const expired = await store.createUser(userInput({
    username: 'expired-lock', email: 'expired-lock@example.test', failedAttempts: 8,
    lockedUntil: new Date(Date.now() - 1000).toISOString(),
  }));
  await store.recordLoginFailure('master', expired.id);
  const afterExpiry = await store.findUserById('master', expired.id);
  assert.equal(afterExpiry.failedAttempts, 1);
  assert.equal(afterExpiry.lockedUntil, null);
});

test('audit records are newest-first, realm-scoped, paginated, and defensively copied', async () => {
  const store = new MemoryIdentityStore();
  const firstEvent = {
    realm: 'master',
    type: 'identity.user.created',
    metadata: { source: 'test' },
  };
  const first = await store.writeAudit(firstEvent);
  firstEvent.metadata.source = 'mutated-after-write';
  const second = await store.writeAudit({ realm: 'staff', type: 'identity.login.succeeded' });
  const third = await store.writeAudit({ realm: 'master', type: 'identity.user.updated' });

  const masterRecords = await store.listAudit('master');
  assert.deepEqual(masterRecords.map((record) => record.id), [third.id, first.id]);
  assert.deepEqual(masterRecords[1].metadata, { source: 'test' });
  assert.deepEqual((await store.listAudit('staff')).map((record) => record.id), [second.id]);
  assert.deepEqual((await store.listAudit('other')).map((record) => record.id), []);
  assert.deepEqual((await store.listAudit('master', { limit: 1, offset: 1 })).map((record) => record.id), [first.id]);

  masterRecords[0].type = 'mutated-outside-store';
  assert.equal((await store.listAudit('master'))[0].type, 'identity.user.updated');
  assert.ok(first.id);
  assert.ok(Number.isFinite(Date.parse(first.createdAt)));

  const forged = await store.writeAudit({ realm: 'master', type: 'forgery.test', id: 'caller-id', createdAt: '1970-01-01T00:00:00.000Z' });
  assert.notEqual(forged.id, 'caller-id');
  assert.notEqual(forged.createdAt, '1970-01-01T00:00:00.000Z');
  assert.equal((await store.writeAudit({ realm: 'master', type: 'ip.valid', ip: '203.0.113.8' })).ip, '203.0.113.8');
  assert.equal((await store.writeAudit({ realm: 'master', type: 'ip.invalid', ip: 'spoofed, 127.0.0.1' })).ip, null);
});

test('administrator grants and opaque sessions are realm-scoped, versioned, and revocable', async () => {
  const store = new MemoryIdentityStore();
  const user = await store.createUser(userInput());
  assert.equal(await store.findAdminGrant('master', user.id), null);

  const firstGrant = await store.upsertAdminGrant('master', user.id, ['users.read', 'audit.read']);
  assert.equal(firstGrant.version, 1);
  firstGrant.permissions.push('outside-mutation');
  assert.deepEqual((await store.findAdminGrant('master', user.id)).permissions, ['users.read', 'audit.read']);
  assert.equal(await store.upsertAdminGrant('other', user.id, ['users.read']), null);
  await assert.rejects(
    store.upsertAdminGrant('master', user.id, ['unsupported.permission']),
    TypeError,
  );

  const secondGrant = await store.upsertAdminGrant('master', user.id, ['*']);
  assert.equal(secondGrant.version, 2);
  const digest = 'a'.repeat(43);
  const created = await store.createAdminSession({
    idDigest: digest,
    realm: 'master',
    userId: user.id,
    grantVersion: secondGrant.version,
    securityVersion: user.securityVersion,
    idleExpiresAt: new Date(Date.now() + 60_000),
    expiresAt: new Date(Date.now() + 120_000),
  });
  assert.equal(created.idDigest, digest);
  assert.equal((await store.findAdminSession(digest)).userId, user.id);
  const touched = await store.touchAdminSession(digest, new Date(Date.now() + 90_000));
  assert.ok(Date.parse(touched.lastSeenAt) >= Date.parse(created.lastSeenAt));
  assert.equal(await store.deleteAdminSession(digest), true);
  assert.equal(await store.findAdminSession(digest), null);

  const expiredDigest = 'b'.repeat(43);
  await store.createAdminSession({
    idDigest: expiredDigest,
    realm: 'master',
    userId: user.id,
    grantVersion: secondGrant.version,
    securityVersion: user.securityVersion,
    idleExpiresAt: new Date(Date.now() - 1_000),
    expiresAt: new Date(Date.now() + 120_000),
  });
  assert.equal(await store.cleanupExpiredAdminSessions(), 1);
  assert.equal(await store.findAdminSession(expiredDigest), null);

  const revoked = await store.revokeAdminGrant('master', user.id);
  assert.equal(revoked.enabled, false);
  assert.equal(revoked.version, 3);
  await store.deleteUser('master', user.id);
  assert.equal(await store.findAdminGrant('master', user.id), null);
});

test('WebAuthn challenges are expiring, context-bound, and consumed exactly once', async () => {
  const store = new MemoryIdentityStore();
  const user = await store.createUser(userInput());
  const challenge = await store.createWebAuthnChallenge({
    realm: 'master',
    purpose: 'registration',
    userId: user.id,
    userHandle: 'opaque-user-handle',
    challenge: 'challenge-value-that-is-long-enough-for-webauthn',
    expiresAt: new Date(Date.now() + 60_000),
  });

  assert.equal(await store.consumeWebAuthnChallenge({
    realm: 'staff', id: challenge.id, purpose: 'registration', userId: user.id,
  }), null);
  assert.equal(await store.consumeWebAuthnChallenge({
    realm: 'master', id: challenge.id, purpose: 'authentication', userId: user.id,
  }), null);
  assert.equal((await store.consumeWebAuthnChallenge({
    realm: 'master', id: challenge.id, purpose: 'registration', userId: user.id,
  })).challenge, challenge.challenge);
  assert.equal(await store.consumeWebAuthnChallenge({
    realm: 'master', id: challenge.id, purpose: 'registration', userId: user.id,
  }), null);

  const expired = await store.createWebAuthnChallenge({
    realm: 'master',
    purpose: 'authentication',
    interactionUid: 'interaction-one',
    challenge: 'expired-challenge-value-that-is-long-enough',
    expiresAt: new Date(Date.now() - 1),
  });
  assert.equal(await store.consumeWebAuthnChallenge({
    realm: 'master', id: expired.id, purpose: 'authentication', interactionUid: 'interaction-one',
  }), null);
  assert.equal(await store.cleanupExpiredWebAuthnChallenges(), 1);
});

test('WebAuthn credentials are realm/user scoped and counters update with compare-and-set semantics', async () => {
  const store = new MemoryIdentityStore();
  const id = 'eeb54dc9-0700-4e56-a9ce-a4edcbd24a72';
  await store.createUser(userInput({ id }));
  await store.createUser(userInput({ id, realm: 'staff' }));
  const input = {
    realm: 'master',
    userId: id,
    id: 'credential_id-1',
    userHandle: 'opaque-user-handle',
    publicKey: Uint8Array.from([1, 2, 3]),
    counter: 4,
    transports: ['internal', 'hybrid'],
    deviceType: 'multiDevice',
    backedUp: false,
    aaguid: '00000000-0000-0000-0000-000000000000',
    name: 'Phone passkey',
  };
  await store.createWebAuthnCredential(input);
  await store.createWebAuthnCredential({ ...input, realm: 'staff' });

  await assert.rejects(
    store.createWebAuthnCredential(input),
    (error) => error.code === 'WEBAUTHN_CREDENTIAL_EXISTS',
  );
  assert.equal((await store.findWebAuthnCredential('master', input.id)).name, 'Phone passkey');
  assert.equal((await store.findWebAuthnCredential('other', input.id)), null);
  assert.equal((await store.listWebAuthnCredentials('master', id)).length, 1);
  assert.equal(await store.updateWebAuthnCredentialCounter('master', input.id, {
    expectedCounter: 3, newCounter: 5, deviceType: 'multiDevice', backedUp: true,
  }), false);
  assert.equal(await store.updateWebAuthnCredentialCounter('master', input.id, {
    expectedCounter: 4, newCounter: 5, deviceType: 'multiDevice', backedUp: true,
  }), true);
  const updated = await store.findWebAuthnCredential('master', input.id);
  assert.equal(updated.counter, 5);
  assert.equal(updated.backedUp, true);
  assert.ok(updated.lastUsedAt);

  assert.equal(await store.deleteWebAuthnCredential('master', randomUUID(), input.id), null);
  assert.equal((await store.deleteWebAuthnCredential('master', id, input.id)).id, input.id);
  assert.equal(await store.findWebAuthnCredential('master', input.id), null);
  assert.notEqual(await store.findWebAuthnCredential('staff', input.id), null);
  await store.deleteUser('staff', id);
  assert.equal(await store.findWebAuthnCredential('staff', input.id), null);
});
