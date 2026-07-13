import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';

import { PostgresIdentityStore } from '../src/repositories/identity-store.js';

const databaseUrl = process.env.DATABASE_URL;
const realm = `test-passkey-${randomUUID().slice(0, 8)}`;
const otherRealm = `test-passkey-${randomUUID().slice(0, 8)}`;
let pool;
let store;
let userId;

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({ connectionString: databaseUrl, max: 4 });
  store = new PostgresIdentityStore(pool);
  await pool.query(
    'INSERT INTO realms (name,display_name) VALUES ($1,$1),($2,$2)',
    [realm, otherRealm],
  );
  userId = randomUUID();
  for (const currentRealm of [realm, otherRealm]) {
    await store.createUser({
      id: userId,
      realm: currentRealm,
      username: `passkey-${currentRealm}`,
      email: `${currentRealm}@example.test`,
      passwordHash: 'unused',
    });
  }
});

after(async () => {
  if (!pool) return;
  await pool.query('DELETE FROM realms WHERE name=ANY($1::text[])', [[realm, otherRealm]]);
  await pool.end();
});

test('PostgreSQL WebAuthn challenges expire, bind context, and have one concurrent consumer', { skip: !databaseUrl }, async () => {
  const challenge = await store.createWebAuthnChallenge({
    realm,
    purpose: 'registration',
    userId,
    userHandle: 'opaque-user-handle',
    challenge: 'postgres-challenge-value-012345678901234567890123456789',
    expiresAt: new Date(Date.now() + 60_000),
  });
  assert.equal(await store.consumeWebAuthnChallenge({
    realm: otherRealm, id: challenge.id, purpose: 'registration', userId,
  }), null);
  const claimed = await Promise.all([
    store.consumeWebAuthnChallenge({ realm, id: challenge.id, purpose: 'registration', userId }),
    store.consumeWebAuthnChallenge({ realm, id: challenge.id, purpose: 'registration', userId }),
  ]);
  assert.equal(claimed.filter(Boolean).length, 1);

  await store.createWebAuthnChallenge({
    realm,
    purpose: 'authentication',
    interactionUid: 'expired-interaction',
    challenge: 'expired-postgres-challenge-01234567890123456789012345',
    expiresAt: new Date(Date.now() - 1_000),
  });
  assert.equal(await store.cleanupExpiredWebAuthnChallenges(1), 1);
});

test('PostgreSQL WebAuthn credentials are realm isolated and counter updates are compare-and-set', { skip: !databaseUrl }, async () => {
  const credential = {
    realm,
    userId,
    id: 'postgres-credential_1',
    userHandle: 'opaque-user-handle',
    publicKey: Uint8Array.from([1, 2, 3, 4]),
    counter: 4,
    transports: ['internal', 'hybrid'],
    deviceType: 'multiDevice',
    backedUp: false,
    aaguid: '00000000-0000-0000-0000-000000000000',
    name: 'PostgreSQL passkey',
  };
  await store.createWebAuthnCredential(credential);
  await store.createWebAuthnCredential({ ...credential, realm: otherRealm });
  await assert.rejects(
    store.createWebAuthnCredential(credential),
    (error) => error.code === 'WEBAUTHN_CREDENTIAL_EXISTS',
  );

  const updates = await Promise.all([
    store.updateWebAuthnCredentialCounter(realm, credential.id, {
      expectedCounter: 4, newCounter: 5, deviceType: 'multiDevice', backedUp: true,
    }),
    store.updateWebAuthnCredentialCounter(realm, credential.id, {
      expectedCounter: 4, newCounter: 6, deviceType: 'multiDevice', backedUp: true,
    }),
  ]);
  assert.deepEqual(updates.sort(), [false, true]);
  const current = await store.findWebAuthnCredential(realm, credential.id);
  assert.ok([5, 6].includes(current.counter));
  assert.equal(current.backedUp, true);
  assert.deepEqual(current.transports, ['internal', 'hybrid']);
  assert.notEqual(await store.findWebAuthnCredential(otherRealm, credential.id), null);

  await store.deleteUser(realm, userId);
  assert.equal(await store.findWebAuthnCredential(realm, credential.id), null);
  assert.notEqual(await store.findWebAuthnCredential(otherRealm, credential.id), null);
});
