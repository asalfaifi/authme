import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';

import { PostgresIdentityStore } from '../src/repositories/identity-store.js';

const databaseUrl = process.env.DATABASE_URL;
const realm = `account-${randomUUID().replaceAll('-', '').slice(0, 12)}`;
const otherRealm = `account-${randomUUID().replaceAll('-', '').slice(0, 12)}`;
let pool;
let store;
let userId;

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({ connectionString: databaseUrl, max: 4, application_name: 'authme-account-console-test' });
  store = new PostgresIdentityStore(pool);
  await pool.query('INSERT INTO realms (name,display_name) VALUES ($1,$1),($2,$2)', [realm, otherRealm]);
  userId = randomUUID();
  for (const currentRealm of [realm, otherRealm]) {
    await store.createUser({
      id: userId,
      realm: currentRealm,
      username: `account-${currentRealm}`,
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

test('PostgreSQL account sessions are opaque, realm-scoped, expiring, and revocable', { skip: !databaseUrl }, async () => {
  const digest = 's'.repeat(43);
  const session = await store.createAccountSession({
    idDigest: digest,
    realm,
    userId,
    securityVersion: 0,
    authenticationMethods: ['pwd'],
    idleExpiresAt: new Date(Date.now() + 60_000),
    expiresAt: new Date(Date.now() + 120_000),
    ip: '203.0.113.9',
    userAgent: 'PostgreSQL account test',
  });
  assert.equal(session.idDigest, digest);
  assert.deepEqual(session.authenticationMethods, ['pwd']);
  assert.equal(session.ip, '203.0.113.9');
  assert.equal((await store.listAccountSessions(realm, userId)).length, 1);
  assert.equal((await store.listAccountSessions(otherRealm, userId)).length, 0);
  assert.notEqual(await store.touchAccountSession(digest, new Date(Date.now() + 90_000)), null);
  assert.equal(await store.deleteAccountSession(digest), true);
  assert.equal(await store.findAccountSession(digest), null);

  const expiredDigest = 'x'.repeat(43);
  await store.createAccountSession({
    idDigest: expiredDigest,
    realm,
    userId,
    securityVersion: 0,
    createdAt: new Date(Date.now() - 60_000),
    lastSeenAt: new Date(Date.now() - 60_000),
    idleExpiresAt: new Date(Date.now() - 1_000),
    expiresAt: new Date(Date.now() + 60_000),
  });
  assert.equal(await store.cleanupExpiredAccountSessions(10), 1);
  assert.equal(await store.findAccountSession(expiredDigest), null);
});

test('PostgreSQL account action tokens replace predecessors and have one realm-bound consumer', { skip: !databaseUrl }, async () => {
  const firstDigest = 'a'.repeat(43);
  const replacementDigest = 'b'.repeat(43);
  await store.createAccountActionToken({
    realm,
    userId,
    type: 'email-verification',
    tokenDigest: firstDigest,
    email: 'first@example.test',
    expiresAt: new Date(Date.now() + 60_000),
  });
  await store.createAccountActionToken({
    realm,
    userId,
    type: 'email-verification',
    tokenDigest: replacementDigest,
    email: 'replacement@example.test',
    expiresAt: new Date(Date.now() + 60_000),
  });
  assert.equal(await store.consumeAccountActionToken({
    realm, type: 'email-verification', tokenDigest: firstDigest,
  }), null);
  assert.equal(await store.consumeAccountActionToken({
    realm: otherRealm, type: 'email-verification', tokenDigest: replacementDigest,
  }), null);
  const consumers = await Promise.all([
    store.consumeAccountActionToken({ realm, type: 'email-verification', tokenDigest: replacementDigest }),
    store.consumeAccountActionToken({ realm, type: 'email-verification', tokenDigest: replacementDigest }),
  ]);
  assert.equal(consumers.filter(Boolean).length, 1);
  assert.equal(consumers.find(Boolean).email, 'replacement@example.test');

  await store.createAccountActionToken({
    realm,
    userId,
    type: 'password-reset',
    tokenDigest: 'c'.repeat(43),
    expiresAt: new Date(Date.now() - 1_000),
  });
  assert.equal(await store.cleanupExpiredAccountActionTokens(10), 1);
});
