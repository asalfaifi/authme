import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';

import { PostgresIdentityStore } from '../src/repositories/identity-store.js';

const databaseUrl = process.env.DATABASE_URL;
const realm = `admin-${randomUUID().replaceAll('-', '').slice(0, 12)}`;
let pool;
let store;
let user;

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({ connectionString: databaseUrl, max: 4, application_name: 'authme-admin-console-test' });
  store = new PostgresIdentityStore(pool);
  await pool.query('INSERT INTO realms (name,display_name) VALUES ($1,$1)', [realm]);
  user = await store.createUser({
    realm,
    username: `administrator-${realm}`,
    email: `${realm}@example.test`,
    passwordHash: 'unused',
  });
});

after(async () => {
  if (!pool) return;
  await pool.query('DELETE FROM realms WHERE name=$1', [realm]);
  await pool.end();
});

test('PostgreSQL administrator grants and sessions are versioned, revocable, and durable', {
  skip: !databaseUrl,
}, async () => {
  const first = await store.upsertAdminGrant(realm, user.id, ['users.read', 'audit.read']);
  assert.equal(first.version, 1);
  assert.deepEqual((await store.findAdminGrant(realm, user.id)).permissions, ['users.read', 'audit.read']);

  const second = await store.upsertAdminGrant(realm, user.id, ['*']);
  assert.equal(second.version, 2);
  const digest = 'c'.repeat(43);
  const session = await store.createAdminSession({
    idDigest: digest,
    realm,
    userId: user.id,
    grantVersion: second.version,
    securityVersion: user.securityVersion,
    idleExpiresAt: new Date(Date.now() + 60_000),
    expiresAt: new Date(Date.now() + 120_000),
  });
  assert.equal(session.idDigest, digest);
  assert.equal((await store.findAdminSession(digest)).grantVersion, 2);
  assert.notEqual(await store.touchAdminSession(digest, new Date(Date.now() + 90_000)), null);

  const revoked = await store.revokeAdminGrant(realm, user.id);
  assert.equal(revoked.enabled, false);
  assert.equal(revoked.version, 3);
  assert.equal(await store.deleteAdminSession(digest), true);
  assert.equal(await store.findAdminSession(digest), null);

  const expiredDigest = 'd'.repeat(43);
  await store.createAdminSession({
    idDigest: expiredDigest,
    realm,
    userId: user.id,
    grantVersion: revoked.version,
    securityVersion: user.securityVersion,
    createdAt: new Date(Date.now() - 60_000).toISOString(),
    lastSeenAt: new Date(Date.now() - 60_000).toISOString(),
    idleExpiresAt: new Date(Date.now() - 1_000),
    expiresAt: new Date(Date.now() + 120_000),
  });
  assert.equal(await store.cleanupExpiredAdminSessions(10), 1);
  assert.equal(await store.findAdminSession(expiredDigest), null);

  await store.createAdminSession({
    idDigest: 'e'.repeat(43),
    realm,
    userId: user.id,
    grantVersion: revoked.version,
    securityVersion: user.securityVersion,
    idleExpiresAt: new Date(Date.now() + 60_000),
    expiresAt: new Date(Date.now() + 120_000),
  });
  await store.deleteUser(realm, user.id);
  assert.equal(await store.findAdminGrant(realm, user.id), null);
  assert.equal(await store.findAdminSession('e'.repeat(43)), null);
});
