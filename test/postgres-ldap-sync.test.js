import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';

import { PostgresFederatedIdentityRepository } from '../src/repositories/federated-identity-repository.js';

const databaseUrl = process.env.DATABASE_URL;
const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
const realm = `ldap-a-${suffix}`;
const otherRealm = `ldap-b-${suffix}`;
let pool;

function input(overrides = {}) {
  return {
    realm,
    providerId: 'corp',
    issuer: 'ldaps://directory.example.test:636',
    externalSubject: 'immutable-alice',
    profile: {
      username: 'alice', email: `alice-${suffix}@example.test`, name: 'Alice',
      givenName: 'Alice', familyName: 'Example', roles: [], groups: ['/Engineering'],
    },
    syncId: randomUUID(),
    syncGroups: true,
    syncRoles: false,
    ...overrides,
  };
}

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({ connectionString: databaseUrl, max: 6, application_name: 'authme-ldap-sync-test' });
  await pool.query(
    'INSERT INTO realms (name,display_name) VALUES ($1,$2),($3,$4)',
    [realm, realm, otherRealm, otherRealm],
  );
});

after(async () => {
  if (!pool) return;
  await pool.query('DELETE FROM realms WHERE name=ANY($1)', [[realm, otherRealm]]);
  await pool.end();
});

test('PostgreSQL LDAP reconciliation is stable, bounded, locked, and realm-scoped', {
  skip: !databaseUrl,
}, async () => {
  const repository = new PostgresFederatedIdentityRepository(pool, { disabledPasswordHash: '!ldap-disabled!' });
  const release = await repository.acquireSyncLock(input());
  assert.equal(await repository.acquireSyncLock(input()), null);
  await release();

  const first = input();
  assert.equal((await repository.syncEntry(first)).status, 'created');
  const renamed = input({
    syncId: randomUUID(),
    profile: { ...first.profile, username: 'alicia', name: 'Alicia' },
  });
  assert.equal((await repository.syncEntry(renamed)).status, 'updated');
  const stored = await pool.query(
    'SELECT id,username FROM users WHERE realm_name=$1',
    [realm],
  );
  assert.equal(stored.rowCount, 1);
  assert.equal(stored.rows[0].username, 'alicia');

  const other = input({ realm: otherRealm, syncId: randomUUID() });
  assert.equal((await repository.syncEntry(other)).status, 'created');
  const missing = await repository.reconcileMissing({
    realm,
    providerId: first.providerId,
    issuer: first.issuer,
    syncId: randomUUID(),
    startedAt: new Date(Date.now() + 60_000).toISOString(),
    scanned: 1,
    deletionPolicy: 'disable',
    maxDeprovisionFraction: 1,
    maxDeprovisionCount: 100,
    batchSize: 1,
  });
  assert.equal(missing.disabled, 1);
  assert.equal((await pool.query('SELECT enabled FROM users WHERE realm_name=$1', [realm])).rows[0].enabled, false);
  assert.equal((await pool.query('SELECT enabled FROM users WHERE realm_name=$1', [otherRealm])).rows[0].enabled, true);

  assert.equal((await repository.syncEntry(input({ syncId: randomUUID(), profile: renamed.profile }))).status, 'updated');
  const deleted = await repository.reconcileMissing({
    realm,
    providerId: first.providerId,
    issuer: first.issuer,
    syncId: randomUUID(),
    startedAt: new Date(Date.now() + 60_000).toISOString(),
    scanned: 1,
    deletionPolicy: 'delete',
    maxDeprovisionFraction: 1,
    maxDeprovisionCount: 100,
    batchSize: 1,
  });
  assert.equal(deleted.deleted, 1);
  assert.equal((await pool.query('SELECT id FROM users WHERE realm_name=$1', [realm])).rowCount, 0);
});

test('PostgreSQL LDAP sync preserves admin disables, protected accounts, and suspicious views', {
  skip: !databaseUrl,
}, async () => {
  const repository = new PostgresFederatedIdentityRepository(pool, { disabledPasswordHash: '!ldap-disabled!' });
  const profileFor = (username) => ({
    username,
    email: `${username}-${suffix}@example.test`,
    name: username,
    givenName: username,
    familyName: 'Example',
    roles: [],
    groups: [],
  });
  const create = async (subject, username) => repository.syncEntry(input({
    externalSubject: subject,
    profile: profileFor(username),
    syncId: randomUUID(),
  }));
  const adminDisabled = await create('admin-disabled', 'admin-disabled');
  const localCredential = await create('local-credential', 'local-credential');
  const otherLink = await create('other-link', 'other-link');
  const keeper = await create('keeper', 'keeper');
  const startedAt = new Date(Date.now() + 60_000).toISOString();

  const empty = await repository.reconcileMissing({
    realm, providerId: 'corp', issuer: input().issuer, syncId: randomUUID(), startedAt,
    scanned: 0, deletionPolicy: 'disable', maxDeprovisionFraction: 1,
    maxDeprovisionCount: 100, batchSize: 2,
  });
  assert.equal(empty.status, 'skipped');
  assert.equal(empty.reason, 'empty_directory_view');
  assert.equal(empty.candidates, 4);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM users WHERE realm_name=$1 AND enabled', [realm])).rows[0].count, 4);

  await pool.query(
    `UPDATE users SET enabled=false,ldap_sync_disable_provider_id=NULL,ldap_sync_disable_issuer=NULL
     WHERE realm_name=$1 AND id=$2`,
    [realm, adminDisabled.userId],
  );
  const observedRun = randomUUID();
  assert.equal((await repository.syncEntry(input({
    externalSubject: 'admin-disabled', profile: profileFor('admin-disabled'), syncId: observedRun,
  }))).status, 'unchanged');
  assert.equal((await pool.query('SELECT enabled FROM users WHERE realm_name=$1 AND id=$2', [realm, adminDisabled.userId])).rows[0].enabled, false);

  await pool.query(
    'UPDATE users SET password_hash=$3,has_local_password=true WHERE realm_name=$1 AND id=$2',
    [realm, localCredential.userId, 'administrator-set-password-hash'],
  );
  await pool.query(
    `INSERT INTO admin_grants (realm_name,user_id,permissions)
     VALUES ($1,$2,$3)`,
    [realm, localCredential.userId, ['users.read']],
  );
  assert.equal((await repository.link({
    realm,
    providerId: 'other-idp',
    issuer: 'https://idp.example.test',
    externalSubject: 'other-source-subject',
    userId: otherLink.userId,
  })).status, 'linked');
  await repository.syncEntry(input({
    externalSubject: 'keeper', profile: profileFor('keeper'), syncId: observedRun,
  }));

  const protectedResult = await repository.reconcileMissing({
    realm, providerId: 'corp', issuer: input().issuer, syncId: observedRun, startedAt,
    scanned: 2, deletionPolicy: 'delete', maxDeprovisionFraction: 1,
    maxDeprovisionCount: 100, batchSize: 1,
  });
  assert.equal(protectedResult.deleted, 0);
  assert.equal(protectedResult.deletionRefused, 2);
  assert.equal(protectedResult.disabled, 2);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM admin_grants WHERE realm_name=$1 AND user_id=$2', [realm, localCredential.userId])).rows[0].count, 1);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM federated_identities WHERE realm_name=$1 AND user_id=$2', [realm, otherLink.userId])).rows[0].count, 2);

  const thresholdRun = randomUUID();
  await repository.syncEntry(input({
    externalSubject: 'admin-disabled', profile: profileFor('admin-disabled'), syncId: thresholdRun,
  }));
  const threshold = await repository.reconcileMissing({
    realm, providerId: 'corp', issuer: input().issuer, syncId: thresholdRun, startedAt,
    scanned: 1, deletionPolicy: 'disable', maxDeprovisionFraction: 0.5,
    maxDeprovisionCount: 100, batchSize: 2,
  });
  assert.equal(threshold.status, 'skipped');
  assert.equal(threshold.reason, 'deprovision_threshold_exceeded');
  assert.equal((await pool.query('SELECT enabled FROM users WHERE realm_name=$1 AND id=$2', [realm, keeper.userId])).rows[0].enabled, true);
});
