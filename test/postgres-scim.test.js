import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';

import pg from 'pg';

import { PostgresScimRepository } from '../src/repositories/scim-repository.js';
import { ScimRepositoryError } from '../src/scim/errors.js';

const databaseUrl = process.env.DATABASE_URL;
const disabledPasswordHash = '!authme-scim-disabled-password!';
let pool;
let hashedInputs;
let repository;

function digestPassword(password) {
  return `test-sha256$${createHash('sha256').update(password).digest('hex')}`;
}

function userAttributes(name, overrides = {}) {
  const lower = name.toLowerCase();
  return {
    userName: lower,
    externalId: `user-${lower}`,
    displayName: name,
    name: { givenName: name, familyName: 'Tester' },
    emails: [{ value: `${lower}@example.test`, primary: true }],
    roles: [{ value: 'reader' }],
    active: true,
    ...overrides,
  };
}

async function expectRepositoryError(promise, code) {
  await assert.rejects(promise, (error) => error instanceof ScimRepositoryError && error.code === code);
}

async function coreUser(realm, id) {
  const result = await pool.query(
    `SELECT username,email,display_name,enabled,password_hash,roles,groups,attributes,
            security_version,failed_attempts,locked_until
     FROM users WHERE realm_name=$1 AND id=$2`,
    [realm, id],
  );
  return result.rows[0]
    ? { ...result.rows[0], security_version: Number(result.rows[0].security_version) }
    : undefined;
}

async function insertSession(realm, { id = randomUUID(), model = 'Session', accountId, grantId } = {}) {
  await pool.query(
    `INSERT INTO oidc_records (realm_name,model,id,payload,grant_id)
     VALUES ($1,$2,$3,$4,$5)`,
    [realm, model, id, accountId ? { accountId } : {}, grantId ?? null],
  );
  return id;
}

async function existingSessionIds(realm, ids) {
  const result = await pool.query(
    'SELECT id FROM oidc_records WHERE realm_name=$1 AND id=ANY($2::text[]) ORDER BY id',
    [realm, ids],
  );
  return result.rows.map(({ id }) => id);
}

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({
    connectionString: databaseUrl,
    max: 8,
    application_name: 'authme-postgres-scim-test',
  });
  hashedInputs = [];
  repository = new PostgresScimRepository(pool, {
    disabledPasswordHash,
    async hashPassword(password) {
      hashedInputs.push(password);
      return digestPassword(password);
    },
  });
});

after(async () => {
  await pool?.end();
});

test('PostgreSQL SCIM repository satisfies the durable realm-scoped contract', { skip: !databaseUrl }, async (t) => {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
  const realm = `scim-a-${suffix}`;
  const otherRealm = `scim-b-${suffix}`;
  await pool.query(
    'INSERT INTO realms (name,display_name) VALUES ($1,$2),($3,$4)',
    [realm, 'SCIM test A', otherRealm, 'SCIM test B'],
  );

  try {
    let alice;
    let bob;

    await t.test('User creation hashes write-only passwords and isolates realm uniqueness', async () => {
      const password = 'Alice password 123!';
      alice = await repository.createUser(realm, userAttributes('Alice', { password }));
      bob = await repository.createUser(realm, userAttributes('Bob', { active: false }));
      const otherAlice = await repository.createUser(otherRealm, userAttributes('Alice', { password }));

      assert.equal(alice.version, 1);
      assert.equal(alice.active, true);
      assert.equal(Object.hasOwn(alice, 'password'), false);
      assert.equal(otherAlice.externalId, alice.externalId);
      assert.deepEqual(hashedInputs, [password, password]);

      const storedAlice = await coreUser(realm, alice.id);
      assert.equal(storedAlice.password_hash, digestPassword(password));
      assert.equal(storedAlice.enabled, true);
      assert.equal(storedAlice.attributes.scim.password, undefined);
      assert.doesNotMatch(JSON.stringify(storedAlice.attributes), /Alice password 123!/);

      const storedBob = await coreUser(realm, bob.id);
      assert.equal(storedBob.password_hash, disabledPasswordHash);
      assert.equal(storedBob.enabled, false);

      await expectRepositoryError(
        repository.createUser(realm, userAttributes('ALICE', {
          externalId: 'another-external-id',
          emails: [{ value: 'unique@example.test', primary: true }],
        })),
        'UNIQUENESS',
      );
      await expectRepositoryError(
        repository.createUser(realm, userAttributes('Carol', { externalId: alice.externalId })),
        'UNIQUENESS',
      );
      await expectRepositoryError(
        repository.createUser(realm, userAttributes('Short', { password: 'too-short' })),
        'INVALID_VALUE',
      );
      assert.equal(hashedInputs.includes('too-short'), false);
    });

    await t.test('User reads, filters, pagination totals, and identifiers are safe and realm-scoped', async () => {
      const firstPage = await repository.listUsers(realm, { startIndex: 1, count: 1, filter: null });
      assert.equal(firstPage.totalResults, 2);
      assert.equal(firstPage.resources.length, 1);

      const zeroPage = await repository.listUsers(realm, { startIndex: 1, count: 0, filter: null });
      assert.equal(zeroPage.totalResults, 2);
      assert.deepEqual(zeroPage.resources, []);

      const offPage = await repository.listUsers(realm, { startIndex: 99, count: 10, filter: null });
      assert.equal(offPage.totalResults, 2);
      assert.deepEqual(offPage.resources, []);

      const byName = await repository.listUsers(realm, {
        startIndex: 1, count: 10, filter: { attribute: 'userName', value: 'ALICE' },
      });
      assert.deepEqual(byName.resources.map(({ id }) => id), [alice.id]);
      assert.equal(byName.totalResults, 1);

      const byExternalId = await repository.listUsers(realm, {
        startIndex: 1, count: 10, filter: { attribute: 'externalId', value: alice.externalId },
      });
      assert.deepEqual(byExternalId.resources.map(({ id }) => id), [alice.id]);

      const inactive = await repository.listUsers(realm, {
        startIndex: 1, count: 10, filter: { attribute: 'active', value: 'false' },
      });
      assert.deepEqual(inactive.resources.map(({ id }) => id), [bob.id]);

      assert.equal((await repository.getUser(realm, alice.id)).id, alice.id);
      assert.equal(await repository.getUser(otherRealm, alice.id), undefined);
      assert.equal(await repository.getUser(realm, 'not-a-uuid'), undefined);
      assert.deepEqual(await repository.listUserGroups(realm, 'not-a-uuid'), []);
    });

    await t.test('User versions ignore login bookkeeping but protect identity changes with CAS', async () => {
      const beforeBookkeeping = await repository.getUser(realm, alice.id);
      await pool.query(
        `UPDATE users SET failed_attempts=failed_attempts+1,last_login_at=now()
         WHERE realm_name=$1 AND id=$2`,
        [realm, alice.id],
      );
      const afterBookkeeping = await repository.getUser(realm, alice.id);
      assert.equal(afterBookkeeping.version, beforeBookkeeping.version);

      await pool.query(
        'UPDATE users SET display_name=$3 WHERE realm_name=$1 AND id=$2',
        [realm, alice.id, 'Alice Core Update'],
      );
      const afterCoreUpdate = await repository.getUser(realm, alice.id);
      assert.equal(afterCoreUpdate.displayName, 'Alice Core Update');
      assert.equal(afterCoreUpdate.version, beforeBookkeeping.version + 1);

      const securityBefore = await coreUser(realm, alice.id);
      const grant = await insertSession(realm, { model: 'Grant', accountId: alice.id });
      const token = await insertSession(realm, { model: 'AccessToken', grantId: grant });
      const direct = await insertSession(realm, { accountId: alice.id });
      const unrelated = await insertSession(realm);
      const replacementPassword = 'Replacement password 123!';
      const replaced = await repository.replaceUser(
        realm,
        alice.id,
        userAttributes('Alice-Renamed', {
          externalId: 'user-alice-renamed',
          active: false,
          password: replacementPassword,
          emails: [{ value: 'alice.renamed@example.test', primary: true }],
          roles: [{ value: 'administrator' }],
        }),
        afterCoreUpdate.version,
      );
      alice = replaced;
      assert.equal(replaced.version, afterCoreUpdate.version + 1);
      assert.equal(replaced.active, false);
      assert.equal(Object.hasOwn(replaced, 'password'), false);
      assert.deepEqual(await existingSessionIds(realm, [grant, token, direct, unrelated]), [unrelated]);

      const securityAfter = await coreUser(realm, alice.id);
      assert.equal(securityAfter.security_version, securityBefore.security_version + 1);
      assert.equal(securityAfter.enabled, false);
      assert.equal(securityAfter.password_hash, digestPassword(replacementPassword));
      assert.equal(securityAfter.failed_attempts, 0);
      assert.equal(securityAfter.locked_until, null);
      assert.equal(securityAfter.attributes.scim.password, undefined);

      await expectRepositoryError(
        repository.replaceUser(realm, alice.id, userAttributes('Stale'), afterCoreUpdate.version),
        'VERSION_MISMATCH',
      );

      const concurrentVersion = alice.version;
      const attempts = await Promise.allSettled([
        repository.replaceUser(realm, alice.id, userAttributes('Alice-One', {
          externalId: 'user-alice-one', emails: [{ value: 'alice.one@example.test', primary: true }],
        }), concurrentVersion),
        repository.replaceUser(realm, alice.id, userAttributes('Alice-Two', {
          externalId: 'user-alice-two', emails: [{ value: 'alice.two@example.test', primary: true }],
        }), concurrentVersion),
      ]);
      assert.equal(attempts.filter(({ status }) => status === 'fulfilled').length, 1);
      const rejected = attempts.find(({ status }) => status === 'rejected');
      assert.equal(rejected.reason.code, 'VERSION_MISMATCH');
      alice = await repository.getUser(realm, alice.id);
      assert.equal(alice.version, concurrentVersion + 1);
    });

    let engineering;

    await t.test('Group creation validates members and synchronizes core claims and security epochs', async () => {
      const aliceBefore = await coreUser(realm, alice.id);
      const bobBefore = await coreUser(realm, bob.id);
      const aliceVersion = (await repository.getUser(realm, alice.id)).version;
      const bobVersion = (await repository.getUser(realm, bob.id)).version;
      const aliceSession = await insertSession(realm, { accountId: alice.id });
      const bobSession = await insertSession(realm, { accountId: bob.id });

      engineering = await repository.createGroup(realm, {
        displayName: 'Engineering',
        externalId: 'group-engineering',
        members: [{ value: alice.id }, { value: bob.id }],
      });
      assert.equal(engineering.version, 1);
      assert.deepEqual(new Set(engineering.members.map(({ value }) => value)), new Set([alice.id, bob.id]));
      assert.deepEqual(await repository.listUserGroups(realm, alice.id), [
        { value: engineering.id, display: 'Engineering', type: 'direct' },
      ]);

      const aliceAfter = await coreUser(realm, alice.id);
      const bobAfter = await coreUser(realm, bob.id);
      assert.deepEqual(aliceAfter.groups, ['/Engineering']);
      assert.deepEqual(bobAfter.groups, ['/Engineering']);
      assert.equal(aliceAfter.security_version, aliceBefore.security_version + 1);
      assert.equal(bobAfter.security_version, bobBefore.security_version + 1);
      assert.equal((await repository.getUser(realm, alice.id)).version, aliceVersion + 1);
      assert.equal((await repository.getUser(realm, bob.id)).version, bobVersion + 1);
      assert.deepEqual(await existingSessionIds(realm, [aliceSession, bobSession]), []);

      const foreignUser = (await repository.listUsers(otherRealm, {
        startIndex: 1, count: 10, filter: { attribute: 'userName', value: 'alice' },
      })).resources[0];
      await expectRepositoryError(
        repository.createGroup(realm, {
          displayName: 'Invalid foreign member', members: [{ value: foreignUser.id }],
        }),
        'INVALID_VALUE',
      );
      await expectRepositoryError(
        repository.createGroup(realm, {
          displayName: 'Invalid identifier', members: [{ value: 'not-a-uuid' }],
        }),
        'INVALID_VALUE',
      );
      await expectRepositoryError(
        repository.createGroup(realm, {
          displayName: 'Duplicate member', members: [{ value: alice.id }, { value: alice.id }],
        }),
        'INVALID_VALUE',
      );
      await expectRepositoryError(
        repository.createGroup(realm, {
          displayName: 'Duplicate external ID', externalId: engineering.externalId, members: [],
        }),
        'UNIQUENESS',
      );
      const otherGroup = await repository.createGroup(otherRealm, {
        displayName: 'Engineering', externalId: engineering.externalId, members: [],
      });
      assert.equal(otherGroup.externalId, engineering.externalId);
    });

    await t.test('Group filters and empty pages retain exact totals and realm isolation', async () => {
      await repository.createGroup(realm, { displayName: 'Operations', externalId: 'group-operations', members: [] });

      const firstPage = await repository.listGroups(realm, { startIndex: 1, count: 1, filter: null });
      assert.equal(firstPage.totalResults, 2);
      assert.equal(firstPage.resources.length, 1);

      const zeroPage = await repository.listGroups(realm, { startIndex: 1, count: 0, filter: null });
      assert.equal(zeroPage.totalResults, 2);
      assert.deepEqual(zeroPage.resources, []);

      const offPage = await repository.listGroups(realm, { startIndex: 99, count: 10, filter: null });
      assert.equal(offPage.totalResults, 2);
      assert.deepEqual(offPage.resources, []);

      const byName = await repository.listGroups(realm, {
        startIndex: 1, count: 10, filter: { attribute: 'displayName', value: 'ENGINEERING' },
      });
      assert.deepEqual(byName.resources.map(({ id }) => id), [engineering.id]);

      const byExternalId = await repository.listGroups(realm, {
        startIndex: 1, count: 10, filter: { attribute: 'externalId', value: engineering.externalId },
      });
      assert.deepEqual(byExternalId.resources.map(({ id }) => id), [engineering.id]);

      const byMember = await repository.listGroups(realm, {
        startIndex: 1, count: 10, filter: { attribute: 'members.value', value: alice.id },
      });
      assert.deepEqual(byMember.resources.map(({ id }) => id), [engineering.id]);
      assert.equal(await repository.getGroup(otherRealm, engineering.id), undefined);
      assert.equal(await repository.getGroup(realm, 'not-a-uuid'), undefined);
    });

    await t.test('Group replacement is CAS-safe and synchronizes membership, claims, ETags, and sessions', async () => {
      const aliceBefore = await coreUser(realm, alice.id);
      const bobBefore = await coreUser(realm, bob.id);
      const aliceVersion = (await repository.getUser(realm, alice.id)).version;
      const bobVersion = (await repository.getUser(realm, bob.id)).version;
      const aliceSession = await insertSession(realm, { accountId: alice.id });
      const bobSession = await insertSession(realm, { accountId: bob.id });

      engineering = await repository.replaceGroup(realm, engineering.id, {
        displayName: 'Platform/Blue',
        externalId: engineering.externalId,
        members: [{ value: alice.id }],
      }, engineering.version);
      assert.equal(engineering.version, 2);
      assert.deepEqual(engineering.members.map(({ value }) => value), [alice.id]);

      const aliceAfter = await coreUser(realm, alice.id);
      const bobAfter = await coreUser(realm, bob.id);
      assert.deepEqual(aliceAfter.groups, ['/Platform-Blue']);
      assert.deepEqual(bobAfter.groups, []);
      assert.equal(aliceAfter.security_version, aliceBefore.security_version + 1);
      assert.equal(bobAfter.security_version, bobBefore.security_version + 1);
      assert.equal((await repository.getUser(realm, alice.id)).version, aliceVersion + 1);
      assert.equal((await repository.getUser(realm, bob.id)).version, bobVersion + 1);
      assert.deepEqual(await existingSessionIds(realm, [aliceSession, bobSession]), []);

      await expectRepositoryError(
        repository.replaceGroup(realm, engineering.id, {
          displayName: 'Stale', externalId: engineering.externalId, members: [],
        }, 1),
        'VERSION_MISMATCH',
      );

      const stableUser = await coreUser(realm, alice.id);
      engineering = await repository.replaceGroup(realm, engineering.id, {
        displayName: engineering.displayName,
        externalId: engineering.externalId,
        members: engineering.members,
      }, engineering.version);
      assert.equal((await coreUser(realm, alice.id)).security_version, stableUser.security_version);

      const foreignUser = (await repository.listUsers(otherRealm, {
        startIndex: 1, count: 10, filter: { attribute: 'userName', value: 'alice' },
      })).resources[0];
      const beforeInvalid = engineering;
      await expectRepositoryError(
        repository.replaceGroup(realm, engineering.id, {
          displayName: 'Must roll back', externalId: engineering.externalId, members: [{ value: foreignUser.id }],
        }, engineering.version),
        'INVALID_VALUE',
      );
      engineering = await repository.getGroup(realm, engineering.id);
      assert.equal(engineering.version, beforeInvalid.version);
      assert.equal(engineering.displayName, beforeInvalid.displayName);
      assert.deepEqual(engineering.members, beforeInvalid.members);

      const concurrentVersion = engineering.version;
      const attempts = await Promise.allSettled([
        repository.replaceGroup(realm, engineering.id, {
          displayName: 'Platform One', externalId: engineering.externalId, members: [{ value: alice.id }],
        }, concurrentVersion),
        repository.replaceGroup(realm, engineering.id, {
          displayName: 'Platform Two', externalId: engineering.externalId, members: [{ value: alice.id }],
        }, concurrentVersion),
      ]);
      assert.equal(attempts.filter(({ status }) => status === 'fulfilled').length, 1);
      assert.equal(attempts.find(({ status }) => status === 'rejected').reason.code, 'VERSION_MISMATCH');
      engineering = await repository.getGroup(realm, engineering.id);
      assert.equal(engineering.version, concurrentVersion + 1);
    });

    await t.test('Group deletion atomically validates its version and revokes affected identity state', async () => {
      const disposable = await repository.createGroup(realm, {
        displayName: 'Disposable', externalId: 'group-disposable', members: [{ value: bob.id }],
      });
      const before = await coreUser(realm, bob.id);
      const userVersion = (await repository.getUser(realm, bob.id)).version;
      const session = await insertSession(realm, { accountId: bob.id });

      await expectRepositoryError(repository.deleteGroup(realm, disposable.id, disposable.version + 1), 'VERSION_MISMATCH');
      assert.equal((await repository.getGroup(realm, disposable.id)).id, disposable.id);

      const deleted = await repository.deleteGroup(realm, disposable.id, disposable.version);
      assert.equal(deleted.id, disposable.id);
      assert.equal(await repository.getGroup(realm, disposable.id), undefined);
      const afterDelete = await coreUser(realm, bob.id);
      assert.deepEqual(afterDelete.groups, []);
      assert.equal(afterDelete.security_version, before.security_version + 1);
      assert.equal((await repository.getUser(realm, bob.id)).version, userVersion + 1);
      assert.deepEqual(await existingSessionIds(realm, [session]), []);
    });

    await t.test('User deletion removes sessions and memberships while advancing affected Group ETags', async () => {
      const charlie = await repository.createUser(realm, userAttributes('Charlie'));
      let retainedGroup = await repository.createGroup(realm, {
        displayName: 'Retained after user deletion',
        externalId: 'group-retained',
        members: [{ value: charlie.id }],
      });
      const groupVersion = retainedGroup.version;
      const grant = await insertSession(realm, { model: 'Grant', accountId: charlie.id });
      const token = await insertSession(realm, { model: 'AccessToken', grantId: grant });
      const direct = await insertSession(realm, { accountId: charlie.id });
      const unrelated = await insertSession(realm);
      const currentCharlie = await repository.getUser(realm, charlie.id);

      await expectRepositoryError(
        repository.deleteUser(realm, charlie.id, currentCharlie.version + 1),
        'VERSION_MISMATCH',
      );
      assert.equal((await repository.getUser(realm, charlie.id)).id, charlie.id);

      const deleted = await repository.deleteUser(realm, charlie.id, currentCharlie.version);
      assert.equal(deleted.id, charlie.id);
      assert.equal(Object.hasOwn(deleted, 'password'), false);
      assert.equal(await repository.getUser(realm, charlie.id), undefined);
      assert.deepEqual(await repository.listUserGroups(realm, charlie.id), []);
      assert.deepEqual(await existingSessionIds(realm, [grant, token, direct, unrelated]), [unrelated]);

      retainedGroup = await repository.getGroup(realm, retainedGroup.id);
      assert.equal(retainedGroup.version, groupVersion + 1);
      assert.deepEqual(retainedGroup.members, []);
    });

    await t.test('concurrent Group replace/delete permits only one stale-version mutation', async () => {
      const group = await repository.createGroup(realm, {
        displayName: 'CAS race', externalId: 'group-cas-race', members: [],
      });
      const attempts = await Promise.allSettled([
        repository.replaceGroup(realm, group.id, {
          displayName: 'CAS replacement', externalId: group.externalId, members: [],
        }, group.version),
        repository.deleteGroup(realm, group.id, group.version),
      ]);
      assert.equal(attempts.filter(({ status }) => status === 'fulfilled').length, 1);
      const rejected = attempts.find(({ status }) => status === 'rejected');
      assert.ok(['NOT_FOUND', 'VERSION_MISMATCH'].includes(rejected.reason.code));
    });

    await t.test('missing resources use repository contract errors', async () => {
      const missing = randomUUID();
      await expectRepositoryError(repository.replaceUser(realm, missing, userAttributes('Missing'), 1), 'NOT_FOUND');
      await expectRepositoryError(repository.deleteUser(realm, missing, 1), 'NOT_FOUND');
      await expectRepositoryError(
        repository.replaceGroup(realm, missing, { displayName: 'Missing', members: [] }, 1),
        'NOT_FOUND',
      );
      await expectRepositoryError(repository.deleteGroup(realm, missing, 1), 'NOT_FOUND');
      await expectRepositoryError(repository.deleteUser(realm, 'not-a-uuid', 1), 'NOT_FOUND');
      await expectRepositoryError(repository.deleteGroup(realm, 'not-a-uuid', 1), 'NOT_FOUND');
    });
  } finally {
    await pool.query('DELETE FROM realms WHERE name=ANY($1::text[])', [[realm, otherRealm]]);
  }
});
