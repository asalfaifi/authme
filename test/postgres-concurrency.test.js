import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';
import { createPostgresAdapter } from '../src/adapters/postgres.js';
import { createDataLayer } from '../src/db.js';
import { PostgresIdentityStore } from '../src/repositories/identity-store.js';

const databaseUrl = process.env.DATABASE_URL;
const realm = `test-${randomUUID().slice(0, 8)}`;
let pool;

async function waitForBlockedRehash(queryable, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await queryable.query(
      `SELECT EXISTS (
         SELECT 1 FROM pg_stat_activity
         WHERE datname=current_database() AND pid<>pg_backend_pid()
           AND query LIKE '%UPDATE users SET password_hash=$4%'
           AND wait_event_type='Lock'
       ) AS waiting`,
    );
    if (result.rows[0].waiting) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
}

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({ connectionString: databaseUrl, max: 4 });
  await pool.query('INSERT INTO realms (name, display_name) VALUES ($1,$2)', [realm, realm]);
});

after(async () => {
  if (!pool) return;
  await pool.query('DELETE FROM realms WHERE name=$1', [realm]);
  await pool.end();
});

test('PostgreSQL consumption and replay claims have exactly one winner', { skip: !databaseUrl }, async () => {
  const Adapter = createPostgresAdapter({ pool, realm });
  const codes = new Adapter('AuthorizationCode');
  await codes.upsert('concurrent-code', {}, 60);
  const consumed = await Promise.allSettled([codes.consume('concurrent-code'), codes.consume('concurrent-code')]);
  assert.deepEqual(consumed.map(({ status }) => status).sort(), ['fulfilled', 'rejected']);

  const first = new Adapter('ReplayDetection');
  const second = new Adapter('ReplayDetection');
  const replayed = await Promise.allSettled([
    first.upsert('same-proof', { iss: 'client' }, 60),
    second.upsert('same-proof', { iss: 'client' }, 60),
  ]);
  assert.deepEqual(replayed.map(({ status }) => status).sort(), ['fulfilled', 'rejected']);
});

test('PostgreSQL field-specific user updates do not lose concurrent security changes', { skip: !databaseUrl }, async () => {
  const store = new PostgresIdentityStore(pool);
  const user = await store.createUser({
    realm, username: 'concurrency', email: 'concurrency@example.test', passwordHash: 'old-hash',
  });
  await Promise.all([
    store.updateUser(realm, user.id, { roles: ['operator'] }),
    store.updateUser(realm, user.id, { passwordHash: 'new-hash' }),
    store.updateUser(realm, user.id, { enabled: false }),
  ]);
  const current = await store.findUserById(realm, user.id);
  assert.deepEqual(current.roles, ['operator']);
  assert.equal(current.passwordHash, 'new-hash');
  assert.equal(current.enabled, false);
});

test('a delayed password rehash cannot overwrite a concurrent administrator reset', { skip: !databaseUrl }, async () => {
  const store = new PostgresIdentityStore(pool);
  const user = await store.createUser({
    realm,
    username: 'rehash-race',
    email: 'rehash-race@example.test',
    passwordHash: 'hash-before-login',
  });
  const resetClient = await pool.connect();
  try {
    await resetClient.query('BEGIN');
    await resetClient.query(
      'UPDATE users SET password_hash=$3 WHERE realm_name=$1 AND id=$2',
      [realm, user.id, 'hash-from-admin-reset'],
    );

    const staleRehash = store.rehashPasswordIfCurrent(
      realm,
      user.id,
      'hash-before-login',
      'rehash-of-old-password',
    );
    const waiting = await waitForBlockedRehash(pool);
    assert.equal(waiting, true, 'the stale rehash must be waiting behind the reset row lock');

    await resetClient.query('COMMIT');
    assert.equal(await staleRehash, false);
    assert.equal((await store.findUserById(realm, user.id)).passwordHash, 'hash-from-admin-reset');
  } catch (error) {
    await resetClient.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    resetClient.release();
  }
});

test('security mutations atomically revoke state and the epoch rejects stale artifacts', { skip: !databaseUrl }, async () => {
  const data = await createDataLayer({ databaseUrl, devMode: false, realms: [realm] });
  try {
    const user = await data.store.createUser({
      realm, username: 'security-epoch', email: 'security-epoch@example.test', passwordHash: 'hash',
    });
    const Adapter = data.adapterFor(realm);
    const tokens = new Adapter('AccessToken');
    const grants = new Adapter('Grant');
    await grants.upsert('security-grant', { accountId: user.id, clientId: 'app' }, 600);
    await tokens.upsert('before-mutation', {
      accountId: user.id, grantId: 'security-grant', clientId: 'app',
    }, 600);

    await assert.rejects(
      data.mutateAccountSecurity(realm, user.id, async (transactionalStore) => {
        const updated = await transactionalStore.updateUser(realm, user.id, { roles: ['must-rollback'] });
        await transactionalStore.writeAudit({ realm, type: '', subjectId: user.id });
        return updated;
      }),
      (error) => error.code === '23514',
    );
    const afterAuditFailure = await data.store.findUserById(realm, user.id);
    assert.deepEqual(afterAuditFailure.roles, []);
    assert.equal(afterAuditFailure.securityVersion, 0);
    assert.notEqual(await tokens.find('before-mutation'), undefined);

    const mutation = await data.mutateAccountSecurity(realm, user.id, (store) => (
      store.updateUser(realm, user.id, { roles: ['security-admin'] })
    ));
    assert.equal(mutation.applied, true);
    assert.equal(mutation.user.securityVersion, 1);
    assert.equal(await tokens.find('before-mutation'), undefined);

    await assert.rejects(
      tokens.upsert('late-after-revocation', {
        accountId: user.id, grantId: 'security-grant', clientId: 'app',
      }, 600),
      /invalid_grant/,
    );
    await assert.rejects(
      tokens.upsert('late-with-parent-account-only', { grantId: 'security-grant', clientId: 'app' }, 600),
      /invalid_grant/,
    );

    await tokens.upsert('stale-epoch', { accountId: user.id, clientId: 'app' }, 600);
    await pool.query(
      'UPDATE users SET security_version=security_version+1 WHERE realm_name=$1 AND id=$2',
      [realm, user.id],
    );
    assert.equal(await tokens.find('stale-epoch'), undefined);
  } finally {
    await data.close();
  }
});

test('account deletion atomically removes the user and realm-scoped provider state', { skip: !databaseUrl }, async () => {
  const data = await createDataLayer({ databaseUrl, devMode: false, realms: [realm] });
  try {
    const user = await data.store.createUser({
      realm, username: 'delete-account', email: 'delete-account@example.test', passwordHash: 'hash',
    });
    const Adapter = data.adapterFor(realm);
    const sessions = new Adapter('Session');
    const grants = new Adapter('Grant');
    const tokens = new Adapter('AccessToken');
    await sessions.upsert('delete-session', { accountId: user.id }, 600);
    await grants.upsert('delete-grant', { accountId: user.id }, 600);
    await tokens.upsert('delete-token', { accountId: user.id, grantId: 'delete-grant' }, 600);

    await assert.rejects(
      data.deleteAccount(realm, user.id, {
        realm,
        type: '',
        subjectId: user.id,
      }),
      (error) => error.code === '23514',
    );
    assert.equal((await data.store.findUserById(realm, user.id)).id, user.id);
    assert.notEqual(await sessions.find('delete-session'), undefined);
    assert.notEqual(await grants.find('delete-grant'), undefined);
    assert.notEqual(await tokens.find('delete-token'), undefined);

    const deleted = await data.deleteAccount(realm, user.id, {
      realm,
      type: 'admin.user.deleted',
      subjectId: user.id,
    });
    assert.equal(deleted.found, true);
    assert.equal(deleted.user.id, user.id);
    assert.equal(await data.store.findUserById(realm, user.id), null);
    assert.equal(await sessions.find('delete-session'), undefined);
    assert.equal(await grants.find('delete-grant'), undefined);
    assert.equal(await tokens.find('delete-token'), undefined);
    const deletionAudit = (await data.store.listAudit(realm))
      .filter(({ type }) => type === 'admin.user.deleted');
    assert.equal(deletionAudit.length, 1);
    assert.equal(deletionAudit[0].subjectId, user.id);
    assert.equal(deletionAudit[0].subject_id, undefined);
    assert.ok(deletionAudit[0].createdAt instanceof Date);
    assert.deepEqual(await data.deleteAccount(realm, user.id), { found: false, user: null });
  } finally {
    await data.close();
  }
});

test('audit retention deletes only records older than the configured window', { skip: !databaseUrl }, async () => {
  const data = await createDataLayer({ databaseUrl, devMode: false, realms: [realm] });
  try {
    const oldId = randomUUID();
    const recentId = randomUUID();
    await pool.query(
      `INSERT INTO audit_events (realm_name,id,event_type,created_at)
       VALUES ($1,$2,'test.old',now()-interval '120 days'),($1,$3,'test.recent',now())`,
      [realm, oldId, recentId],
    );
    assert.equal(await data.cleanupAudit(90, 1), 1);
    assert.equal(await data.cleanupAudit(90, 1), 0);
    const remaining = await pool.query(
      'SELECT id FROM audit_events WHERE realm_name=$1 AND id=ANY($2::uuid[])',
      [realm, [oldId, recentId]],
    );
    assert.deepEqual(remaining.rows.map(({ id }) => id), [recentId]);
  } finally {
    await data.close();
  }
});
