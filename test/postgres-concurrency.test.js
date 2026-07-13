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
  await codes.upsert('concurrent-code', { grantId: 'grant' }, 60);
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

test('security mutations atomically revoke state and the epoch rejects stale artifacts', { skip: !databaseUrl }, async () => {
  const data = await createDataLayer({ databaseUrl, devMode: false, realms: [realm] });
  try {
    const user = await data.store.createUser({
      realm, username: 'security-epoch', email: 'security-epoch@example.test', passwordHash: 'hash',
    });
    const Adapter = data.adapterFor(realm);
    const tokens = new Adapter('AccessToken');
    await tokens.upsert('before-mutation', { accountId: user.id, clientId: 'app' }, 600);

    const mutation = await data.mutateAccountSecurity(realm, user.id, (store) => (
      store.updateUser(realm, user.id, { roles: ['security-admin'] })
    ));
    assert.equal(mutation.applied, true);
    assert.equal(mutation.user.securityVersion, 1);
    assert.equal(await tokens.find('before-mutation'), undefined);

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
