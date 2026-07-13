import pg from 'pg';
import { claimMemoryInitialAccessToken, createMemoryAdapter, revokeMemoryAccount } from './adapters/memory.js';
import { createPostgresAdapter } from './adapters/postgres.js';
import { MemoryIdentityStore, PostgresIdentityStore } from './repositories/identity-store.js';

const revokeAccountSql = `WITH account_grants AS MATERIALIZED (
    SELECT id FROM oidc_records
    WHERE realm_name=$1 AND model='Grant'
      AND payload ? 'accountId' AND payload->>'accountId'=$2
  ), doomed AS (
    SELECT realm_name, model, id FROM oidc_records
    WHERE realm_name=$1
      AND payload ? 'accountId' AND payload->>'accountId'=$2
    UNION
    SELECT records.realm_name, records.model, records.id
    FROM oidc_records AS records
    JOIN account_grants AS grants ON grants.id=records.grant_id
    WHERE records.realm_name=$1 AND records.grant_id IS NOT NULL
  )
  DELETE FROM oidc_records AS records USING doomed
  WHERE records.realm_name=doomed.realm_name
    AND records.model=doomed.model AND records.id=doomed.id`;

export async function createDataLayer(config) {
  if (!config.databaseUrl) {
    if (!config.devMode) throw new Error('The in-memory store is permitted only in development mode');
    const store = new MemoryIdentityStore();
    return {
      store,
      adapterFor: (realm) => createMemoryAdapter({
        realm,
        async securityVersionFor(accountId) {
          const user = await store.findUserById(realm, accountId);
          return user?.enabled ? user.securityVersion : null;
        },
      }),
      async claimInitialAccessToken(realm, id) { return claimMemoryInitialAccessToken(realm, id); },
      async revokeAccount(realm, accountId) { return revokeMemoryAccount(realm, accountId); },
      async mutateAccountSecurity(realm, accountId, mutate) {
        const current = await store.findUserById(realm, accountId);
        if (!current) return { found: false, applied: false, result: null, user: null };
        const result = await mutate(store);
        if (!result) return { found: true, applied: false, result, user: await store.findUserById(realm, accountId) };
        await store.bumpSecurityVersion(realm, accountId);
        revokeMemoryAccount(realm, accountId);
        return { found: true, applied: true, result, user: await store.findUserById(realm, accountId) };
      },
      async cleanupExpired() { return 0; },
      async cleanupAudit() { return 0; },
      async close() { await store.close(); },
    };
  }

  const pool = new pg.Pool({
    connectionString: config.databaseUrl,
    max: 20,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: 'authme',
  });
  const store = new PostgresIdentityStore(pool);
  await store.ready();
  for (const realm of config.realms) {
    await pool.query(
      `INSERT INTO realms (name, display_name) VALUES ($1, $2)
       ON CONFLICT (name) DO UPDATE SET display_name=EXCLUDED.display_name`,
      [realm, realm === 'master' ? 'Master' : realm],
    );
  }
  return {
    pool,
    store,
    adapterFor: (realm) => createPostgresAdapter({ pool, realm }),
    async claimInitialAccessToken(realm, id) {
      const result = await pool.query(
        `UPDATE oidc_records SET consumed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
         WHERE realm_name=$1 AND model='InitialAccessToken' AND id=$2
           AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
         RETURNING id`,
        [realm, id],
      );
      return result.rowCount === 1;
    },
    async revokeAccount(realm, accountId) {
      const result = await pool.query(revokeAccountSql, [realm, accountId]);
      return result.rowCount;
    },
    async mutateAccountSecurity(realm, accountId, mutate) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const locked = await client.query(
          'SELECT id FROM users WHERE realm_name=$1 AND id=$2 FOR UPDATE',
          [realm, accountId],
        );
        if (locked.rowCount !== 1) {
          await client.query('ROLLBACK');
          return { found: false, applied: false, result: null, user: null };
        }
        const transactionalStore = new PostgresIdentityStore(client);
        const result = await mutate(transactionalStore);
        if (!result) {
          const user = await transactionalStore.findUserById(realm, accountId);
          await client.query('COMMIT');
          return { found: true, applied: false, result, user };
        }
        await client.query(
          'UPDATE users SET security_version=security_version+1, updated_at=now() WHERE realm_name=$1 AND id=$2',
          [realm, accountId],
        );
        await client.query(revokeAccountSql, [realm, accountId]);
        const user = await transactionalStore.findUserById(realm, accountId);
        await client.query('COMMIT');
        return { found: true, applied: true, result, user };
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    },
    async cleanupExpired(limit = 1000) {
      const result = await pool.query(
        `DELETE FROM oidc_records WHERE ctid IN (
           SELECT ctid FROM oidc_records
         WHERE expires_at <= CURRENT_TIMESTAMP
           ORDER BY expires_at
           FOR UPDATE SKIP LOCKED LIMIT $1
         )`,
        [limit],
      );
      return result.rowCount;
    },
    async cleanupAudit(retentionDays, limit = 1000) {
      const result = await pool.query(
        `DELETE FROM audit_events WHERE ctid IN (
           SELECT ctid FROM audit_events
           WHERE created_at < CURRENT_TIMESTAMP - ($1::integer * interval '1 day')
           ORDER BY created_at
           FOR UPDATE SKIP LOCKED LIMIT $2
         )`,
        [retentionDays, limit],
      );
      return result.rowCount;
    },
    async close() { await store.close(); },
  };
}
