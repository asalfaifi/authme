import pg from 'pg';
import {
  claimMemoryInitialAccessToken,
  createMemoryAdapter,
  listMemoryAdapterRecords,
  listMemoryAccountSessions,
  revokeMemoryAccount,
  revokeMemoryClient,
  revokeMemorySession,
} from './adapters/memory.js';
import { createPostgresAdapter } from './adapters/postgres.js';
import { verifyMigrationState } from './migrations.js';
import { MemoryIdentityStore, PostgresIdentityStore } from './repositories/identity-store.js';
import { MemoryManagementStore, PostgresManagementStore } from './repositories/management-store.js';

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

export const cleanupExpiredOidcSql = `DELETE FROM oidc_records WHERE ctid IN (
  SELECT ctid FROM oidc_records
  WHERE expires_at <= CURRENT_TIMESTAMP
    AND (model <> 'BackchannelAuthenticationRequest'
      OR expires_at <= CURRENT_TIMESTAMP - INTERVAL '1 day')
    ORDER BY expires_at
    FOR UPDATE SKIP LOCKED LIMIT $1
)`;

async function restoreMemoryWebAuthnCredentials(store, realm, accountId, snapshot) {
  const current = await store.listWebAuthnCredentials(realm, accountId);
  for (const credential of current) {
    await store.deleteWebAuthnCredential(realm, accountId, credential.id);
  }
  for (const credential of snapshot) await store.createWebAuthnCredential(credential);
}

export async function createDataLayer(config) {
  if (!config.databaseUrl) {
    if (!config.devMode) throw new Error('The in-memory store is permitted only in development mode');
    const store = new MemoryIdentityStore();
    const management = new MemoryManagementStore(config.realms);
    const adapterFor = (realm) => createMemoryAdapter({
      realm,
      async securityVersionFor(accountId) {
        const user = await store.findUserById(realm, accountId);
        return user?.enabled ? user.securityVersion : null;
      },
    });
    return {
      store,
      management,
      adapterFor,
      async listManagedClients(realm) {
        return listMemoryAdapterRecords(realm, 'Client').map(({ id, payload }) => ({ id, metadata: payload }));
      },
      async upsertManagedClient(realm, metadata) {
        const Adapter = adapterFor(realm);
        await new Adapter('Client').upsert(metadata.client_id, metadata);
        return cloneManagedClient(metadata);
      },
      async deleteManagedClient(realm, clientId) {
        const Adapter = adapterFor(realm);
        const existing = await new Adapter('Client').find(clientId);
        if (!existing) return false;
        const affectedUsers = [];
        for (let offset = 0; ; offset += 200) {
          const users = await store.listUsers(realm, { limit: 200, offset });
          affectedUsers.push(...users.filter((user) => Object.hasOwn(user.clientRoles ?? {}, clientId)));
          if (users.length < 200) break;
        }
        await new Adapter('Client').destroy(clientId);
        revokeMemoryClient(realm, clientId);
        await management.deleteClientPolicy(realm, clientId);
        for (const user of affectedUsers) {
          const clientRoles = structuredClone(user.clientRoles);
          delete clientRoles[clientId];
          await store.updateUser(realm, user.id, { clientRoles });
          await store.bumpSecurityVersion(realm, user.id);
          revokeMemoryAccount(realm, user.id);
        }
        return true;
      },
      async claimInitialAccessToken(realm, id) { return claimMemoryInitialAccessToken(realm, id); },
      async revokeAccount(realm, accountId) { return revokeMemoryAccount(realm, accountId); },
      async listOidcSessions(realm, accountId) { return listMemoryAccountSessions(realm, accountId); },
      async revokeOidcSession(realm, accountId, sessionId) {
        return revokeMemorySession(realm, accountId, sessionId);
      },
      async deleteAccount(realm, accountId, auditEvent) {
        const credentials = await store.listWebAuthnCredentials(realm, accountId);
        const adminGrant = await store.findAdminGrant(realm, accountId);
        const user = await store.deleteUser(realm, accountId);
        if (!user) return { found: false, user: null };
        try {
          if (auditEvent) await store.writeAudit(auditEvent);
        } catch (error) {
          await store.createUser(user);
          if (adminGrant) await store.restoreAdminGrant(adminGrant);
          await restoreMemoryWebAuthnCredentials(store, realm, accountId, credentials);
          throw error;
        }
        revokeMemoryAccount(realm, accountId);
        return { found: true, user };
      },
      async mutateAccountSecurity(realm, accountId, mutate) {
        const current = await store.findUserById(realm, accountId);
        if (!current) return { found: false, applied: false, result: null, user: null };
        const credentials = await store.listWebAuthnCredentials(realm, accountId);
        let result;
        try {
          result = await mutate(store);
        } catch (error) {
          await store.restoreUser(current);
          await restoreMemoryWebAuthnCredentials(store, realm, accountId, credentials);
          throw error;
        }
        if (!result) return { found: true, applied: false, result, user: await store.findUserById(realm, accountId) };
        await store.bumpSecurityVersion(realm, accountId);
        revokeMemoryAccount(realm, accountId);
        return { found: true, applied: true, result, user: await store.findUserById(realm, accountId) };
      },
      async cleanupExpired(limit = 1000) {
        return await store.cleanupExpiredWebAuthnChallenges(limit)
          + await store.cleanupExpiredAdminSessions(limit)
          + await store.cleanupExpiredAccountSessions(limit)
          + await store.cleanupExpiredAccountActionTokens(limit);
      },
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
  const management = new PostgresManagementStore(pool);
  try {
    await store.ready();
    if (!config.devMode) await verifyMigrationState(pool);
    for (const realm of config.realms) {
      await pool.query(
        `INSERT INTO realms (name, display_name) VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE SET display_name=EXCLUDED.display_name`,
        [realm, realm === 'master' ? 'Master' : realm],
      );
    }
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
  return {
    pool,
    store,
    management,
    adapterFor: (realm) => createPostgresAdapter({ pool, realm }),
    async listManagedClients(realm) {
      const result = await pool.query(
        `SELECT id, payload FROM oidc_records
         WHERE realm_name=$1 AND model='Client' AND (expires_at IS NULL OR expires_at>CURRENT_TIMESTAMP)
         ORDER BY id`,
        [realm],
      );
      return result.rows.map(({ id, payload }) => ({ id, metadata: structuredClone(payload) }));
    },
    async upsertManagedClient(realm, metadata) {
      const Adapter = createPostgresAdapter({ pool, realm });
      await new Adapter('Client').upsert(metadata.client_id, metadata);
      return cloneManagedClient(metadata);
    },
    async deleteManagedClient(realm, clientId) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [
          `authme:client-roles:${realm}:${clientId}`,
        ]);
        const result = await client.query(
          `WITH removed_client AS (
             DELETE FROM oidc_records WHERE realm_name=$1 AND model='Client' AND id=$2 RETURNING id
           ), affected_users AS MATERIALIZED (
             SELECT id::text AS id FROM users
             WHERE realm_name=$1 AND client_roles ? $2
               AND EXISTS (SELECT 1 FROM removed_client)
             FOR UPDATE
           ), updated_users AS (
             UPDATE users SET client_roles=client_roles-$2,
               security_version=security_version+1, updated_at=CURRENT_TIMESTAMP
             WHERE realm_name=$1 AND id::text IN (SELECT id FROM affected_users)
             RETURNING id::text AS id
           ), client_grants AS MATERIALIZED (
             SELECT id FROM oidc_records
             WHERE realm_name=$1 AND model='Grant' AND payload->>'clientId'=$2
               AND EXISTS (SELECT 1 FROM removed_client)
           ), account_grants AS MATERIALIZED (
             SELECT id FROM oidc_records
             WHERE realm_name=$1 AND model='Grant'
               AND payload->>'accountId' IN (SELECT id FROM updated_users)
           ), revoked AS (
             DELETE FROM oidc_records WHERE realm_name=$1
               AND EXISTS (SELECT 1 FROM removed_client)
               AND ((payload->>'clientId'=$2 AND model<>'Client')
                 OR payload->>'accountId' IN (SELECT id FROM updated_users)
                 OR grant_id IN (SELECT id FROM client_grants)
                 OR grant_id IN (SELECT id FROM account_grants))
           ), assignments AS (
             DELETE FROM client_scope_assignments
             WHERE realm_name=$1 AND client_id=$2 AND EXISTS (SELECT 1 FROM removed_client)
           ), mappers AS (
             DELETE FROM claim_mappers
             WHERE realm_name=$1 AND owner_type='client' AND owner_id=$2 AND EXISTS (SELECT 1 FROM removed_client)
           ), roles AS (
             DELETE FROM client_roles
             WHERE realm_name=$1 AND client_id=$2 AND EXISTS (SELECT 1 FROM removed_client)
           ), updated_flows AS (
             UPDATE authentication_flows SET client_ids=array_remove(client_ids,$2)
             WHERE realm_name=$1 AND $2=ANY(client_ids) AND cardinality(client_ids)>1
               AND EXISTS (SELECT 1 FROM removed_client)
           ), deleted_flows AS (
             DELETE FROM authentication_flows
             WHERE realm_name=$1 AND $2=ANY(client_ids) AND cardinality(client_ids)=1
               AND EXISTS (SELECT 1 FROM removed_client)
           ) SELECT id FROM removed_client`,
          [realm, clientId],
        );
        await client.query('COMMIT');
        return result.rowCount === 1;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    },
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
    async listOidcSessions(realm, accountId) {
      const result = await pool.query(
        `SELECT id, payload, created_at, updated_at, expires_at
         FROM oidc_records
         WHERE realm_name=$1 AND model='Session'
           AND payload->>'accountId'=$2
           AND (expires_at IS NULL OR expires_at>CURRENT_TIMESTAMP)
           AND EXISTS (
             SELECT 1 FROM users
             WHERE users.realm_name=oidc_records.realm_name
               AND users.id=(oidc_records.payload->>'accountId')::uuid
               AND users.enabled
               AND users.security_version=oidc_records.account_security_version
           )
         ORDER BY updated_at DESC`,
        [realm, accountId],
      );
      return result.rows.map((row) => ({
        id: row.id,
        createdAt: row.created_at?.toISOString?.() ?? row.created_at,
        lastSeenAt: row.updated_at?.toISOString?.() ?? row.updated_at,
        expiresAt: row.expires_at?.toISOString?.() ?? row.expires_at,
        clientIds: row.payload?.authorizations && typeof row.payload.authorizations === 'object'
          ? Object.keys(row.payload.authorizations)
          : [],
      }));
    },
    async revokeOidcSession(realm, accountId, sessionId) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const target = await client.query(
          `SELECT payload FROM oidc_records
           WHERE realm_name=$1 AND model='Session' AND id=$2
             AND payload->>'accountId'=$3
           FOR UPDATE`,
          [realm, sessionId, accountId],
        );
        if (target.rowCount !== 1) {
          await client.query('ROLLBACK');
          return false;
        }
        const grantIds = Object.values(target.rows[0].payload?.authorizations ?? {})
          .filter((value) => typeof value === 'string');
        await client.query(
          `DELETE FROM oidc_records
           WHERE realm_name=$1 AND (
             (model='Session' AND id=$2)
             OR (model='Grant' AND id=ANY($3::text[]))
             OR grant_id=ANY($3::text[])
           )`,
          [realm, sessionId, grantIds],
        );
        await client.query('COMMIT');
        return true;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    },
    async deleteAccount(realm, accountId, auditEvent) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const locked = await client.query(
          'SELECT id FROM users WHERE realm_name=$1 AND id=$2 FOR UPDATE',
          [realm, accountId],
        );
        if (locked.rowCount !== 1) {
          await client.query('ROLLBACK');
          return { found: false, user: null };
        }
        await client.query(revokeAccountSql, [realm, accountId]);
        const transactionalStore = new PostgresIdentityStore(client);
        const user = await transactionalStore.deleteUser(realm, accountId);
        if (auditEvent) await transactionalStore.writeAudit(auditEvent);
        await client.query('COMMIT');
        return { found: true, user };
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        client.release();
      }
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
      const oidc = await pool.query(cleanupExpiredOidcSql, [limit]);
      return oidc.rowCount
        + await store.cleanupExpiredWebAuthnChallenges(limit)
        + await store.cleanupExpiredAdminSessions(limit)
        + await store.cleanupExpiredAccountSessions(limit)
        + await store.cleanupExpiredAccountActionTokens(limit);
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

function cloneManagedClient(metadata) {
  return structuredClone(metadata);
}
