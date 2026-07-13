import { randomUUID } from 'node:crypto';

import { ScimRepositoryError } from '../scim/errors.js';

function repositoryError(code, message) {
  return new ScimRepositoryError(code, message);
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value) {
  return typeof value === 'string' && uuidPattern.test(value);
}

function json(value) {
  if (!value) return {};
  return typeof value === 'string' ? JSON.parse(value) : value;
}

function scimAttributes(attributes) {
  const { password, externalId, userName, active, ...safe } = attributes;
  return safe;
}

function primaryValue(values) {
  if (!Array.isArray(values)) return '';
  const primary = values.find((item) => item?.primary === true && typeof item.value === 'string');
  const first = values.find((item) => typeof item?.value === 'string');
  return String(primary?.value ?? first?.value ?? '').trim();
}

function coreUser(attributes, id) {
  const extra = scimAttributes(attributes);
  const givenName = String(attributes.name?.givenName ?? '').trim();
  const familyName = String(attributes.name?.familyName ?? '').trim();
  const displayName = String(attributes.displayName
    ?? attributes.name?.formatted
    ?? [givenName, familyName].filter(Boolean).join(' ')
    ?? attributes.userName).trim() || attributes.userName;
  const email = primaryValue(attributes.emails).toLowerCase()
    || (String(attributes.userName).includes('@') ? String(attributes.userName).toLowerCase() : `scim-${id}@invalid.local`);
  const roles = Array.isArray(attributes.roles)
    ? [...new Set(attributes.roles.map((role) => String(role?.value ?? role?.display ?? '').trim()).filter(Boolean))]
    : [];
  return {
    username: attributes.userName,
    email,
    emailVerified: Boolean(attributes.emails?.find((item) => item?.value?.toLowerCase?.() === email)?.verified),
    displayName,
    givenName,
    familyName,
    enabled: attributes.active !== false,
    roles,
    extra,
  };
}

function rowToUser(row) {
  if (!row) return undefined;
  const attributes = json(row.scim_attributes);
  return {
    ...attributes,
    userName: row.username,
    ...(row.external_id == null ? {} : { externalId: row.external_id }),
    displayName: row.display_name,
    name: {
      ...(attributes.name ?? {}),
      ...(row.given_name ? { givenName: row.given_name } : {}),
      ...(row.family_name ? { familyName: row.family_name } : {}),
      formatted: row.display_name,
    },
    emails: Array.isArray(attributes.emails) && attributes.emails.length
      ? attributes.emails : [{ value: row.email, primary: true }],
    roles: Array.isArray(attributes.roles) && attributes.roles.length
      ? attributes.roles : row.roles.map((value) => ({ value })),
    active: row.enabled,
    id: row.id,
    version: Number(row.version),
    createdAt: row.scim_created_at?.toISOString?.() ?? row.scim_created_at,
    updatedAt: row.scim_updated_at?.toISOString?.() ?? row.scim_updated_at,
  };
}

function rowToGroup(row, members = []) {
  if (!row) return undefined;
  return {
    ...(row.external_id == null ? {} : { externalId: row.external_id }),
    displayName: row.display_name,
    members: members.map((value) => ({ value, type: 'User' })),
    id: row.id,
    version: Number(row.version),
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
  };
}

const userSelect = `SELECT users.*, resources.external_id, resources.version,
  resources.created_at AS scim_created_at, resources.updated_at AS scim_updated_at,
  users.attributes->'scim' AS scim_attributes
 FROM users JOIN scim_user_resources AS resources
   ON resources.realm_name=users.realm_name AND resources.user_id=users.id`;

function translateConstraint(error, resourceType) {
  if (error?.code === '23505') {
    return repositoryError('UNIQUENESS', `${resourceType} userName, displayName, email, or externalId already exists in this realm.`);
  }
  if (error?.code === '23503') return repositoryError('INVALID_VALUE', 'A referenced User does not exist in this realm.');
  if (error?.code === '22P02') return repositoryError('INVALID_VALUE', 'A SCIM resource identifier is invalid.');
  return error;
}

function filterSql(filter, resourceType, startParameter = 2) {
  if (!filter) return { sql: '', values: [] };
  const userColumns = { id: 'users.id::text', userName: 'lower(users.username)', externalId: 'resources.external_id', active: 'users.enabled::text' };
  const groupColumns = { id: 'groups.id::text', displayName: 'lower(groups.display_name)', externalId: 'groups.external_id' };
  const column = (resourceType === 'User' ? userColumns : groupColumns)[filter.attribute];
  if (!column) return { sql: '', values: [] };
  const insensitive = ['userName', 'displayName'].includes(filter.attribute);
  return { sql: ` AND ${column}=$${startParameter}`, values: [insensitive ? filter.value.toLowerCase() : filter.value] };
}

async function withTransaction(pool, operation) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function revokeAccounts(client, realm, accountIds) {
  if (!accountIds.length) return;
  await client.query(
    `WITH account_grants AS MATERIALIZED (
       SELECT id FROM oidc_records
       WHERE realm_name=$1 AND model='Grant'
         AND payload ? 'accountId' AND payload->>'accountId'=ANY($2::text[])
     ), doomed AS (
       SELECT realm_name,model,id FROM oidc_records
       WHERE realm_name=$1
         AND payload ? 'accountId' AND payload->>'accountId'=ANY($2::text[])
       UNION
       SELECT records.realm_name,records.model,records.id
       FROM oidc_records AS records
       JOIN account_grants AS grants ON grants.id=records.grant_id
       WHERE records.realm_name=$1 AND records.grant_id IS NOT NULL
     )
     DELETE FROM oidc_records AS records USING doomed
     WHERE records.realm_name=doomed.realm_name
       AND records.model=doomed.model AND records.id=doomed.id`,
    [realm, accountIds],
  );
}

export class PostgresScimRepository {
  constructor(pool, { hashPassword, disabledPasswordHash }) {
    if (!pool?.query || !pool?.connect) throw new TypeError('PostgresScimRepository requires a PostgreSQL pool');
    if (typeof hashPassword !== 'function' || typeof disabledPasswordHash !== 'string') {
      throw new TypeError('PostgresScimRepository requires password hashing and a disabled password hash');
    }
    this.pool = pool;
    this.hashPassword = hashPassword;
    this.disabledPasswordHash = disabledPasswordHash;
  }

  async listUsers(realm, options) {
    const filtered = filterSql(options.filter, 'User');
    const values = [realm, ...filtered.values, options.count, options.startIndex - 1];
    const countParameter = 2 + filtered.values.length;
    const offsetParameter = countParameter + 1;
    const result = await this.pool.query(
      `WITH selected AS (${userSelect} WHERE users.realm_name=$1${filtered.sql})
       SELECT selected.*, count(*) OVER()::integer AS total_results
       FROM selected ORDER BY id LIMIT $${countParameter} OFFSET $${offsetParameter}`,
      values,
    );
    let totalResults = result.rows[0]?.total_results ?? 0;
    if (!result.rows.length) {
      const count = await this.pool.query(
        `SELECT count(*)::integer AS total FROM users JOIN scim_user_resources AS resources
         ON resources.realm_name=users.realm_name AND resources.user_id=users.id
         WHERE users.realm_name=$1${filtered.sql}`,
        [realm, ...filtered.values],
      );
      totalResults = count.rows[0].total;
    }
    return { totalResults, resources: result.rows.map(rowToUser) };
  }

  async getUser(realm, id) {
    if (!isUuid(id)) return undefined;
    const result = await this.pool.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2`, [realm, id]);
    return rowToUser(result.rows[0]);
  }

  async createUser(realm, attributes) {
    const id = randomUUID();
    const core = coreUser(attributes, id);
    let passwordHash = this.disabledPasswordHash;
    if (attributes.password !== undefined) {
      if (typeof attributes.password !== 'string' || attributes.password.length < 12 || attributes.password.length > 1024) {
        throw repositoryError('INVALID_VALUE', 'password does not meet the AuthMe password policy.');
      }
      passwordHash = await this.hashPassword(attributes.password);
    }
    try {
      return await withTransaction(this.pool, async (client) => {
        await client.query(
          `INSERT INTO users
           (realm_name,id,username,email,email_verified,display_name,given_name,family_name,enabled,
            password_hash,roles,groups,client_roles,attributes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'{}','{}',$12)`,
          [realm, id, core.username, core.email, core.emailVerified, core.displayName, core.givenName,
            core.familyName, core.enabled, passwordHash, core.roles, { scim: core.extra }],
        );
        await client.query(
          'UPDATE scim_user_resources SET external_id=$3 WHERE realm_name=$1 AND user_id=$2',
          [realm, id, attributes.externalId ?? null],
        );
        const result = await client.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2`, [realm, id]);
        return rowToUser(result.rows[0]);
      });
    } catch (error) { throw translateConstraint(error, 'User'); }
  }

  async replaceUser(realm, id, attributes, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
    const core = coreUser(attributes, id);
    let passwordHash;
    if (attributes.password !== undefined) {
      if (typeof attributes.password !== 'string' || attributes.password.length < 12 || attributes.password.length > 1024) {
        throw repositoryError('INVALID_VALUE', 'password does not meet the AuthMe password policy.');
      }
      passwordHash = await this.hashPassword(attributes.password);
    }
    try {
      return await withTransaction(this.pool, async (client) => {
        const locked = await client.query(
          `SELECT users.password_hash, resources.version FROM users JOIN scim_user_resources AS resources
           ON resources.realm_name=users.realm_name AND resources.user_id=users.id
           WHERE users.realm_name=$1 AND users.id=$2 FOR UPDATE OF users, resources`,
          [realm, id],
        );
        if (!locked.rows.length) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
        if (Number(locked.rows[0].version) !== expectedVersion) {
          throw repositoryError('VERSION_MISMATCH', 'The SCIM User changed since it was read.');
        }
        await client.query(
          `UPDATE users SET username=$3,email=$4,email_verified=$5,display_name=$6,given_name=$7,
             family_name=$8,enabled=$9,password_hash=$10,roles=$11,
             attributes=jsonb_set(attributes,'{scim}',$12::jsonb,true),
             security_version=security_version+1,failed_attempts=0,locked_until=NULL
           WHERE realm_name=$1 AND id=$2`,
          [realm, id, core.username, core.email, core.emailVerified, core.displayName, core.givenName,
            core.familyName, core.enabled, passwordHash ?? locked.rows[0].password_hash, core.roles, core.extra],
        );
        await client.query(
          'UPDATE scim_user_resources SET external_id=$3 WHERE realm_name=$1 AND user_id=$2',
          [realm, id, attributes.externalId ?? null],
        );
        await revokeAccounts(client, realm, [id]);
        const result = await client.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2`, [realm, id]);
        return rowToUser(result.rows[0]);
      });
    } catch (error) { throw translateConstraint(error, 'User'); }
  }

  async deleteUser(realm, id, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
    return withTransaction(this.pool, async (client) => {
      const current = await client.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2 FOR UPDATE OF users, resources`, [realm, id]);
      if (!current.rows.length) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
      if (Number(current.rows[0].version) !== expectedVersion) throw repositoryError('VERSION_MISMATCH', 'The SCIM User changed since it was read.');
      const memberships = await client.query(
        'SELECT group_id::text FROM scim_group_members WHERE realm_name=$1 AND user_id=$2', [realm, id],
      );
      const groupIds = memberships.rows.map(({ group_id: groupId }) => groupId);
      if (groupIds.length) {
        await client.query(
          `UPDATE scim_groups SET version=version+1
           WHERE realm_name=$1 AND id=ANY($2::uuid[])`, [realm, groupIds],
        );
      }
      await revokeAccounts(client, realm, [id]);
      await client.query('DELETE FROM users WHERE realm_name=$1 AND id=$2', [realm, id]);
      return rowToUser(current.rows[0]);
    });
  }

  async #group(realm, id, client = this.pool) {
    if (!isUuid(id)) return undefined;
    const result = await client.query('SELECT * FROM scim_groups WHERE realm_name=$1 AND id=$2', [realm, id]);
    if (!result.rows.length) return undefined;
    const members = await client.query(
      'SELECT user_id::text FROM scim_group_members WHERE realm_name=$1 AND group_id=$2 ORDER BY user_id', [realm, id],
    );
    return rowToGroup(result.rows[0], members.rows.map(({ user_id: userId }) => userId));
  }

  async listGroups(realm, options) {
    let join = '';
    let memberCondition = '';
    let filtered = filterSql(options.filter, 'Group');
    if (options.filter?.attribute === 'members.value') {
      join = ' JOIN scim_group_members AS membership ON membership.realm_name=groups.realm_name AND membership.group_id=groups.id';
      memberCondition = ' AND membership.user_id::text=$2';
      filtered = { sql: memberCondition, values: [options.filter.value] };
    }
    const values = [realm, ...filtered.values, options.count, options.startIndex - 1];
    const limit = 2 + filtered.values.length;
    const result = await this.pool.query(
      `SELECT DISTINCT groups.*, count(*) OVER()::integer AS total_results
       FROM scim_groups AS groups${join} WHERE groups.realm_name=$1${filtered.sql}
       ORDER BY groups.id LIMIT $${limit} OFFSET $${limit + 1}`,
      values,
    );
    const resources = await Promise.all(result.rows.map((row) => this.#group(realm, row.id)));
    let totalResults = result.rows[0]?.total_results ?? 0;
    if (!result.rows.length) {
      const count = await this.pool.query(
        `SELECT count(DISTINCT groups.id)::integer AS total
         FROM scim_groups AS groups${join} WHERE groups.realm_name=$1${filtered.sql}`,
        [realm, ...filtered.values],
      );
      totalResults = count.rows[0].total;
    }
    return { totalResults, resources };
  }

  async getGroup(realm, id) { return this.#group(realm, id); }

  async #replaceMembers(client, realm, groupId, members) {
    const ids = members.map(({ value }) => value);
    if (ids.some((id) => !isUuid(id)) || new Set(ids).size !== ids.length) {
      throw repositoryError('INVALID_VALUE', 'Group members must be distinct User identifiers.');
    }
    if (ids.length) {
      const found = await client.query('SELECT id::text FROM users WHERE realm_name=$1 AND id=ANY($2::uuid[])', [realm, ids]);
      if (found.rowCount !== ids.length) throw repositoryError('INVALID_VALUE', 'A Group member is not a User in this realm.');
    }
    const previous = await client.query('SELECT user_id::text FROM scim_group_members WHERE realm_name=$1 AND group_id=$2', [realm, groupId]);
    await client.query('DELETE FROM scim_group_members WHERE realm_name=$1 AND group_id=$2', [realm, groupId]);
    for (const userId of ids) {
      await client.query('INSERT INTO scim_group_members (realm_name,group_id,user_id) VALUES ($1,$2,$3)', [realm, groupId, userId]);
    }
    return [...new Set([...previous.rows.map(({ user_id: userId }) => userId), ...ids])];
  }

  async #syncUserGroups(client, realm, userIds) {
    if (!userIds.length) return;
    const changed = await client.query(
      `WITH desired AS (
         SELECT users.id,COALESCE((
           SELECT array_agg('/' || replace(groups.display_name, '/', '-') ORDER BY lower(groups.display_name))
           FROM scim_group_members AS memberships JOIN scim_groups AS groups
             ON groups.realm_name=memberships.realm_name AND groups.id=memberships.group_id
           WHERE memberships.realm_name=users.realm_name AND memberships.user_id=users.id
         ), '{}'::text[]) AS groups
         FROM users WHERE realm_name=$1 AND id=ANY($2::uuid[])
       )
       UPDATE users SET groups=desired.groups,security_version=security_version+1
       FROM desired
       WHERE users.realm_name=$1 AND users.id=desired.id
         AND users.groups IS DISTINCT FROM desired.groups
       RETURNING users.id::text`,
      [realm, userIds],
    );
    await revokeAccounts(client, realm, changed.rows.map(({ id }) => id));
  }

  async createGroup(realm, attributes) {
    const id = randomUUID();
    try {
      return await withTransaction(this.pool, async (client) => {
        await client.query(
          `INSERT INTO scim_groups (realm_name,id,external_id,display_name)
           VALUES ($1,$2,$3,$4)`, [realm, id, attributes.externalId ?? null, attributes.displayName],
        );
        const affected = await this.#replaceMembers(client, realm, id, attributes.members ?? []);
        await this.#syncUserGroups(client, realm, affected);
        return this.#group(realm, id, client);
      });
    } catch (error) { throw translateConstraint(error, 'Group'); }
  }

  async replaceGroup(realm, id, attributes, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM Group does not exist.');
    try {
      return await withTransaction(this.pool, async (client) => {
        const updated = await client.query(
          `UPDATE scim_groups SET external_id=$3,display_name=$4,version=version+1
           WHERE realm_name=$1 AND id=$2 AND version=$5 RETURNING id`,
          [realm, id, attributes.externalId ?? null, attributes.displayName, expectedVersion],
        );
        if (!updated.rows.length) {
          const exists = await client.query('SELECT 1 FROM scim_groups WHERE realm_name=$1 AND id=$2', [realm, id]);
          throw repositoryError(exists.rows.length ? 'VERSION_MISMATCH' : 'NOT_FOUND', `The SCIM Group ${exists.rows.length ? 'changed since it was read' : 'does not exist'}.`);
        }
        const affected = await this.#replaceMembers(client, realm, id, attributes.members ?? []);
        await this.#syncUserGroups(client, realm, affected);
        return this.#group(realm, id, client);
      });
    } catch (error) { throw translateConstraint(error, 'Group'); }
  }

  async deleteGroup(realm, id, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM Group does not exist.');
    return withTransaction(this.pool, async (client) => {
      const locked = await client.query(
        'SELECT * FROM scim_groups WHERE realm_name=$1 AND id=$2 FOR UPDATE', [realm, id],
      );
      if (!locked.rows.length) throw repositoryError('NOT_FOUND', 'The requested SCIM Group does not exist.');
      const members = await client.query(
        'SELECT user_id::text FROM scim_group_members WHERE realm_name=$1 AND group_id=$2 ORDER BY user_id', [realm, id],
      );
      const current = rowToGroup(locked.rows[0], members.rows.map(({ user_id: userId }) => userId));
      if (current.version !== expectedVersion) throw repositoryError('VERSION_MISMATCH', 'The SCIM Group changed since it was read.');
      const affected = current.members.map(({ value }) => value);
      await client.query('DELETE FROM scim_groups WHERE realm_name=$1 AND id=$2', [realm, id]);
      await this.#syncUserGroups(client, realm, affected);
      return current;
    });
  }

  async listUserGroups(realm, userId) {
    if (!isUuid(userId)) return [];
    const result = await this.pool.query(
      `SELECT groups.id::text AS value, groups.display_name AS display
       FROM scim_group_members AS members JOIN scim_groups AS groups
         ON groups.realm_name=members.realm_name AND groups.id=members.group_id
       WHERE members.realm_name=$1 AND members.user_id=$2 ORDER BY lower(groups.display_name)`,
      [realm, userId],
    );
    return result.rows.map((row) => ({ ...row, type: 'direct' }));
  }
}
