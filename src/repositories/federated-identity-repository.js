import { randomUUID } from 'node:crypto';

const providerPattern = /^[a-z][a-z0-9-]{1,63}$/;
const realmPattern = /^[a-z][a-z0-9-]{0,62}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const controlPattern = /[\u0000-\u001f\u007f]/;

function invalid(message) {
  return Object.assign(new Error(`Invalid federated identity: ${message}`), {
    code: 'AUTHME_FEDERATED_IDENTITY_INVALID',
  });
}

function normalize(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalid('input must be an object');
  if (!realmPattern.test(input.realm ?? '')) throw invalid('realm is invalid');
  if (!providerPattern.test(input.providerId ?? '')) throw invalid('providerId is invalid');
  if (typeof input.issuer !== 'string' || !input.issuer || input.issuer.length > 2048 || controlPattern.test(input.issuer)) {
    throw invalid('issuer is invalid');
  }
  if (typeof input.externalSubject !== 'string' || !input.externalSubject || input.externalSubject.length > 2048
    || controlPattern.test(input.externalSubject)) {
    throw invalid('externalSubject is invalid');
  }
  const profile = input.profile ?? {};
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) throw invalid('profile must be an object');
  const text = (value, fallback = '', max = 256) => {
    const resolved = typeof value === 'string' ? value.trim() : fallback;
    return resolved.slice(0, max);
  };
  const username = text(profile.username, input.externalSubject, 256);
  if (!username) throw invalid('profile username is empty');
  const email = text(profile.email, '', 320).toLowerCase();
  const strings = (value) => Array.isArray(value)
    ? [...new Set(value.filter((item) => typeof item === 'string').map((item) => item.trim()).filter(Boolean))].slice(0, 200)
    : [];
  return {
    realm: input.realm,
    providerId: input.providerId,
    issuer: input.issuer,
    externalSubject: input.externalSubject,
    allowCreate: input.allowCreate === true,
    profile: {
      username,
      email,
      emailVerified: profile.emailVerified === true,
      name: text(profile.name, username),
      givenName: text(profile.givenName),
      familyName: text(profile.familyName),
      roles: strings(profile.roles),
      groups: strings(profile.groups),
    },
  };
}

function publicLink(link) {
  return {
    realm: link.realm,
    providerId: link.providerId,
    issuer: link.issuer,
    externalSubject: link.externalSubject,
    userId: link.userId,
    createdAt: link.createdAt,
    updatedAt: link.updatedAt,
    lastLoginAt: link.lastLoginAt,
  };
}

function key(identity) {
  return JSON.stringify([
    identity.realm,
    identity.providerId,
    identity.issuer,
    identity.externalSubject,
  ]);
}

function userProviderKey(identity, userId) {
  return JSON.stringify([
    'user-provider',
    identity.realm,
    userId,
    identity.providerId,
    identity.issuer,
  ]);
}

function syntheticEmail(userId) {
  return `federated-${userId}@invalid.local`;
}

function syncContext(input, { run = false } = {}) {
  const identity = normalize({
    realm: input?.realm,
    providerId: input?.providerId,
    issuer: input?.issuer,
    externalSubject: input?.externalSubject ?? 'sync-context',
    profile: input?.profile ?? { username: 'sync-context' },
  });
  if (run) {
    if (!uuidPattern.test(input.syncId ?? '')) throw invalid('syncId is invalid');
    const startedAt = new Date(input.startedAt);
    if (!Number.isFinite(startedAt.getTime())) throw invalid('startedAt is invalid');
    if (!['disable', 'delete'].includes(input.deletionPolicy)) throw invalid('deletionPolicy is invalid');
    if (!Number.isSafeInteger(input.scanned) || input.scanned < 0) throw invalid('scanned is invalid');
    if (typeof input.maxDeprovisionFraction !== 'number' || input.maxDeprovisionFraction < 0.01
      || input.maxDeprovisionFraction > 1) throw invalid('maxDeprovisionFraction is invalid');
    if (!Number.isSafeInteger(input.maxDeprovisionCount) || input.maxDeprovisionCount < 1
      || input.maxDeprovisionCount > 1_000_000) throw invalid('maxDeprovisionCount is invalid');
  }
  return identity;
}

function syncLockKey(input) {
  const identity = syncContext(input);
  return JSON.stringify(['ldap-sync', identity.realm, identity.providerId, identity.issuer]);
}

function syncOwnerMatches(user, identity) {
  return user.syncDisableProviderId === identity.providerId && user.syncDisableIssuer === identity.issuer;
}

function synchronizedPatch(user, identity, { syncGroups, syncRoles }) {
  const desired = {
    username: identity.profile.username,
    name: identity.profile.name,
    givenName: identity.profile.givenName,
    familyName: identity.profile.familyName,
    ...(!user.enabled && syncOwnerMatches(user, identity) ? { enabled: true } : {}),
    ...(identity.profile.email ? {
      email: identity.profile.email,
      emailVerified: identity.profile.emailVerified,
    } : {}),
    ...(syncGroups ? { groups: identity.profile.groups } : {}),
    ...(syncRoles ? { roles: identity.profile.roles } : {}),
  };
  return Object.fromEntries(Object.entries(desired).filter(([field, value]) => {
    if (Array.isArray(value)) return JSON.stringify(user[field]) !== JSON.stringify(value);
    return user[field] !== value;
  }));
}

function initialReconciliation(existing, candidates) {
  return {
    status: 'completed',
    reason: null,
    existing,
    candidates,
    disabled: 0,
    deleted: 0,
    deletionRefused: 0,
  };
}

function reconciliationGuard(input, existing, candidates) {
  const result = initialReconciliation(existing, candidates);
  if (input.scanned === 0) return { ...result, status: 'skipped', reason: 'empty_directory_view' };
  if (candidates > input.maxDeprovisionCount
    || (existing > 0 && candidates / existing > input.maxDeprovisionFraction)) {
    return { ...result, status: 'skipped', reason: 'deprovision_threshold_exceeded' };
  }
  return result;
}

export class MemoryFederatedIdentityRepository {
  #links = new Map();
  #locks = new Map();
  #syncLocks = new Set();

  constructor(store, { disabledPasswordHash }) {
    if (!store?.findUserById || !store?.createUser) throw new TypeError('MemoryFederatedIdentityRepository requires an identity store');
    if (typeof disabledPasswordHash !== 'string') throw new TypeError('disabledPasswordHash is required');
    this.store = store;
    this.disabledPasswordHash = disabledPasswordHash;
  }

  async #locked(lockKey, operation) {
    const predecessor = this.#locks.get(lockKey) ?? Promise.resolve();
    let release;
    const current = new Promise((resolve) => { release = resolve; });
    const queued = predecessor.then(() => current);
    this.#locks.set(lockKey, queued);
    await predecessor;
    try { return await operation(); } finally {
      release();
      if (this.#locks.get(lockKey) === queued) this.#locks.delete(lockKey);
    }
  }

  async resolve(input) {
    const identity = normalize(input);
    return this.#locked(key(identity), async () => {
      const existing = this.#links.get(key(identity));
      if (existing) {
        const user = await this.store.findUserById(identity.realm, existing.userId);
        if (!user) this.#links.delete(key(identity));
        else {
          existing.lastLoginAt = new Date().toISOString();
          existing.updatedAt = existing.lastLoginAt;
          existing.profile = structuredClone(identity.profile);
          return { status: user.enabled ? 'resolved' : 'disabled', user, link: publicLink(existing) };
        }
      }
      if (!identity.allowCreate) return { status: 'not_found', user: null };
      const collision = await this.store.findUserByLogin(identity.realm, identity.profile.username)
        || (identity.profile.email ? await this.store.findUserByLogin(identity.realm, identity.profile.email) : null);
      if (collision) return { status: 'link_required', user: collision };
      const userId = randomUUID();
      let user;
      try {
        user = await this.store.createUser({
          id: userId,
          realm: identity.realm,
          username: identity.profile.username,
          email: identity.profile.email || syntheticEmail(userId),
          emailVerified: identity.profile.emailVerified,
          name: identity.profile.name,
          givenName: identity.profile.givenName,
          familyName: identity.profile.familyName,
          enabled: true,
          passwordHash: this.disabledPasswordHash,
          hasLocalPassword: false,
          roles: identity.profile.roles,
          groups: identity.profile.groups,
        });
      } catch (error) {
        if (error?.code !== 'USER_EXISTS') throw error;
        const concurrentCollision = await this.store.findUserByLogin(identity.realm, identity.profile.username)
          || (identity.profile.email ? await this.store.findUserByLogin(identity.realm, identity.profile.email) : null);
        if (!concurrentCollision) throw error;
        return { status: 'link_required', user: concurrentCollision };
      }
      const now = new Date().toISOString();
      const link = {
        ...identity, userId: user.id, createdAt: now, updatedAt: now, lastLoginAt: now,
        syncCreatedUser: false,
      };
      this.#links.set(key(identity), link);
      return { status: 'created', user, link: publicLink(link) };
    });
  }

  async acquireSyncLock(input) {
    const lockKey = syncLockKey(input);
    if (this.#syncLocks.has(lockKey)) return null;
    this.#syncLocks.add(lockKey);
    let released = false;
    const release = async () => {
      if (released) return;
      released = true;
      this.#syncLocks.delete(lockKey);
    };
    release.startedAt = new Date().toISOString();
    return release;
  }

  async syncEntry(input) {
    const identity = normalize({ ...input, allowCreate: true });
    if (!uuidPattern.test(input.syncId ?? '')) throw invalid('syncId is invalid');
    return this.#locked(key(identity), async () => {
      const linkKey = key(identity);
      const existing = this.#links.get(linkKey);
      if (existing) {
        const user = await this.store.findUserById(identity.realm, existing.userId);
        if (!user) {
          this.#links.delete(linkKey);
        } else {
          const patch = synchronizedPatch(user, identity, input);
          let status = Object.keys(patch).length ? 'updated' : 'unchanged';
          try {
            if (Object.keys(patch).length) {
              await this.store.updateFederatedUser(identity.realm, user.id, patch);
              if (patch.enabled && user.enabled === false) await this.store.bumpSecurityVersion(identity.realm, user.id);
            }
          } catch (error) {
            if (error?.code !== 'USER_EXISTS') throw error;
            status = 'conflict';
          }
          existing.profile = structuredClone(identity.profile);
          existing.lastSyncId = input.syncId;
          existing.lastSyncedAt = new Date().toISOString();
          existing.updatedAt = existing.lastSyncedAt;
          return { status, userId: user.id };
        }
      }

      const collision = await this.store.findUserByLogin(identity.realm, identity.profile.username)
        || (identity.profile.email ? await this.store.findUserByLogin(identity.realm, identity.profile.email) : null);
      if (collision) return { status: 'conflict', userId: collision.id };
      const userId = randomUUID();
      let user;
      try {
        user = await this.store.createUser({
          id: userId,
          realm: identity.realm,
          username: identity.profile.username,
          email: identity.profile.email || syntheticEmail(userId),
          emailVerified: identity.profile.emailVerified,
          name: identity.profile.name,
          givenName: identity.profile.givenName,
          familyName: identity.profile.familyName,
          enabled: true,
          passwordHash: this.disabledPasswordHash,
          hasLocalPassword: false,
          roles: input.syncRoles ? identity.profile.roles : [],
          groups: input.syncGroups ? identity.profile.groups : [],
        });
      } catch (error) {
        if (error?.code !== 'USER_EXISTS') throw error;
        return { status: 'conflict' };
      }
      const now = new Date().toISOString();
      this.#links.set(linkKey, {
        ...identity,
        userId: user.id,
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null,
        lastSyncId: input.syncId,
        lastSyncedAt: now,
        syncCreatedUser: true,
      });
      return { status: 'created', userId: user.id };
    });
  }

  async reconcileMissing(input) {
    const context = syncContext(input, { run: true });
    const startedAt = new Date(input.startedAt).getTime();
    const existing = [...this.#links.entries()].filter(([, candidate]) => candidate.realm === context.realm
      && candidate.providerId === context.providerId && candidate.issuer === context.issuer
      && new Date(candidate.createdAt).getTime() <= startedAt);
    const candidates = existing.filter(([, candidate]) => candidate.lastSyncId !== input.syncId);
    const result = reconciliationGuard(input, existing.length, candidates.length);
    if (result.status === 'skipped') return result;
    for (const [candidateKey] of candidates) {
      await this.#locked(candidateKey, async () => {
        const link = this.#links.get(candidateKey);
        if (!link || link.lastSyncId === input.syncId || new Date(link.createdAt).getTime() > startedAt) return;
        const user = await this.store.findUserById(context.realm, link.userId);
        if (!user) {
          this.#links.delete(candidateKey);
          return;
        }
        const otherLink = [...this.#links.values()].some((related) => related.realm === context.realm
          && related.userId === user.id && related !== link);
        const webauthnCredentials = typeof this.store.listWebAuthnCredentials === 'function'
          ? await this.store.listWebAuthnCredentials(context.realm, user.id) : [null];
        const localCredential = user.hasLocalPassword || user.totpConfirmed || Boolean(user.totpSecret)
          || Boolean(user.pendingTotpSecret) || (user.recoveryCodeHashes?.length ?? 0) > 0
          || webauthnCredentials.length > 0;
        const adminGrant = typeof this.store.findAdminGrant === 'function'
          ? await this.store.findAdminGrant(context.realm, user.id) : true;
        const safeToDelete = input.deletionPolicy === 'delete' && link.syncCreatedUser === true
          && !otherLink && !localCredential && !adminGrant
          && (user.enabled || syncOwnerMatches(user, context));
        if (safeToDelete) {
          await this.store.deleteUser(context.realm, user.id);
          for (const [linkKey, related] of this.#links) {
            if (related.realm === context.realm && related.userId === user.id) this.#links.delete(linkKey);
          }
          result.deleted += 1;
        } else {
          if (input.deletionPolicy === 'delete') result.deletionRefused += 1;
          if (await this.store.disableUserForLdapSync(context.realm, user.id, {
            providerId: context.providerId,
            issuer: context.issuer,
          })) result.disabled += 1;
        }
      });
    }
    return result;
  }

  async link(input) {
    const identity = normalize({ ...input, profile: input.profile ?? { username: 'linked' } });
    if (!uuidPattern.test(input.userId ?? '')) throw invalid('userId is invalid');
    return this.#locked(userProviderKey(identity, input.userId), () => this.#locked(key(identity), async () => {
      const user = await this.store.findUserById(identity.realm, input.userId);
      if (!user) return { status: 'not_found' };
      const existing = this.#links.get(key(identity));
      if (existing) return { status: existing.userId === user.id ? 'linked' : 'conflict', link: publicLink(existing) };
      const userProviderLink = [...this.#links.values()].find((candidate) => candidate.realm === identity.realm
        && candidate.userId === user.id && candidate.providerId === identity.providerId && candidate.issuer === identity.issuer);
      if (userProviderLink) return { status: 'conflict', link: publicLink(userProviderLink) };
      const now = new Date().toISOString();
      const link = {
        ...identity, userId: user.id, createdAt: now, updatedAt: now, lastLoginAt: null,
        syncCreatedUser: false,
      };
      this.#links.set(key(identity), link);
      return { status: 'linked', link: publicLink(link) };
    }));
  }

  async list(realm, userId) {
    return [...this.#links.values()]
      .filter((link) => link.realm === realm && link.userId === userId)
      .map(publicLink);
  }

  async unlink({ realm, userId, providerId, issuer }) {
    for (const [linkKey, link] of this.#links) {
      if (link.realm === realm && link.userId === userId && link.providerId === providerId && link.issuer === issuer) {
        this.#links.delete(linkKey);
        return publicLink(link);
      }
    }
    return null;
  }
}

function rowLink(row) {
  if (!row) return null;
  return publicLink({
    realm: row.realm_name,
    providerId: row.provider_id,
    issuer: row.issuer,
    externalSubject: row.external_subject,
    userId: row.user_id,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
    lastLoginAt: row.last_login_at?.toISOString?.() ?? row.last_login_at,
  });
}

async function updatePostgresSyncUser(client, user, patch) {
  const columns = {
    username: 'username',
    email: 'email',
    emailVerified: 'email_verified',
    name: 'display_name',
    givenName: 'given_name',
    familyName: 'family_name',
    enabled: 'enabled',
    roles: 'roles',
    groups: 'groups',
  };
  const entries = Object.entries(patch).filter(([field]) => field in columns);
  if (!entries.length) return;
  const values = [user.realm, user.id];
  const assignments = entries.map(([field, value]) => {
    values.push(value);
    return `${columns[field]}=$${values.length}`;
  });
  if (patch.enabled && user.enabled === false) {
    assignments.push(
      'security_version=security_version+1',
      'ldap_sync_disable_provider_id=NULL',
      'ldap_sync_disable_issuer=NULL',
    );
  }
  await client.query(
    `UPDATE users SET ${assignments.join(', ')},updated_at=now() WHERE realm_name=$1 AND id=$2`,
    values,
  );
}

export class PostgresFederatedIdentityRepository {
  constructor(pool, { disabledPasswordHash }) {
    if (!pool?.query || !pool?.connect) throw new TypeError('PostgresFederatedIdentityRepository requires a PostgreSQL pool');
    if (typeof disabledPasswordHash !== 'string') throw new TypeError('disabledPasswordHash is required');
    this.pool = pool;
    this.disabledPasswordHash = disabledPasswordHash;
  }

  async resolve(input) {
    const identity = normalize(input);
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [key(identity)]);
      const existing = await client.query(
        `UPDATE federated_identities AS links SET profile=$5,last_login_at=now()
         FROM users WHERE links.realm_name=$1 AND links.provider_id=$2 AND links.issuer=$3
           AND links.external_subject=$4 AND users.realm_name=links.realm_name AND users.id=links.user_id
         RETURNING links.*, users.enabled`,
        [identity.realm, identity.providerId, identity.issuer, identity.externalSubject, identity.profile],
      );
      if (existing.rows.length) {
        const user = await this.#user(client, identity.realm, existing.rows[0].user_id);
        await client.query('COMMIT');
        return { status: existing.rows[0].enabled ? 'resolved' : 'disabled', user, link: rowLink(existing.rows[0]) };
      }
      if (!identity.allowCreate) {
        await client.query('COMMIT');
        return { status: 'not_found', user: null };
      }
      const collision = await client.query(
        `SELECT id FROM users WHERE realm_name=$1 AND (
           lower(username) IN (lower($2),lower($3)) OR lower(email) IN (lower($2),lower($3))
         ) LIMIT 1`, [identity.realm, identity.profile.username, identity.profile.email],
      );
      if (collision.rows.length) {
        const user = await this.#user(client, identity.realm, collision.rows[0].id);
        await client.query('COMMIT');
        return { status: 'link_required', user };
      }
      const userId = randomUUID();
      const email = identity.profile.email || syntheticEmail(userId);
      await client.query(
        `INSERT INTO users
         (realm_name,id,username,email,email_verified,display_name,given_name,family_name,enabled,
          password_hash,has_local_password,roles,groups,client_roles,attributes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,false,$10,$11,'{}',$12)`,
        [identity.realm, userId, identity.profile.username, email, identity.profile.emailVerified,
          identity.profile.name, identity.profile.givenName, identity.profile.familyName,
          this.disabledPasswordHash, identity.profile.roles, identity.profile.groups,
          { federation: { providerId: identity.providerId, issuer: identity.issuer } }],
      );
      const inserted = await client.query(
        `INSERT INTO federated_identities
         (realm_name,provider_id,issuer,external_subject,user_id,profile,last_login_at)
         VALUES ($1,$2,$3,$4,$5,$6,now()) RETURNING *`,
        [identity.realm, identity.providerId, identity.issuer, identity.externalSubject, userId, identity.profile],
      );
      const user = await this.#user(client, identity.realm, userId);
      await client.query('COMMIT');
      return { status: 'created', user, link: rowLink(inserted.rows[0]) };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      if (error?.code === '23505') return { status: 'link_required', user: null };
      throw error;
    } finally { client.release(); }
  }

  async acquireSyncLock(input) {
    const lockKey = syncLockKey(input);
    const client = await this.pool.connect();
    let startedAt;
    try {
      const result = await client.query(
        'SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS locked,CURRENT_TIMESTAMP AS started_at',
        [lockKey],
      );
      if (!result.rows[0]?.locked) {
        client.release();
        return null;
      }
      startedAt = result.rows[0].started_at?.toISOString?.() ?? result.rows[0].started_at;
    } catch (error) {
      client.release();
      throw error;
    }
    let released = false;
    const release = async () => {
      if (released) return;
      released = true;
      try {
        await client.query('SELECT pg_advisory_unlock(hashtextextended($1,0))', [lockKey]);
      } finally {
        client.release();
      }
    };
    release.startedAt = startedAt;
    return release;
  }

  async syncEntry(input) {
    const identity = normalize({ ...input, allowCreate: true });
    if (!uuidPattern.test(input.syncId ?? '')) throw invalid('syncId is invalid');
    const client = await this.pool.connect();
    let existingUserId = null;
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [key(identity)]);
      const existing = await client.query(
        `SELECT * FROM federated_identities
         WHERE realm_name=$1 AND provider_id=$2 AND issuer=$3 AND external_subject=$4
         FOR UPDATE`,
        [identity.realm, identity.providerId, identity.issuer, identity.externalSubject],
      );
      if (existing.rows.length) {
        existingUserId = existing.rows[0].user_id;
        const user = await this.#user(client, identity.realm, existingUserId, { forUpdate: true });
        if (!user) throw new Error('LDAP sync identity references a missing user');
        const patch = synchronizedPatch(user, identity, input);
        await updatePostgresSyncUser(client, user, patch);
        await client.query(
          `UPDATE federated_identities SET profile=$5,last_sync_id=$6,last_synced_at=now()
           WHERE realm_name=$1 AND provider_id=$2 AND issuer=$3 AND external_subject=$4`,
          [identity.realm, identity.providerId, identity.issuer, identity.externalSubject, identity.profile, input.syncId],
        );
        await client.query('COMMIT');
        return { status: Object.keys(patch).length ? 'updated' : 'unchanged', userId: user.id };
      }

      const collision = await client.query(
        `SELECT id FROM users WHERE realm_name=$1 AND (
           lower(username) IN (lower($2),lower($3)) OR lower(email) IN (lower($2),lower($3))
         ) LIMIT 1`,
        [identity.realm, identity.profile.username, identity.profile.email],
      );
      if (collision.rows.length) {
        await client.query('COMMIT');
        return { status: 'conflict', userId: collision.rows[0].id };
      }
      const userId = randomUUID();
      const email = identity.profile.email || syntheticEmail(userId);
      await client.query(
        `INSERT INTO users
         (realm_name,id,username,email,email_verified,display_name,given_name,family_name,enabled,
          password_hash,has_local_password,roles,groups,client_roles,attributes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,false,$10,$11,'{}',$12)`,
        [identity.realm, userId, identity.profile.username, email, identity.profile.emailVerified,
          identity.profile.name, identity.profile.givenName, identity.profile.familyName,
          this.disabledPasswordHash,
          input.syncRoles ? identity.profile.roles : [],
          input.syncGroups ? identity.profile.groups : [],
          { federation: { providerId: identity.providerId, issuer: identity.issuer } }],
      );
      await client.query(
         `INSERT INTO federated_identities
         (realm_name,provider_id,issuer,external_subject,user_id,profile,last_sync_id,last_synced_at,sync_created_user)
         VALUES ($1,$2,$3,$4,$5,$6,$7,now(),true)`,
        [identity.realm, identity.providerId, identity.issuer, identity.externalSubject,
          userId, identity.profile, input.syncId],
      );
      await client.query('COMMIT');
      return { status: 'created', userId };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      if (error?.code === '23505' || error?.code === 'USER_EXISTS') {
        if (existingUserId) {
          await this.pool.query(
            `UPDATE federated_identities SET profile=$5,last_sync_id=$6,last_synced_at=now()
             WHERE realm_name=$1 AND provider_id=$2 AND issuer=$3 AND external_subject=$4 AND user_id=$7`,
            [identity.realm, identity.providerId, identity.issuer, identity.externalSubject,
              identity.profile, input.syncId, existingUserId],
          );
        }
        return { status: 'conflict', userId: existingUserId };
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async reconcileMissing(input) {
    const context = syncContext(input, { run: true });
    const batchSize = Number(input.batchSize ?? 200);
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) {
      throw invalid('batchSize is invalid');
    }
    const counts = await this.pool.query(
      `SELECT count(*)::integer AS existing,
              (count(*) FILTER (WHERE last_sync_id IS DISTINCT FROM $4::uuid))::integer AS candidates
       FROM federated_identities
       WHERE realm_name=$1 AND provider_id=$2 AND issuer=$3 AND created_at <= $5`,
      [context.realm, context.providerId, context.issuer, input.syncId, input.startedAt],
    );
    const result = reconciliationGuard(
      input,
      Number(counts.rows[0].existing),
      Number(counts.rows[0].candidates),
    );
    if (result.status === 'skipped') return result;
    let cursor = '';
    while (true) {
      const candidates = await this.pool.query(
        `SELECT external_subject FROM federated_identities
         WHERE realm_name=$1 AND provider_id=$2 AND issuer=$3
           AND last_sync_id IS DISTINCT FROM $4::uuid AND created_at <= $5
           AND external_subject > $6
         ORDER BY external_subject LIMIT $7`,
        [context.realm, context.providerId, context.issuer, input.syncId, input.startedAt, cursor, batchSize],
      );
      if (!candidates.rows.length) break;
      for (const candidate of candidates.rows) {
        cursor = candidate.external_subject;
        const client = await this.pool.connect();
        try {
          await client.query('BEGIN');
          const link = await client.query(
            `SELECT user_id,sync_created_user FROM federated_identities
             WHERE realm_name=$1 AND provider_id=$2 AND issuer=$3 AND external_subject=$4
               AND last_sync_id IS DISTINCT FROM $5::uuid AND created_at <= $6
             FOR UPDATE`,
            [context.realm, context.providerId, context.issuer, candidate.external_subject,
              input.syncId, input.startedAt],
          );
          if (!link.rows.length) {
            await client.query('COMMIT');
            continue;
          }
          const userId = link.rows[0].user_id;
          const user = await this.#user(client, context.realm, userId, { forUpdate: true });
          if (!user) {
            await client.query('COMMIT');
            continue;
          }
          let safeToDelete = false;
          if (input.deletionPolicy === 'delete' && link.rows[0].sync_created_user
            && (user.enabled || syncOwnerMatches(user, context))
            && !user.hasLocalPassword && !user.totpConfirmed && !user.totpSecret
            && !user.pendingTotpSecret && (user.recoveryCodeHashes?.length ?? 0) === 0) {
            const dependencies = await client.query(
              `SELECT
                 (SELECT count(*) FROM federated_identities
                  WHERE realm_name=$1 AND user_id=$2)::integer AS identity_count,
                 EXISTS (SELECT 1 FROM webauthn_credentials
                  WHERE realm_name=$1 AND user_id=$2) AS has_webauthn,
                 EXISTS (SELECT 1 FROM admin_grants
                  WHERE realm_name=$1 AND user_id=$2) AS has_admin_grant`,
              [context.realm, userId],
            );
            safeToDelete = Number(dependencies.rows[0].identity_count) === 1
              && !dependencies.rows[0].has_webauthn && !dependencies.rows[0].has_admin_grant;
          }
          if (safeToDelete) {
            const deleted = await client.query(
              'DELETE FROM users WHERE realm_name=$1 AND id=$2 RETURNING id',
              [context.realm, userId],
            );
            result.deleted += deleted.rowCount;
          } else {
            if (input.deletionPolicy === 'delete') result.deletionRefused += 1;
            const disabled = await client.query(
              `UPDATE users SET enabled=false,ldap_sync_disable_provider_id=$3,
                 ldap_sync_disable_issuer=$4,security_version=security_version+1,updated_at=now()
               WHERE realm_name=$1 AND id=$2 AND enabled RETURNING id`,
              [context.realm, userId, context.providerId, context.issuer],
            );
            result.disabled += disabled.rowCount;
          }
          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK').catch(() => {});
          throw error;
        } finally {
          client.release();
        }
      }
    }
    return result;
  }

  async #user(client, realm, id, { forUpdate = false } = {}) {
    const result = await client.query(
      `SELECT * FROM users WHERE realm_name=$1 AND id=$2${forUpdate ? ' FOR UPDATE' : ''}`,
      [realm, id],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id, realm: row.realm_name, username: row.username, email: row.email,
      emailVerified: row.email_verified, name: row.display_name, givenName: row.given_name,
      familyName: row.family_name, enabled: row.enabled, securityVersion: Number(row.security_version),
      passwordHash: row.password_hash, hasLocalPassword: row.has_local_password,
      syncDisableProviderId: row.ldap_sync_disable_provider_id,
      syncDisableIssuer: row.ldap_sync_disable_issuer,
      roles: row.roles, groups: row.groups, clientRoles: row.client_roles,
      totpSecret: row.totp_secret, totpConfirmed: row.totp_confirmed,
      pendingTotpSecret: row.pending_totp_secret,
      pendingTotpCreatedAt: row.pending_totp_created_at,
      recoveryCodeHashes: row.recovery_code_hashes, lastTotpStep: row.last_totp_step == null ? null : Number(row.last_totp_step),
      failedAttempts: row.failed_attempts, lockedUntil: row.locked_until, createdAt: row.created_at,
      updatedAt: row.updated_at, lastLoginAt: row.last_login_at,
    };
  }

  async link(input) {
    const identity = normalize({ ...input, profile: input.profile ?? { username: 'linked' } });
    if (!uuidPattern.test(input.userId ?? '')) throw invalid('userId is invalid');
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [
        userProviderKey(identity, input.userId),
      ]);
      const user = await client.query(
        'SELECT 1 FROM users WHERE realm_name=$1 AND id=$2 FOR KEY SHARE',
        [identity.realm, input.userId],
      );
      if (!user.rows.length) {
        await client.query('COMMIT');
        return { status: 'not_found' };
      }
      const result = await client.query(
        `INSERT INTO federated_identities AS existing
         (realm_name,provider_id,issuer,external_subject,user_id,profile)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (realm_name,provider_id,issuer,external_subject) DO UPDATE
           SET profile=existing.profile WHERE existing.user_id=EXCLUDED.user_id
         RETURNING existing.*`,
        [identity.realm, identity.providerId, identity.issuer, identity.externalSubject, input.userId, identity.profile],
      );
      await client.query('COMMIT');
      return result.rows.length ? { status: 'linked', link: rowLink(result.rows[0]) } : { status: 'conflict' };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      if (error?.code === '23505') return { status: 'conflict' };
      throw error;
    } finally { client.release(); }
  }

  async list(realm, userId) {
    const result = await this.pool.query(
      `SELECT * FROM federated_identities WHERE realm_name=$1 AND user_id=$2
       ORDER BY provider_id,issuer`, [realm, userId],
    );
    return result.rows.map(rowLink);
  }

  async unlink({ realm, userId, providerId, issuer }) {
    const result = await this.pool.query(
      `DELETE FROM federated_identities WHERE realm_name=$1 AND user_id=$2
       AND provider_id=$3 AND issuer=$4 RETURNING *`, [realm, userId, providerId, issuer],
    );
    return rowLink(result.rows[0]);
  }
}
