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

export class MemoryFederatedIdentityRepository {
  #links = new Map();
  #locks = new Map();

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
      };
      this.#links.set(key(identity), link);
      return { status: 'created', user, link: publicLink(link) };
    });
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
      const link = { ...identity, userId: user.id, createdAt: now, updatedAt: now, lastLoginAt: null };
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
          password_hash,roles,groups,client_roles,attributes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,$10,$11,'{}',$12)`,
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

  async #user(client, realm, id) {
    const result = await client.query('SELECT * FROM users WHERE realm_name=$1 AND id=$2', [realm, id]);
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id, realm: row.realm_name, username: row.username, email: row.email,
      emailVerified: row.email_verified, name: row.display_name, givenName: row.given_name,
      familyName: row.family_name, enabled: row.enabled, securityVersion: Number(row.security_version),
      passwordHash: row.password_hash, roles: row.roles, groups: row.groups, clientRoles: row.client_roles,
      totpSecret: row.totp_secret, totpConfirmed: row.totp_confirmed,
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
