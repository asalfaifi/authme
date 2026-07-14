import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { normalizeAdminPermissions } from '../security/admin-permissions.js';

function nowIso() {
  return new Date().toISOString();
}

function normalizeUser(input) {
  return {
    id: input.id ?? randomUUID(),
    realm: input.realm,
    username: input.username.trim(),
    email: input.email.trim().toLowerCase(),
    emailVerified: Boolean(input.emailVerified),
    name: input.name?.trim() || input.username.trim(),
    givenName: input.givenName?.trim() || '',
    familyName: input.familyName?.trim() || '',
    enabled: input.enabled !== false,
    securityVersion: Number(input.securityVersion ?? 0),
    passwordHash: input.passwordHash,
    roles: [...new Set(input.roles ?? [])],
    groups: [...new Set(input.groups ?? [])],
    clientRoles: input.clientRoles ?? {},
    totpSecret: input.totpSecret ?? null,
    totpConfirmed: Boolean(input.totpConfirmed),
    pendingTotpSecret: input.pendingTotpSecret ?? null,
    pendingTotpCreatedAt: input.pendingTotpCreatedAt ?? null,
    recoveryCodeHashes: input.recoveryCodeHashes ?? [],
    lastTotpStep: input.lastTotpStep ?? null,
    failedAttempts: Number(input.failedAttempts ?? 0),
    lockedUntil: input.lockedUntil ?? null,
    createdAt: input.createdAt ?? nowIso(),
    updatedAt: input.updatedAt ?? nowIso(),
    lastLoginAt: input.lastLoginAt ?? null,
  };
}

function normalizeWebAuthnCredential(input) {
  const counter = Number(input.counter ?? 0);
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > 0xffff_ffff) {
    throw new TypeError('WebAuthn credential counter is invalid');
  }
  return {
    realm: input.realm,
    userId: input.userId,
    id: input.id,
    userHandle: input.userHandle,
    publicKey: new Uint8Array(input.publicKey),
    counter,
    transports: [...new Set(input.transports ?? [])],
    deviceType: input.deviceType,
    backedUp: Boolean(input.backedUp),
    aaguid: input.aaguid,
    name: String(input.name ?? 'Passkey').trim() || 'Passkey',
    createdAt: input.createdAt ?? nowIso(),
    updatedAt: input.updatedAt ?? nowIso(),
    lastUsedAt: input.lastUsedAt ?? null,
  };
}

function normalizeAdminGrant(input) {
  const version = Number(input.version ?? 1);
  if (!Number.isSafeInteger(version) || version < 1) throw new TypeError('Administrator grant version is invalid');
  return {
    realm: input.realm,
    userId: input.userId,
    permissions: [...normalizeAdminPermissions(input.permissions)],
    enabled: input.enabled !== false,
    version,
    createdAt: input.createdAt ?? nowIso(),
    updatedAt: input.updatedAt ?? nowIso(),
  };
}

function normalizeAdminSession(input) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(input.idDigest ?? '')) throw new TypeError('Administrator session digest is invalid');
  const grantVersion = Number(input.grantVersion);
  const securityVersion = Number(input.securityVersion);
  if (!Number.isSafeInteger(grantVersion) || grantVersion < 1
    || !Number.isSafeInteger(securityVersion) || securityVersion < 0) {
    throw new TypeError('Administrator session version snapshot is invalid');
  }
  const expiresAt = new Date(input.expiresAt);
  const idleExpiresAt = new Date(input.idleExpiresAt);
  if (!Number.isFinite(expiresAt.getTime()) || !Number.isFinite(idleExpiresAt.getTime())) {
    throw new TypeError('Administrator session expiry is invalid');
  }
  return {
    idDigest: input.idDigest,
    realm: input.realm,
    userId: input.userId,
    grantVersion,
    securityVersion,
    createdAt: input.createdAt ?? nowIso(),
    lastSeenAt: input.lastSeenAt ?? nowIso(),
    idleExpiresAt: idleExpiresAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
}

function rowToWebAuthnCredential(row) {
  if (!row) return null;
  return normalizeWebAuthnCredential({
    realm: row.realm_name,
    userId: row.user_id,
    id: row.credential_id,
    userHandle: row.user_handle,
    publicKey: row.public_key,
    counter: row.counter,
    transports: row.transports,
    deviceType: row.credential_device_type,
    backedUp: row.backed_up,
    aaguid: row.aaguid,
    name: row.display_name,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
    lastUsedAt: row.last_used_at?.toISOString?.() ?? row.last_used_at,
  });
}

function rowToWebAuthnChallenge(row) {
  if (!row) return null;
  return {
    id: row.id,
    realm: row.realm_name,
    purpose: row.purpose,
    userId: row.user_id ?? null,
    interactionUid: row.interaction_uid ?? null,
    userHandle: row.user_handle ?? null,
    challenge: row.challenge,
    expiresAt: row.expires_at?.toISOString?.() ?? row.expires_at,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
  };
}

export function publicUser(user) {
  if (!user) return null;
  const { passwordHash, totpSecret, pendingTotpSecret, pendingTotpCreatedAt, recoveryCodeHashes, lastTotpStep, securityVersion, ...safe } = user;
  return { ...safe, mfaEnabled: Boolean(user.totpConfirmed), recoveryCodesRemaining: recoveryCodeHashes?.length ?? 0 };
}

export class MemoryIdentityStore {
  #users = new Map();
  #adminGrants = new Map();
  #adminSessions = new Map();
  #audit = [];
  #webauthnCredentials = new Map();
  #webauthnChallenges = new Map();

  async ready() {
    return true;
  }

  async close() {}

  async createUser(input) {
    const user = normalizeUser(input);
    if (this.#users.has(`${user.realm}:${user.id}`)) {
      throw Object.assign(new Error('A user with that id already exists'), { code: 'USER_EXISTS' });
    }
    const duplicate = [...this.#users.values()].find(
      (item) => item.realm === user.realm
        && [item.username.toLowerCase(), item.email].some(
          (login) => login === user.username.toLowerCase() || login === user.email,
        ),
    );
    if (duplicate) throw Object.assign(new Error('A user with that username or email already exists'), { code: 'USER_EXISTS' });
    this.#users.set(`${user.realm}:${user.id}`, structuredClone(user));
    return structuredClone(user);
  }

  async findUserById(realm, id) {
    const user = this.#users.get(`${realm}:${id}`);
    return user ? structuredClone(user) : null;
  }

  async findUserByLogin(realm, login) {
    const normalized = String(login).trim().toLowerCase();
    const user = [...this.#users.values()].find(
      (item) => item.realm === realm && (item.username.toLowerCase() === normalized || item.email === normalized),
    );
    return user ? structuredClone(user) : null;
  }

  async listUsers(realm, { limit = 100, offset = 0 } = {}) {
    return [...this.#users.values()]
      .filter((item) => item.realm === realm)
      .sort((a, b) => a.username.localeCompare(b.username))
      .slice(offset, offset + limit)
      .map((item) => structuredClone(item));
  }

  async updateUser(realm, id, patch) {
    const key = `${realm}:${id}`;
    const current = this.#users.get(key);
    if (!current) return null;
    const allowed = ['email', 'emailVerified', 'name', 'givenName', 'familyName', 'enabled', 'passwordHash', 'roles', 'groups', 'clientRoles'];
    const next = structuredClone(current);
    if ('email' in patch) {
      patch = { ...patch, email: String(patch.email).trim().toLowerCase() };
      const duplicate = [...this.#users.values()].find(
        (item) => item.realm === realm && item.id !== id
          && (item.email === patch.email || item.username.toLowerCase() === patch.email),
      );
      if (duplicate) throw Object.assign(new Error('A user with that email already exists'), { code: 'USER_EXISTS' });
    }
    for (const field of allowed) if (field in patch) next[field] = structuredClone(patch[field]);
    next.updatedAt = nowIso();
    this.#users.set(key, next);
    return structuredClone(next);
  }

  async deleteUser(realm, id) {
    const key = `${realm}:${id}`;
    const user = this.#users.get(key);
    if (!user) return null;
    this.#users.delete(key);
    this.#adminGrants.delete(key);
    for (const [digest, session] of this.#adminSessions) {
      if (session.realm === realm && session.userId === id) this.#adminSessions.delete(digest);
    }
    for (const [credentialKey, credential] of this.#webauthnCredentials) {
      if (credential.realm === realm && credential.userId === id) this.#webauthnCredentials.delete(credentialKey);
    }
    for (const [challengeKey, challenge] of this.#webauthnChallenges) {
      if (challenge.realm === realm && challenge.userId === id) this.#webauthnChallenges.delete(challengeKey);
    }
    return structuredClone(user);
  }

  async restoreUser(user) {
    const restored = normalizeUser(user);
    this.#users.set(`${restored.realm}:${restored.id}`, structuredClone(restored));
    return structuredClone(restored);
  }

  async findAdminGrant(realm, userId) {
    const grant = this.#adminGrants.get(`${realm}:${userId}`);
    return grant ? structuredClone(grant) : null;
  }

  async upsertAdminGrant(realm, userId, permissions, { enabled = true } = {}) {
    if (!this.#users.has(`${realm}:${userId}`)) return null;
    const key = `${realm}:${userId}`;
    const current = this.#adminGrants.get(key);
    const grant = normalizeAdminGrant({
      realm,
      userId,
      permissions,
      enabled,
      version: current ? current.version + 1 : 1,
      createdAt: current?.createdAt,
    });
    this.#adminGrants.set(key, structuredClone(grant));
    return structuredClone(grant);
  }

  async revokeAdminGrant(realm, userId) {
    const current = this.#adminGrants.get(`${realm}:${userId}`);
    if (!current) return null;
    return this.upsertAdminGrant(realm, userId, current.permissions, { enabled: false });
  }

  async restoreAdminGrant(grant) {
    const restored = normalizeAdminGrant(grant);
    this.#adminGrants.set(`${restored.realm}:${restored.userId}`, structuredClone(restored));
    return structuredClone(restored);
  }

  async createAdminSession(input) {
    const session = normalizeAdminSession(input);
    if (!this.#users.has(`${session.realm}:${session.userId}`) || this.#adminSessions.has(session.idDigest)) return null;
    this.#adminSessions.set(session.idDigest, structuredClone(session));
    return structuredClone(session);
  }

  async findAdminSession(idDigest) {
    const session = this.#adminSessions.get(idDigest);
    return session ? structuredClone(session) : null;
  }

  async touchAdminSession(idDigest, idleExpiresAt) {
    const session = this.#adminSessions.get(idDigest);
    if (!session) return null;
    session.lastSeenAt = nowIso();
    session.idleExpiresAt = new Date(idleExpiresAt).toISOString();
    return structuredClone(session);
  }

  async deleteAdminSession(idDigest) {
    return this.#adminSessions.delete(idDigest);
  }

  async cleanupExpiredAdminSessions(limit = 1000) {
    let deleted = 0;
    const now = Date.now();
    for (const [digest, session] of this.#adminSessions) {
      if (deleted >= limit) break;
      if (new Date(session.expiresAt).getTime() <= now || new Date(session.idleExpiresAt).getTime() <= now) {
        this.#adminSessions.delete(digest);
        deleted += 1;
      }
    }
    return deleted;
  }

  async rehashPasswordIfCurrent(realm, id, expectedHash, passwordHash) {
    const key = `${realm}:${id}`;
    const user = this.#users.get(key);
    if (!user || user.passwordHash !== expectedHash) return false;
    user.passwordHash = passwordHash;
    user.updatedAt = nowIso();
    return true;
  }

  async recordLoginFailure(realm, id) {
    const key = `${realm}:${id}`;
    const user = this.#users.get(key);
    if (!user) return;
    if (user.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now()) return;
    if (user.lockedUntil) {
      user.failedAttempts = 0;
      user.lockedUntil = null;
    }
    user.failedAttempts += 1;
    if (user.failedAttempts >= 5) user.lockedUntil = new Date(Date.now() + 15 * 60_000).toISOString();
    user.updatedAt = nowIso();
  }

  async recordLoginSuccess(realm, id) {
    const user = this.#users.get(`${realm}:${id}`);
    if (!user) return;
    user.failedAttempts = 0;
    user.lockedUntil = null;
    user.lastLoginAt = nowIso();
    user.updatedAt = nowIso();
  }

  async unlockUser(realm, id) {
    const user = this.#users.get(`${realm}:${id}`);
    if (!user) return null;
    user.failedAttempts = 0;
    user.lockedUntil = null;
    user.updatedAt = nowIso();
    return structuredClone(user);
  }

  async bumpSecurityVersion(realm, id) {
    const user = this.#users.get(`${realm}:${id}`);
    if (!user) return null;
    user.securityVersion += 1;
    user.updatedAt = nowIso();
    return structuredClone(user);
  }

  async beginTotpEnrollment(realm, id, pendingSecret) {
    const user = this.#users.get(`${realm}:${id}`);
    if (!user) return null;
    user.pendingTotpSecret = pendingSecret;
    user.pendingTotpCreatedAt = nowIso();
    user.updatedAt = nowIso();
    return structuredClone(user);
  }

  async confirmTotpEnrollment(realm, id, { pendingSecret, activeSecret, step, recoveryCodeHashes }) {
    const user = this.#users.get(`${realm}:${id}`);
    const pendingFresh = user?.pendingTotpCreatedAt && Date.now() - new Date(user.pendingTotpCreatedAt).getTime() <= 10 * 60_000;
    if (!user || !pendingFresh || user.pendingTotpSecret !== pendingSecret || typeof activeSecret !== 'string' || !Number.isSafeInteger(step)) return false;
    user.totpSecret = activeSecret;
    user.totpConfirmed = true;
    user.pendingTotpSecret = null;
    user.pendingTotpCreatedAt = null;
    user.recoveryCodeHashes = [...recoveryCodeHashes];
    user.lastTotpStep = step;
    user.updatedAt = nowIso();
    return true;
  }

  async configureTotp(realm, id, { secret, confirmed, recoveryCodeHashes }) {
    const user = this.#users.get(`${realm}:${id}`);
    if (!user) return null;
    user.totpSecret = secret;
    user.totpConfirmed = Boolean(confirmed);
    if (!confirmed) {
      user.lastTotpStep = null;
      user.pendingTotpSecret = null;
      user.pendingTotpCreatedAt = null;
    }
    if (recoveryCodeHashes) user.recoveryCodeHashes = [...recoveryCodeHashes];
    user.updatedAt = nowIso();
    return structuredClone(user);
  }

  async consumeTotpStep(realm, id, step) {
    const user = this.#users.get(`${realm}:${id}`);
    if (!user || !Number.isSafeInteger(step) || (user.lastTotpStep !== null && user.lastTotpStep >= step)) return false;
    user.lastTotpStep = step;
    user.updatedAt = nowIso();
    return true;
  }

  async consumeRecoveryCode(realm, id, digest) {
    const user = this.#users.get(`${realm}:${id}`);
    if (!user) return false;
    const index = user.recoveryCodeHashes.indexOf(digest);
    if (index < 0) return false;
    user.recoveryCodeHashes.splice(index, 1);
    user.updatedAt = nowIso();
    return true;
  }

  async createWebAuthnChallenge({ realm, purpose, userId = null, interactionUid = null, userHandle = null, challenge, expiresAt }) {
    const record = {
      id: randomUUID(),
      realm,
      purpose,
      userId,
      interactionUid,
      userHandle,
      challenge,
      expiresAt: new Date(expiresAt).toISOString(),
      createdAt: nowIso(),
    };
    this.#webauthnChallenges.set(`${realm}:${record.id}`, structuredClone(record));
    return structuredClone(record);
  }

  async consumeWebAuthnChallenge({ realm, id, purpose, userId = null, interactionUid = null }) {
    const key = `${realm}:${id}`;
    const record = this.#webauthnChallenges.get(key);
    if (!record
      || record.purpose !== purpose
      || record.userId !== userId
      || record.interactionUid !== interactionUid
      || new Date(record.expiresAt).getTime() <= Date.now()) return null;
    this.#webauthnChallenges.delete(key);
    return structuredClone(record);
  }

  async cleanupExpiredWebAuthnChallenges(limit = 1000) {
    let deleted = 0;
    for (const [key, record] of this.#webauthnChallenges) {
      if (deleted >= limit) break;
      if (new Date(record.expiresAt).getTime() <= Date.now()) {
        this.#webauthnChallenges.delete(key);
        deleted += 1;
      }
    }
    return deleted;
  }

  async createWebAuthnCredential(input) {
    const credential = normalizeWebAuthnCredential(input);
    if (!this.#users.has(`${credential.realm}:${credential.userId}`)) return null;
    const key = `${credential.realm}:${credential.id}`;
    if (this.#webauthnCredentials.has(key)) {
      throw Object.assign(new Error('This passkey is already registered'), { code: 'WEBAUTHN_CREDENTIAL_EXISTS' });
    }
    this.#webauthnCredentials.set(key, structuredClone(credential));
    return structuredClone(credential);
  }

  async findWebAuthnCredential(realm, credentialId) {
    const credential = this.#webauthnCredentials.get(`${realm}:${credentialId}`);
    return credential ? structuredClone(credential) : null;
  }

  async listWebAuthnCredentials(realm, userId) {
    return [...this.#webauthnCredentials.values()]
      .filter((credential) => credential.realm === realm && credential.userId === userId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt))
      .map((credential) => structuredClone(credential));
  }

  async updateWebAuthnCredentialCounter(realm, credentialId, { expectedCounter, newCounter, deviceType, backedUp }) {
    const credential = this.#webauthnCredentials.get(`${realm}:${credentialId}`);
    if (!credential || credential.counter !== expectedCounter) return false;
    if (!Number.isSafeInteger(newCounter) || newCounter < 0 || newCounter > 0xffff_ffff
      || ((expectedCounter > 0 || newCounter > 0) && newCounter <= expectedCounter)) return false;
    credential.counter = newCounter;
    credential.deviceType = deviceType;
    credential.backedUp = Boolean(backedUp);
    credential.lastUsedAt = nowIso();
    credential.updatedAt = credential.lastUsedAt;
    return true;
  }

  async deleteWebAuthnCredential(realm, userId, credentialId) {
    const key = `${realm}:${credentialId}`;
    const credential = this.#webauthnCredentials.get(key);
    if (!credential || credential.userId !== userId) return null;
    this.#webauthnCredentials.delete(key);
    return structuredClone(credential);
  }

  async writeAudit(event) {
    const ip = isIP(String(event.ip ?? '')) ? String(event.ip) : null;
    const record = { ...structuredClone(event), ip, id: randomUUID(), createdAt: nowIso() };
    this.#audit.unshift(record);
    this.#audit.length = Math.min(this.#audit.length, 10_000);
    return structuredClone(record);
  }

  async listAudit(realm, { limit = 100, offset = 0 } = {}) {
    return this.#audit.filter((item) => item.realm === realm).slice(offset, offset + limit).map((item) => structuredClone(item));
  }
}

function rowToUser(row) {
  if (!row) return null;
  return normalizeUser({
    id: row.id,
    realm: row.realm_name,
    username: row.username,
    email: row.email,
    emailVerified: row.email_verified,
    name: row.display_name,
    givenName: row.given_name,
    familyName: row.family_name,
    enabled: row.enabled,
    securityVersion: row.security_version,
    passwordHash: row.password_hash,
    roles: row.roles,
    groups: row.groups,
    clientRoles: row.client_roles,
    totpSecret: row.totp_secret,
    totpConfirmed: row.totp_confirmed,
    pendingTotpSecret: row.pending_totp_secret,
    pendingTotpCreatedAt: row.pending_totp_created_at?.toISOString?.() ?? row.pending_totp_created_at,
    recoveryCodeHashes: row.recovery_code_hashes,
    lastTotpStep: row.last_totp_step === null ? null : Number(row.last_totp_step),
    failedAttempts: row.failed_attempts,
    lockedUntil: row.locked_until?.toISOString?.() ?? row.locked_until,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
    lastLoginAt: row.last_login_at?.toISOString?.() ?? row.last_login_at,
  });
}

function rowToAdminGrant(row) {
  if (!row) return null;
  return normalizeAdminGrant({
    realm: row.realm_name,
    userId: row.user_id,
    permissions: row.permissions,
    enabled: row.enabled,
    version: row.version,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
  });
}

function rowToAdminSession(row) {
  if (!row) return null;
  return normalizeAdminSession({
    idDigest: row.id_digest,
    realm: row.realm_name,
    userId: row.user_id,
    grantVersion: row.grant_version,
    securityVersion: row.security_version,
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    lastSeenAt: row.last_seen_at?.toISOString?.() ?? row.last_seen_at,
    idleExpiresAt: row.idle_expires_at?.toISOString?.() ?? row.idle_expires_at,
    expiresAt: row.expires_at?.toISOString?.() ?? row.expires_at,
  });
}

export class PostgresIdentityStore {
  constructor(pool) {
    this.pool = pool;
  }

  async ready() {
    await this.pool.query('SELECT 1');
    return true;
  }

  async close() {
    await this.pool.end();
  }

  async createUser(input) {
    const user = normalizeUser(input);
    try {
      const result = await this.pool.query(
        `INSERT INTO users
          (id, realm_name, username, email, email_verified, display_name, given_name, family_name,
           enabled, password_hash, roles, groups, client_roles, totp_secret, totp_confirmed,
           recovery_code_hashes, last_totp_step, failed_attempts, locked_until, created_at, updated_at, last_login_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
         RETURNING *`,
        [user.id, user.realm, user.username, user.email, user.emailVerified, user.name, user.givenName,
          user.familyName, user.enabled, user.passwordHash, user.roles, user.groups, user.clientRoles,
          user.totpSecret, user.totpConfirmed, user.recoveryCodeHashes, user.lastTotpStep, user.failedAttempts, user.lockedUntil,
          user.createdAt, user.updatedAt, user.lastLoginAt],
      );
      return rowToUser(result.rows[0]);
    } catch (error) {
      if (error.code === '23505') throw Object.assign(new Error('A user with that username or email already exists'), { code: 'USER_EXISTS' });
      throw error;
    }
  }

  async findUserById(realm, id) {
    const result = await this.pool.query('SELECT * FROM users WHERE realm_name=$1 AND id=$2', [realm, id]);
    return rowToUser(result.rows[0]);
  }

  async findUserByLogin(realm, login) {
    const result = await this.pool.query(
      'SELECT * FROM users WHERE realm_name=$1 AND (lower(username)=lower($2) OR lower(email)=lower($2)) LIMIT 1',
      [realm, String(login).trim()],
    );
    return rowToUser(result.rows[0]);
  }

  async listUsers(realm, { limit = 100, offset = 0 } = {}) {
    const result = await this.pool.query(
      'SELECT * FROM users WHERE realm_name=$1 ORDER BY username LIMIT $2 OFFSET $3',
      [realm, limit, offset],
    );
    return result.rows.map(rowToUser);
  }

  async findAdminGrant(realm, userId) {
    const result = await this.pool.query(
      'SELECT * FROM admin_grants WHERE realm_name=$1 AND user_id=$2',
      [realm, userId],
    );
    return rowToAdminGrant(result.rows[0]);
  }

  async upsertAdminGrant(realm, userId, permissions, { enabled = true } = {}) {
    const normalized = normalizeAdminPermissions(permissions);
    const result = await this.pool.query(
      `INSERT INTO admin_grants (realm_name, user_id, permissions, enabled)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (realm_name, user_id) DO UPDATE
         SET permissions=EXCLUDED.permissions, enabled=EXCLUDED.enabled,
             version=admin_grants.version+1, updated_at=CURRENT_TIMESTAMP
       RETURNING *`,
      [realm, userId, [...normalized], Boolean(enabled)],
    );
    return rowToAdminGrant(result.rows[0]);
  }

  async revokeAdminGrant(realm, userId) {
    const result = await this.pool.query(
      `UPDATE admin_grants SET enabled=FALSE, version=version+1, updated_at=CURRENT_TIMESTAMP
       WHERE realm_name=$1 AND user_id=$2 RETURNING *`,
      [realm, userId],
    );
    return rowToAdminGrant(result.rows[0]);
  }

  async createAdminSession(input) {
    const session = normalizeAdminSession(input);
    const result = await this.pool.query(
      `INSERT INTO admin_sessions
        (id_digest, realm_name, user_id, grant_version, security_version,
         created_at, last_seen_at, idle_expires_at, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (id_digest) DO NOTHING
       RETURNING *`,
      [session.idDigest, session.realm, session.userId, session.grantVersion, session.securityVersion,
        session.createdAt, session.lastSeenAt, session.idleExpiresAt, session.expiresAt],
    );
    return rowToAdminSession(result.rows[0]);
  }

  async findAdminSession(idDigest) {
    const result = await this.pool.query('SELECT * FROM admin_sessions WHERE id_digest=$1', [idDigest]);
    return rowToAdminSession(result.rows[0]);
  }

  async touchAdminSession(idDigest, idleExpiresAt) {
    const result = await this.pool.query(
      `UPDATE admin_sessions SET last_seen_at=CURRENT_TIMESTAMP, idle_expires_at=$2
       WHERE id_digest=$1 AND expires_at>CURRENT_TIMESTAMP AND idle_expires_at>CURRENT_TIMESTAMP
       RETURNING *`,
      [idDigest, idleExpiresAt],
    );
    return rowToAdminSession(result.rows[0]);
  }

  async deleteAdminSession(idDigest) {
    const result = await this.pool.query('DELETE FROM admin_sessions WHERE id_digest=$1', [idDigest]);
    return result.rowCount === 1;
  }

  async cleanupExpiredAdminSessions(limit = 1000) {
    const result = await this.pool.query(
      `DELETE FROM admin_sessions WHERE id_digest IN (
         SELECT id_digest FROM admin_sessions
         WHERE expires_at<=CURRENT_TIMESTAMP OR idle_expires_at<=CURRENT_TIMESTAMP
         ORDER BY LEAST(expires_at, idle_expires_at)
         FOR UPDATE SKIP LOCKED LIMIT $1
       )`,
      [limit],
    );
    return result.rowCount;
  }

  async updateUser(realm, id, patch) {
    const columns = {
      email: 'email', emailVerified: 'email_verified', name: 'display_name', givenName: 'given_name',
      familyName: 'family_name', enabled: 'enabled', passwordHash: 'password_hash', roles: 'roles',
      groups: 'groups', clientRoles: 'client_roles',
    };
    const entries = Object.entries(patch).filter(([field]) => field in columns);
    if (!entries.length) return this.findUserById(realm, id);
    const values = [realm, id];
    const assignments = entries.map(([field, raw]) => {
      const value = field === 'email' ? String(raw).trim().toLowerCase() : raw;
      values.push(value);
      return `${columns[field]}=$${values.length}`;
    });
    try {
      const result = await this.pool.query(
        `UPDATE users SET ${assignments.join(', ')}, updated_at=now()
         WHERE realm_name=$1 AND id=$2 RETURNING *`,
        values,
      );
      return rowToUser(result.rows[0]);
    } catch (error) {
      if (error.code === '23505') throw Object.assign(new Error('A user with that email already exists'), { code: 'USER_EXISTS' });
      throw error;
    }
  }

  async deleteUser(realm, id) {
    const result = await this.pool.query(
      'DELETE FROM users WHERE realm_name=$1 AND id=$2 RETURNING *',
      [realm, id],
    );
    return rowToUser(result.rows[0]);
  }

  async rehashPasswordIfCurrent(realm, id, expectedHash, passwordHash) {
    const result = await this.pool.query(
      `UPDATE users SET password_hash=$4, updated_at=now()
       WHERE realm_name=$1 AND id=$2 AND password_hash=$3
       RETURNING id`,
      [realm, id, expectedHash, passwordHash],
    );
    return result.rowCount === 1;
  }

  async recordLoginFailure(realm, id) {
    await this.pool.query(
      `UPDATE users SET
       failed_attempts=CASE
         WHEN locked_until IS NOT NULL AND locked_until <= now() THEN 1
         WHEN locked_until IS NOT NULL AND locked_until > now() THEN failed_attempts
         ELSE failed_attempts+1
       END,
       locked_until=CASE
         WHEN locked_until IS NOT NULL AND locked_until > now() THEN locked_until
         WHEN locked_until IS NOT NULL AND locked_until <= now() THEN NULL
         WHEN failed_attempts+1 >= 5 THEN now()+interval '15 minutes'
         ELSE NULL
       END,
       updated_at=now() WHERE realm_name=$1 AND id=$2`,
      [realm, id],
    );
  }

  async recordLoginSuccess(realm, id) {
    await this.pool.query(
      'UPDATE users SET failed_attempts=0, locked_until=NULL, last_login_at=now(), updated_at=now() WHERE realm_name=$1 AND id=$2',
      [realm, id],
    );
  }

  async unlockUser(realm, id) {
    const result = await this.pool.query(
      'UPDATE users SET failed_attempts=0, locked_until=NULL, updated_at=now() WHERE realm_name=$1 AND id=$2 RETURNING *',
      [realm, id],
    );
    return rowToUser(result.rows[0]);
  }

  async beginTotpEnrollment(realm, id, pendingSecret) {
    const result = await this.pool.query(
      `UPDATE users SET pending_totp_secret=$3, pending_totp_created_at=now(), updated_at=now()
       WHERE realm_name=$1 AND id=$2 RETURNING *`,
      [realm, id, pendingSecret],
    );
    return rowToUser(result.rows[0]);
  }

  async confirmTotpEnrollment(realm, id, { pendingSecret, activeSecret, step, recoveryCodeHashes }) {
    if (typeof activeSecret !== 'string' || !Number.isSafeInteger(step)) return false;
    const result = await this.pool.query(
      `UPDATE users SET totp_secret=$4, totp_confirmed=TRUE,
       pending_totp_secret=NULL, pending_totp_created_at=NULL,
       recovery_code_hashes=$5, last_totp_step=$6, updated_at=now()
       WHERE realm_name=$1 AND id=$2 AND pending_totp_secret=$3
         AND pending_totp_created_at > now()-interval '10 minutes'
       RETURNING id`,
      [realm, id, pendingSecret, activeSecret, recoveryCodeHashes, step],
    );
    return result.rowCount === 1;
  }

  async configureTotp(realm, id, { secret, confirmed, recoveryCodeHashes }) {
    const result = await this.pool.query(
      `UPDATE users SET totp_secret=$3, totp_confirmed=$4,
       recovery_code_hashes=COALESCE($5,recovery_code_hashes),
       last_totp_step=CASE WHEN $4 THEN last_totp_step ELSE NULL END,
       pending_totp_secret=CASE WHEN $4 THEN pending_totp_secret ELSE NULL END,
       pending_totp_created_at=CASE WHEN $4 THEN pending_totp_created_at ELSE NULL END,
       updated_at=now()
       WHERE realm_name=$1 AND id=$2 RETURNING *`,
      [realm, id, secret, Boolean(confirmed), recoveryCodeHashes ?? null],
    );
    return rowToUser(result.rows[0]);
  }

  async consumeTotpStep(realm, id, step) {
    if (!Number.isSafeInteger(step)) return false;
    const result = await this.pool.query(
      `UPDATE users SET last_totp_step=$3, updated_at=now()
       WHERE realm_name=$1 AND id=$2 AND (last_totp_step IS NULL OR last_totp_step < $3)
       RETURNING id`,
      [realm, id, step],
    );
    return result.rowCount === 1;
  }

  async consumeRecoveryCode(realm, id, digest) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        'SELECT recovery_code_hashes FROM users WHERE realm_name=$1 AND id=$2 FOR UPDATE',
        [realm, id],
      );
      const hashes = result.rows[0]?.recovery_code_hashes ?? [];
      const index = hashes.indexOf(digest);
      if (index < 0) {
        await client.query('ROLLBACK');
        return false;
      }
      hashes.splice(index, 1);
      await client.query(
        'UPDATE users SET recovery_code_hashes=$3, updated_at=now() WHERE realm_name=$1 AND id=$2',
        [realm, id, hashes],
      );
      await client.query('COMMIT');
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async createWebAuthnChallenge({ realm, purpose, userId = null, interactionUid = null, userHandle = null, challenge, expiresAt }) {
    const result = await this.pool.query(
      `INSERT INTO webauthn_challenges
       (realm_name,id,purpose,user_id,interaction_uid,user_handle,challenge,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [realm, randomUUID(), purpose, userId, interactionUid, userHandle, challenge, expiresAt],
    );
    return rowToWebAuthnChallenge(result.rows[0]);
  }

  async consumeWebAuthnChallenge({ realm, id, purpose, userId = null, interactionUid = null }) {
    const result = await this.pool.query(
      `DELETE FROM webauthn_challenges
       WHERE realm_name=$1 AND id=$2 AND purpose=$3
         AND user_id IS NOT DISTINCT FROM $4::uuid
         AND interaction_uid IS NOT DISTINCT FROM $5
         AND expires_at > now()
       RETURNING *`,
      [realm, id, purpose, userId, interactionUid],
    );
    return rowToWebAuthnChallenge(result.rows[0]);
  }

  async cleanupExpiredWebAuthnChallenges(limit = 1000) {
    const result = await this.pool.query(
      `DELETE FROM webauthn_challenges WHERE ctid IN (
         SELECT ctid FROM webauthn_challenges
         WHERE expires_at <= now() ORDER BY expires_at
         FOR UPDATE SKIP LOCKED LIMIT $1
       )`,
      [limit],
    );
    return result.rowCount;
  }

  async createWebAuthnCredential(input) {
    const credential = normalizeWebAuthnCredential(input);
    try {
      const result = await this.pool.query(
        `INSERT INTO webauthn_credentials
         (realm_name,user_id,credential_id,user_handle,public_key,counter,transports,
          credential_device_type,backed_up,aaguid,display_name,created_at,updated_at,last_used_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING *`,
        [credential.realm, credential.userId, credential.id, credential.userHandle,
          Buffer.from(credential.publicKey), credential.counter, credential.transports,
          credential.deviceType, credential.backedUp, credential.aaguid, credential.name,
          credential.createdAt, credential.updatedAt, credential.lastUsedAt],
      );
      return rowToWebAuthnCredential(result.rows[0]);
    } catch (error) {
      if (error.code === '23505') {
        throw Object.assign(new Error('This passkey is already registered'), { code: 'WEBAUTHN_CREDENTIAL_EXISTS' });
      }
      throw error;
    }
  }

  async findWebAuthnCredential(realm, credentialId) {
    const result = await this.pool.query(
      'SELECT * FROM webauthn_credentials WHERE realm_name=$1 AND credential_id=$2',
      [realm, credentialId],
    );
    return rowToWebAuthnCredential(result.rows[0]);
  }

  async listWebAuthnCredentials(realm, userId) {
    const result = await this.pool.query(
      `SELECT * FROM webauthn_credentials
       WHERE realm_name=$1 AND user_id=$2 ORDER BY created_at, credential_id`,
      [realm, userId],
    );
    return result.rows.map(rowToWebAuthnCredential);
  }

  async updateWebAuthnCredentialCounter(realm, credentialId, { expectedCounter, newCounter, deviceType, backedUp }) {
    if (!Number.isSafeInteger(expectedCounter) || expectedCounter < 0
      || !Number.isSafeInteger(newCounter) || newCounter < 0 || newCounter > 0xffff_ffff
      || ((expectedCounter > 0 || newCounter > 0) && newCounter <= expectedCounter)) return false;
    const result = await this.pool.query(
      `UPDATE webauthn_credentials
       SET counter=$4, credential_device_type=$5, backed_up=$6,
           last_used_at=now(), updated_at=now()
       WHERE realm_name=$1 AND credential_id=$2 AND counter=$3
       RETURNING credential_id`,
      [realm, credentialId, expectedCounter, newCounter, deviceType, Boolean(backedUp)],
    );
    return result.rowCount === 1;
  }

  async deleteWebAuthnCredential(realm, userId, credentialId) {
    const result = await this.pool.query(
      `DELETE FROM webauthn_credentials
       WHERE realm_name=$1 AND user_id=$2 AND credential_id=$3 RETURNING *`,
      [realm, userId, credentialId],
    );
    return rowToWebAuthnCredential(result.rows[0]);
  }

  async writeAudit(event) {
    const ip = isIP(String(event.ip ?? '')) ? String(event.ip) : null;
    const result = await this.pool.query(
      `INSERT INTO audit_events (id, realm_name, event_type, actor_id, subject_id, client_id, ip_address, user_agent, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [randomUUID(), event.realm, event.type, event.actorId ?? null, event.subjectId ?? null,
        event.clientId ?? null, ip, event.userAgent ?? null, event.metadata ?? {}],
    );
    return result.rows[0];
  }

  async listAudit(realm, { limit = 100, offset = 0 } = {}) {
    const result = await this.pool.query(
      `SELECT id, realm_name AS realm, event_type AS type, actor_id AS "actorId",
       subject_id AS "subjectId", client_id AS "clientId", ip_address AS ip,
       user_agent AS "userAgent", metadata, created_at AS "createdAt" FROM audit_events
       WHERE realm_name=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [realm, limit, offset],
    );
    return result.rows;
  }
}
