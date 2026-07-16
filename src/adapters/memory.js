import { errors } from 'oidc-provider';

const stores = new Map();
const backchannelRequestModel = 'BackchannelAuthenticationRequest';

function bucket(realm, model) {
  const key = `${realm}\u0000${model}`;
  if (!stores.has(key)) stores.set(key, new Map());
  return stores.get(key);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function current(record) {
  if (!record) return undefined;
  if (record.expiresAt !== null && record.expiresAt <= Date.now()) return undefined;
  return record;
}

/** Development/test adapter. Production startup refuses to use it. */
export function createMemoryAdapter({ realm, securityVersionFor = async () => null }) {
  return class MemoryAdapter {
    constructor(model) {
      this.model = model;
      this.records = bucket(realm, model);
    }

    async upsert(id, payload, expiresIn) {
      const existing = this.records.get(id);
      const next = clone(payload);
      if (this.model === 'ReplayDetection' && current(existing)) {
        throw new errors.InvalidRequest('replayed assertion or proof detected');
      }
      if (this.model === backchannelRequestModel && existing) {
        const incomingFinal = next.grantId != null || next.error != null;
        const existingFinal = existing.payload.grantId != null || existing.payload.error != null;
        if (!incomingFinal || existingFinal || existing.payload.consumed) {
          throw new errors.InvalidGrant('backchannel authentication request state transition was rejected');
        }
      }
      if (existing?.payload?.consumed && !next.consumed) next.consumed = existing.payload.consumed;
      let parent;
      if (next.grantId != null) {
        parent = current(bucket(realm, 'Grant').get(next.grantId));
        const parentAccountId = parent?.payload?.accountId;
        const parentVersion = parentAccountId == null ? null : await securityVersionFor(parentAccountId);
        if (!parent || parentAccountId == null || parentVersion == null || parent.securityVersion !== parentVersion) {
          throw new errors.InvalidGrant('parent grant is unavailable or stale');
        }
        if (next.accountId != null && next.accountId !== parentAccountId) {
          throw new errors.InvalidGrant('artifact account does not match its parent grant');
        }
        next.accountId = parentAccountId;
      }
      const securityVersion = next.accountId == null ? null : await securityVersionFor(next.accountId);
      if (next.accountId != null && securityVersion == null) {
        throw new errors.InvalidGrant('account-bound artifact references an unavailable account');
      }
      if (next.grantId != null) {
        const liveParent = current(bucket(realm, 'Grant').get(next.grantId));
        if (liveParent !== parent || liveParent?.securityVersion !== securityVersion) {
          throw new errors.InvalidGrant('parent grant changed while the artifact was being saved');
        }
      }
      this.records.set(id, {
        payload: next,
        securityVersion,
        expiresAt: expiresIn === undefined ? null : Date.now() + Number(expiresIn) * 1000,
        cibaPollIntervalSeconds: existing?.cibaPollIntervalSeconds,
        cibaNextPollAt: existing?.cibaNextPollAt,
      });
    }

    async find(id) {
      const stored = this.records.get(id);
      const record = this.model === backchannelRequestModel ? stored : current(stored);
      if (!record) return undefined;
      if (record.securityVersion != null && await securityVersionFor(record.payload.accountId) !== record.securityVersion) return undefined;
      return clone(record.payload);
    }

    async findByUserCode(userCode) {
      for (const record of this.records.values()) {
        const live = current(record);
        if (live?.payload?.userCode === userCode) {
          if (live.securityVersion != null && await securityVersionFor(live.payload.accountId) !== live.securityVersion) return undefined;
          return clone(live.payload);
        }
      }
      return undefined;
    }

    async findByUid(uid) {
      for (const record of this.records.values()) {
        const live = current(record);
        if (live?.payload?.uid === uid) {
          if (live.securityVersion != null && await securityVersionFor(live.payload.accountId) !== live.securityVersion) return undefined;
          return clone(live.payload);
        }
      }
      return undefined;
    }

    async consume(id) {
      const record = current(this.records.get(id));
      if (!record || record.payload.consumed) {
        if (['AuthorizationCode', 'RefreshToken', 'DeviceCode', backchannelRequestModel].includes(this.model)) {
          throw new errors.InvalidGrant('one-use grant artifact was already consumed');
        }
        throw new errors.InvalidRequest('one-use artifact was already consumed');
      }
      record.payload.consumed = Math.floor(Date.now() / 1000);
    }

    async checkCibaPoll(id, clientId, intervalSeconds) {
      if (this.model !== backchannelRequestModel) throw new TypeError('CIBA polling is only valid for backchannel authentication requests');
      const record = current(this.records.get(id));
      if (!record || record.payload.clientId !== clientId || record.payload.consumed) return { status: 'invalid' };
      if (record.securityVersion != null && await securityVersionFor(record.payload.accountId) !== record.securityVersion) {
        return { status: 'invalid' };
      }
      const now = Date.now();
      const allowed = record.cibaNextPollAt == null || record.cibaNextPollAt <= now;
      const interval = allowed
        ? record.cibaPollIntervalSeconds ?? intervalSeconds
        : (record.cibaPollIntervalSeconds ?? intervalSeconds) + 5;
      record.cibaPollIntervalSeconds = interval;
      record.cibaNextPollAt = now + interval * 1000;
      return { status: allowed ? 'allowed' : 'slow_down', interval };
    }

    async destroy(id) {
      this.records.delete(id);
    }

    async revokeByGrantId(grantId) {
      for (const [id, record] of this.records.entries()) {
        if (record.payload.grantId === grantId) this.records.delete(id);
      }
    }
  };
}

export function clearMemoryAdapter() {
  stores.clear();
}

export function listMemoryAdapterRecords(realm, model) {
  const records = [];
  for (const [id, record] of bucket(realm, model)) {
    const live = current(record);
    if (live) records.push({ id, payload: clone(live.payload) });
  }
  return records;
}

export function revokeMemoryAccount(realm, accountId) {
  const prefix = `${realm}\u0000`;
  const grantIds = new Set();
  for (const [key, records] of stores) {
    if (key === `${prefix}Grant`) {
      for (const [id, record] of records) {
        if (record.payload.accountId === accountId) grantIds.add(id);
      }
    }
  }
  let deleted = 0;
  for (const [key, records] of stores) {
    if (!key.startsWith(prefix)) continue;
    for (const [id, record] of records) {
      if (record.payload.accountId === accountId || grantIds.has(record.payload.grantId)) {
        records.delete(id);
        deleted += 1;
      }
    }
  }
  return deleted;
}

export function revokeMemoryClient(realm, clientId) {
  const prefix = `${realm}\u0000`;
  const grantIds = new Set();
  for (const [id, record] of bucket(realm, 'Grant')) {
    if (record.payload.clientId === clientId) grantIds.add(id);
  }
  let deleted = 0;
  for (const [entry, records] of stores) {
    if (!entry.startsWith(prefix)) continue;
    for (const [id, record] of records) {
      if (record.payload.clientId === clientId || grantIds.has(record.payload.grantId)) {
        records.delete(id);
        deleted += 1;
      }
    }
  }
  return deleted;
}

export function listMemoryAccountSessions(realm, accountId) {
  const sessions = [];
  for (const [id, record] of bucket(realm, 'Session')) {
    const live = current(record);
    if (!live || live.payload.accountId !== accountId) continue;
    const authorizations = live.payload.authorizations;
    sessions.push({
      id,
      createdAt: Number.isFinite(live.payload.iat) ? new Date(live.payload.iat * 1000).toISOString() : null,
      lastSeenAt: Number.isFinite(live.payload.touched) ? new Date(live.payload.touched * 1000).toISOString() : null,
      expiresAt: live.expiresAt == null ? null : new Date(live.expiresAt).toISOString(),
      clientIds: authorizations && typeof authorizations === 'object' ? Object.keys(authorizations) : [],
    });
  }
  return structuredClone(sessions);
}

export function revokeMemorySession(realm, accountId, sessionId) {
  const sessions = bucket(realm, 'Session');
  const target = current(sessions.get(sessionId));
  if (!target || target.payload.accountId !== accountId) return false;
  const grantIds = new Set(Object.values(target.payload.authorizations ?? {}).filter((value) => typeof value === 'string'));
  sessions.delete(sessionId);
  const prefix = `${realm}\u0000`;
  for (const [key, records] of stores) {
    if (!key.startsWith(prefix)) continue;
    const model = key.slice(prefix.length);
    for (const [id, record] of records) {
      if ((model === 'Grant' && grantIds.has(id)) || grantIds.has(record.payload.grantId)) records.delete(id);
    }
  }
  return true;
}

export function claimMemoryInitialAccessToken(realm, id) {
  const record = current(bucket(realm, 'InitialAccessToken').get(id));
  if (!record || record.payload.consumed) return false;
  record.payload.consumed = Math.floor(Date.now() / 1000);
  return true;
}
