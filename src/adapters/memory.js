import { errors } from 'oidc-provider';

const stores = new Map();

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
      if (this.model === 'ReplayDetection' && current(existing)) {
        throw new errors.InvalidRequest('replayed assertion or proof detected');
      }
      const next = clone(payload);
      if (existing?.payload?.consumed && !next.consumed) next.consumed = existing.payload.consumed;
      const securityVersion = next.accountId == null ? null : await securityVersionFor(next.accountId);
      if (next.accountId != null && securityVersion == null) {
        throw new errors.InvalidGrant('account-bound artifact references an unavailable account');
      }
      this.records.set(id, {
        payload: next,
        securityVersion,
        expiresAt: expiresIn === undefined ? null : Date.now() + Number(expiresIn) * 1000,
      });
    }

    async find(id) {
      const record = current(this.records.get(id));
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
        if (['AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest'].includes(this.model)) {
          throw new errors.InvalidGrant('one-use grant artifact was already consumed');
        }
        throw new errors.InvalidRequest('one-use artifact was already consumed');
      }
      record.payload.consumed = Math.floor(Date.now() / 1000);
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

export function claimMemoryInitialAccessToken(realm, id) {
  const record = current(bucket(realm, 'InitialAccessToken').get(id));
  if (!record || record.payload.consumed) return false;
  record.payload.consumed = Math.floor(Date.now() / 1000);
  return true;
}
