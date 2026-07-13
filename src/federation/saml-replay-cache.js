function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function validateKey(key) {
  if (typeof key !== 'string' || key.length === 0 || key.length > 1024) {
    throw new TypeError('SAML replay-cache keys must be non-empty strings no longer than 1024 characters');
  }
}

function validateTtl(ttlMs) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 24 * 60 * 60 * 1000) {
    throw new TypeError('SAML replay-cache TTL must be an integer between 1ms and 24 hours');
  }
}

export function assertSamlReplayCache(cache) {
  if (!cache || typeof cache !== 'object') throw new TypeError('A shared SAML replay cache is required');
  for (const method of ['putIfAbsent', 'get', 'consume']) {
    if (typeof cache[method] !== 'function') {
      throw new TypeError(`SAML replay cache must implement ${method}()`);
    }
  }
  return cache;
}

/**
 * Process-local implementation for tests and single-process development only.
 * Production replicas must inject a shared implementation whose putIfAbsent
 * and consume operations are atomic.
 */
export class MemorySamlReplayCache {
  constructor({ now = Date.now } = {}) {
    if (typeof now !== 'function') throw new TypeError('now must be a function');
    this.now = now;
    this.records = new Map();
  }

  prune() {
    const now = this.now();
    for (const [key, record] of this.records) {
      if (record.expiresAt <= now) this.records.delete(key);
    }
  }

  async putIfAbsent(key, value, ttlMs) {
    validateKey(key);
    validateTtl(ttlMs);
    this.prune();
    if (this.records.has(key)) return false;
    this.records.set(key, { value: clone(value), expiresAt: this.now() + ttlMs });
    return true;
  }

  async get(key) {
    validateKey(key);
    this.prune();
    return clone(this.records.get(key)?.value ?? null);
  }

  async consume(key) {
    validateKey(key);
    this.prune();
    const record = this.records.get(key);
    if (!record) return null;
    this.records.delete(key);
    return clone(record.value);
  }
}

function oneUseConflict(error) {
  return error?.error === 'invalid_request'
    && /replay|one-use|already consumed/i.test(error?.error_description ?? error?.message ?? '');
}

/**
 * Uses AuthMe's realm-scoped oidc-provider adapter storage. ReplayDetection
 * inserts and artifact consumption are atomic in both shipped adapters, so no
 * extra schema is needed. Construct one cache per realm.
 */
export function createAdapterSamlReplayCache(Adapter) {
  if (typeof Adapter !== 'function') throw new TypeError('A realm-scoped AuthMe Adapter class is required');
  const records = new Adapter('ReplayDetection');
  return Object.freeze({
    async putIfAbsent(key, value, ttlMs) {
      validateKey(key);
      validateTtl(ttlMs);
      try {
        await records.upsert(key, { value }, ttlMs / 1000);
        return true;
      } catch (error) {
        if (oneUseConflict(error)) return false;
        throw error;
      }
    },
    async get(key) {
      validateKey(key);
      const record = await records.find(key);
      return record && !record.consumed ? clone(record.value) : null;
    },
    async consume(key) {
      validateKey(key);
      const record = await records.find(key);
      if (!record || record.consumed) return null;
      try {
        await records.consume(key);
        return clone(record.value);
      } catch (error) {
        if (oneUseConflict(error)) return null;
        throw error;
      }
    },
  });
}

/**
 * Adapts AuthMe's atomic replay-cache contract to Node-SAML's CacheProvider.
 * A second response/assertion claim in the broker remains necessary because
 * Node-SAML's CacheProvider protocol performs request lookup and removal as
 * separate operations.
 */
export function createNodeSamlCacheProvider({ cache, prefix, ttlMs, now = Date.now }) {
  assertSamlReplayCache(cache);
  if (typeof prefix !== 'string' || prefix.length === 0) throw new TypeError('SAML cache prefix is required');
  validateTtl(ttlMs);
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  const keyFor = (key) => `${prefix}:request:${key}`;
  return Object.freeze({
    async saveAsync(key, value) {
      validateKey(key);
      const saved = await cache.putIfAbsent(keyFor(key), value, ttlMs);
      return saved ? { value, createdAt: now() } : null;
    },
    async getAsync(key) {
      validateKey(key);
      return cache.get(keyFor(key));
    },
    async removeAsync(key) {
      if (key === null) return null;
      validateKey(key);
      return await cache.consume(keyFor(key)) === null ? null : key;
    },
  });
}
