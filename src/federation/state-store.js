import { randomBytes } from 'node:crypto';

function invalidState() {
  return Object.assign(new Error('Federation state is missing, expired, or already used'), {
    code: 'AUTHME_FEDERATION_STATE_INVALID',
    status: 400,
    safe: true,
  });
}

export function createAdapterFederationStateStore(adapterFor) {
  return {
    async issue(realm, payload, expiresInSeconds = 300) {
      const state = randomBytes(32).toString('base64url');
      const Adapter = adapterFor(realm);
      await new Adapter('FederationState').upsert(state, payload, expiresInSeconds);
      return state;
    },

    async consume(realm, state) {
      if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(state)) throw invalidState();
      const Adapter = adapterFor(realm);
      const records = new Adapter('FederationState');
      const payload = await records.find(state);
      if (!payload) throw invalidState();
      try { await records.consume(state); } catch { throw invalidState(); }
      return payload;
    },
  };
}

export { invalidState as invalidFederationState };
