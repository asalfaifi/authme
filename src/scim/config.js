import { safeEqual } from '../crypto/secrets.js';

function configurationError(message, cause) {
  return Object.assign(new Error(`Invalid SCIM token configuration: ${message}`, cause ? { cause } : undefined), {
    code: 'AUTHME_SCIM_CONFIGURATION_INVALID',
  });
}

export function parseScimTokens(value, { realms, devMode }) {
  if (!value) return Object.freeze(Object.fromEntries(realms.map((realm) => [realm, Object.freeze([])])));
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) {
    throw configurationError('AUTHME_SCIM_TOKENS_JSON must contain valid JSON', error);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw configurationError('AUTHME_SCIM_TOKENS_JSON must be an object keyed by realm');
  }
  const unknownRealms = Object.keys(parsed).filter((realm) => !realms.includes(realm));
  if (unknownRealms.length) throw configurationError(`unknown realms: ${unknownRealms.join(', ')}`);
  const result = {};
  for (const realm of realms) {
    if (!Array.isArray(parsed[realm] ?? [])) throw configurationError(`${realm} must be an array`);
    const ids = new Set();
    result[realm] = Object.freeze((parsed[realm] ?? []).map((item, index) => {
      if (!item || Array.isArray(item) || typeof item !== 'object'
        || Object.keys(item).some((key) => !['id', 'token'].includes(key))) {
        throw configurationError(`${realm}[${index}] must contain only id and token`);
      }
      if (!/^[a-z][a-z0-9-]{1,63}$/.test(item.id ?? '') || ids.has(item.id)) {
        throw configurationError(`${realm}[${index}].id is invalid or duplicated`);
      }
      ids.add(item.id);
      if (typeof item.token !== 'string' || Buffer.byteLength(item.token) < 32 || Buffer.byteLength(item.token) > 4096) {
        throw configurationError(`${realm}[${index}].token must contain 32 to 4096 bytes`);
      }
      if (!devMode && /(?:replace[-_ ]?with|change[-_ ]?me|example[-_ ]?secret)/i.test(item.token)) {
        throw configurationError(`${realm}[${index}].token contains an example placeholder`);
      }
      return Object.freeze({ id: item.id, token: item.token });
    }));
  }
  return Object.freeze(result);
}

export function createScimTokenAuthenticator(tokensByRealm) {
  return async function authenticate({ realm, token }) {
    let actor = null;
    // Compare every configured token so the matching position does not affect
    // request timing. safeEqual also covers unequal-length candidates.
    for (const candidate of tokensByRealm[realm] ?? []) {
      if (safeEqual(String(token ?? ''), candidate.token)) actor = { type: 'scim-token', id: candidate.id };
    }
    return actor;
  };
}
