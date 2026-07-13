import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { KeyObject, randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair, importJWK } from 'jose';

const allowedAlgorithms = new Set(['RS256', 'PS256', 'ES256', 'EdDSA']);

async function validateJwks(jwks, source) {
  if (!jwks || !Array.isArray(jwks.keys) || !jwks.keys.length) throw new Error(`${source} must contain a non-empty JWK Set`);
  const kids = new Set();
  for (const key of jwks.keys) {
    if (!key.d) throw new Error(`${source} must contain private signing keys`);
    if (!key.kid || kids.has(key.kid)) throw new Error(`${source} contains a missing or duplicate kid`);
    if (key.use !== 'sig' || (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || !key.key_ops.includes('sign')))) {
      throw new Error(`${source} contains a key that is not explicitly intended for signing`);
    }
    if (!allowedAlgorithms.has(key.alg)) throw new Error(`${source} contains unsupported or missing algorithm ${key.alg}`);
    const expected = {
      RS256: ['RSA'], PS256: ['RSA'], ES256: ['EC', 'P-256'], EdDSA: ['OKP', 'Ed25519'],
    }[key.alg];
    if (key.kty !== expected[0] || (expected[1] && key.crv !== expected[1])) {
      throw new Error(`${source} contains a key type that does not match ${key.alg}`);
    }
    let imported;
    try {
      imported = KeyObject.from(await importJWK(key, key.alg));
    } catch (error) {
      throw new Error(`${source} contains a key that cannot be imported for ${key.alg}`, { cause: error });
    }
    if (expected[0] === 'RSA' && (imported.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new Error(`${source} contains an RSA key smaller than 2048 bits`);
    }
    kids.add(key.kid);
  }
  return { keys: jwks.keys };
}

export async function generateDevelopmentJwks() {
  const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const jwk = await exportJWK(privateKey);
  return {
    keys: [{ ...jwk, kid: randomBytes(12).toString('base64url'), alg: 'RS256', use: 'sig' }],
  };
}

export async function loadRealmJwks(config, realm) {
  if (config.devMode && !config.jwksDir) return generateDevelopmentJwks();
  const path = join(config.jwksDir, `${realm}.json`);
  let parsed;
  try {
    parsed = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load realm key set ${path}`, { cause: error });
  }
  return validateJwks(parsed, path);
}
