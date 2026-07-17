import { constants, createPublicKey, verify } from 'node:crypto';
import { ExternalSigningKey } from 'oidc-provider';
import {
  loadRealmJwks,
  publicSigningJwks,
  validatePublicSigningJwks,
} from './jwks.js';

function ecdsaDerToJose(signature, size = 32) {
  if (signature.length === size * 2) return signature;
  let offset = 0;
  const readLength = () => {
    const first = signature[offset++];
    if (first < 0x80) return first;
    const bytes = first & 0x7f;
    if (bytes < 1 || bytes > 2 || offset + bytes > signature.length) throw new Error('External signer returned invalid ECDSA DER');
    let length = 0;
    for (let index = 0; index < bytes; index += 1) length = (length << 8) | signature[offset++];
    return length;
  };
  if (signature[offset++] !== 0x30) throw new Error('External signer returned invalid ECDSA signature');
  const sequenceLength = readLength();
  if (offset + sequenceLength !== signature.length || signature[offset++] !== 0x02) throw new Error('External signer returned invalid ECDSA signature');
  const readInteger = () => {
    const length = readLength();
    const value = signature.subarray(offset, offset + length);
    offset += length;
    const normalized = value[0] === 0 ? value.subarray(1) : value;
    if (!normalized.length || normalized.length > size) throw new Error('External signer returned an out-of-range ECDSA signature');
    const result = Buffer.alloc(size);
    normalized.copy(result, size - normalized.length);
    return result;
  };
  const r = readInteger();
  if (signature[offset++] !== 0x02) throw new Error('External signer returned invalid ECDSA signature');
  const s = readInteger();
  if (offset !== signature.length) throw new Error('External signer returned invalid ECDSA signature');
  return Buffer.concat([r, s]);
}

function verifyExternalSignature(algorithm, key, data, signature) {
  const digest = algorithm === 'EdDSA' ? null : 'sha256';
  let keyOptions = key;
  if (algorithm === 'RS256') keyOptions = { key, padding: constants.RSA_PKCS1_PADDING };
  if (algorithm === 'PS256') keyOptions = { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
  if (algorithm === 'ES256') keyOptions = { key, dsaEncoding: 'ieee-p1363' };
  if (!verify(digest, data, keyOptions, signature)) {
    throw new Error('External signing adapter returned a signature that does not match the configured public key');
  }
}

class AuthMeExternalSigningKey extends ExternalSigningKey {
  #jwk;

  #keyObject;

  #signer;

  constructor(jwk, keyObject, signer) {
    super();
    this.#jwk = Object.freeze(structuredClone(jwk));
    this.#keyObject = keyObject;
    this.#signer = signer;
    this.kid = jwk.kid;
    this.alg = jwk.alg;
  }

  keyObject() { return this.#keyObject; }

  toPublicJwk() { return structuredClone(this.#jwk); }

  async sign(data) {
    const value = await this.#signer(Buffer.from(data));
    if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) {
      throw new TypeError('External signing adapters must return a Buffer or Uint8Array signature');
    }
    const signature = Buffer.from(value);
    if (!signature.length) throw new Error('External signing adapter returned an empty signature');
    const normalized = this.alg === 'ES256' ? ecdsaDerToJose(signature) : signature;
    verifyExternalSignature(this.alg, this.#keyObject, Buffer.from(data), normalized);
    return normalized;
  }
}

function adapterFor(adapters, provider) {
  return adapters instanceof Map ? adapters.get(provider) : adapters?.[provider];
}

export function createSigningKeyManager({ config, realm, management, adapters = {}, clock = () => new Date() }) {
  const policy = config.signingKeyProvidersByRealm[realm];
  if (!policy) throw new Error(`No signing-key policy is configured for realm ${realm}`);
  const external = policy.provider === 'file' ? null : adapterFor(adapters, policy.provider);
  if (policy.provider !== 'file' && (!external?.loadJwks || !external?.sign || !external?.rotate)) {
    throw new Error(`Signing-key provider ${policy.provider} requires loadJwks, sign, and rotate adapter methods`);
  }

  async function rawLoad() {
    if (policy.provider === 'file') return loadRealmJwks(config, realm);
    const publicJwks = await validatePublicSigningJwks(
      await external.loadJwks({ realm, policy }),
      `${policy.provider}:${policy.materialReference}`,
    );
    if (publicJwks.keys.some((key) => key.alg !== policy.algorithm)) {
      throw new Error(`${policy.provider}:${policy.materialReference} contains a key that does not match configured algorithm ${policy.algorithm}`);
    }
    return {
      keys: publicJwks.keys.map((jwk) => new AuthMeExternalSigningKey(
        jwk,
        createPublicKey({ key: jwk, format: 'jwk' }),
        (data) => external.sign({ realm, policy, keyId: jwk.kid, algorithm: jwk.alg, data }),
      )),
    };
  }

  async function synchronize(jwks) {
    if (!management) return;
    const existing = await management.listSigningKeys(realm);
    const timestamp = clock();
    const publishedKids = new Set(jwks.keys.map((key) => key.kid));
    const prematurelyRemoved = existing.find((entry) => !publishedKids.has(entry.keyId) && (
      entry.status === 'active'
      || (entry.status === 'retiring' && entry.retireAfter && new Date(entry.retireAfter) > timestamp)
    ));
    if (prematurelyRemoved) {
      throw new Error(`Signing key ${prematurelyRemoved.keyId} was removed before its verification overlap completed`);
    }
    const activeKid = jwks.keys[0].kid;
    for (const key of jwks.keys) {
      const previous = existing.find((entry) => entry.keyId === key.kid);
      const active = key.kid === activeKid;
      await management.putSigningKey(realm, {
        keyId: key.kid,
        provider: policy.provider,
        status: active ? 'active' : 'retiring',
        algorithm: key.alg,
        materialReference: policy.materialReference,
        publicJwk: publicSigningJwks({ keys: [key] }).keys[0],
        activatedAt: active ? previous?.activatedAt ?? timestamp : previous?.activatedAt ?? null,
        retireAfter: active ? null : previous?.retireAfter ?? new Date(timestamp.getTime() + policy.overlapSeconds * 1000),
      });
    }
    for (const previous of existing.filter((entry) => !jwks.keys.some((key) => key.kid === entry.keyId)
      && entry.status !== 'retired')) {
      await management.putSigningKey(realm, { ...previous, status: 'retired' });
    }
  }

  async function load({ rotateIfDue = true } = {}) {
    const jwks = await rawLoad();
    await synchronize(jwks);
    if (rotateIfDue && external) {
      const result = await rotate();
      if (result.rotated) return result.jwks;
    }
    return jwks;
  }

  async function rotate({ force = false } = {}) {
    if (policy.provider === 'file') {
      throw Object.assign(new Error('File-backed keys rotate through npm run keys:rotate and an atomic deployment secret update'), {
        code: 'SIGNING_KEY_FILE_ROTATION_REQUIRED',
      });
    }
    const current = await management.listSigningKeys(realm);
    const active = current.find((entry) => entry.status === 'active');
    const dueAt = active?.activatedAt
      ? new Date(active.activatedAt).getTime() + policy.rotationDays * 86_400_000
      : 0;
    if (!force && dueAt > clock().getTime()) return { rotated: false, dueAt: new Date(dueAt) };
    await external.rotate({ realm, policy, activeKeyId: active?.keyId, overlapSeconds: policy.overlapSeconds });
    const jwks = await rawLoad();
    const previousActive = active?.keyId;
    const nextActive = jwks.keys[0];
    if (previousActive && nextActive.kid === previousActive) {
      throw new Error(`${policy.provider} rotation did not publish a new signing key`);
    }
    if (previousActive && !jwks.keys.some((key) => key.kid === previousActive)) {
      throw new Error(`${policy.provider} rotation removed the previous signing key before the configured overlap`);
    }
    const ordered = { keys: [nextActive, ...jwks.keys.filter((key) => key.kid !== nextActive.kid)] };
    if (previousActive) {
      const previous = current.find((entry) => entry.keyId === previousActive);
      await management.putSigningKey(realm, {
        ...previous,
        status: 'retiring',
        retireAfter: new Date(clock().getTime() + policy.overlapSeconds * 1000),
      });
    }
    await management.putSigningKey(realm, {
      keyId: nextActive.kid,
      provider: policy.provider,
      status: 'active',
      algorithm: nextActive.alg,
      materialReference: policy.materialReference,
      publicJwk: publicSigningJwks({ keys: [nextActive] }).keys[0],
      activatedAt: clock(),
      retireAfter: null,
    });
    return { rotated: true, keyId: nextActive.kid, jwks: ordered };
  }

  return Object.freeze({ realm, policy, load, rotate });
}
