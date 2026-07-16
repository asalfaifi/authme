import { loadRealmJwks, validateJwks } from './jwks.js';

const privateMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv']);

function publicJwk(key) {
  return Object.fromEntries(Object.entries(key).filter(([name]) => !privateMembers.has(name)));
}

function adapterFor(adapters, provider) {
  return adapters instanceof Map ? adapters.get(provider) : adapters?.[provider];
}

export function createSigningKeyManager({ config, realm, management, adapters = {}, clock = () => new Date() }) {
  const policy = config.signingKeyProvidersByRealm[realm];
  if (!policy) throw new Error(`No signing-key policy is configured for realm ${realm}`);
  const external = policy.provider === 'file' ? null : adapterFor(adapters, policy.provider);
  if (policy.provider !== 'file' && (!external?.loadJwks || !external?.rotate)) {
    throw new Error(`Signing-key provider ${policy.provider} requires loadJwks and rotate adapter methods`);
  }

  async function rawLoad() {
    if (policy.provider === 'file') return loadRealmJwks(config, realm);
    const result = await external.loadJwks({ realm, policy });
    return validateJwks(result, `${policy.provider}:${policy.materialReference}`);
  }

  async function synchronize(jwks) {
    if (!management) return;
    const existing = await management.listSigningKeys(realm);
    const existingActive = existing.find((entry) => entry.status === 'active');
    const activeKid = jwks.keys.some((entry) => entry.kid === existingActive?.keyId)
      ? existingActive.keyId
      : jwks.keys[0].kid;
    const timestamp = clock();
    for (const key of jwks.keys) {
      const previous = existing.find((entry) => entry.keyId === key.kid);
      const active = key.kid === activeKid;
      await management.putSigningKey(realm, {
        keyId: key.kid,
        provider: policy.provider,
        status: active ? 'active' : 'retiring',
        algorithm: key.alg,
        materialReference: policy.materialReference,
        publicJwk: publicJwk(key),
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
    const nextActive = jwks.keys.find((key) => key.kid !== previousActive) ?? jwks.keys[0];
    if (previousActive && nextActive.kid === previousActive) {
      throw new Error(`${policy.provider} rotation did not publish a new signing key`);
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
      publicJwk: publicJwk(nextActive),
      activatedAt: clock(),
      retireAfter: null,
    });
    return { rotated: true, keyId: nextActive.kid, jwks: ordered };
  }

  return Object.freeze({ realm, policy, load, rotate });
}
