export const AUTHME_EXTENSION_API_VERSION = 'authme.identity/v1';

const kinds = new Set(['authenticator', 'federation', 'provisioning']);
const idPattern = /^[a-z][a-z0-9.-]{1,63}$/;
const capabilityPattern = /^[a-z][a-z0-9._-]{0,63}$/;

function configurationError(message) {
  return Object.assign(new Error(`Invalid identity extension: ${message}`), {
    code: 'AUTHME_EXTENSION_INVALID',
  });
}

function normalizeManifest(input) {
  if (!input || Array.isArray(input) || typeof input !== 'object') {
    throw configurationError('manifest must be an object');
  }
  if (input.apiVersion !== AUTHME_EXTENSION_API_VERSION) {
    throw configurationError(`apiVersion must be ${AUTHME_EXTENSION_API_VERSION}`);
  }
  if (!idPattern.test(input.id ?? '')) throw configurationError('id is not valid');
  if (!kinds.has(input.kind)) throw configurationError('kind is not supported');
  if (typeof input.displayName !== 'string' || !input.displayName.trim() || input.displayName.length > 100) {
    throw configurationError('displayName must contain 1 to 100 characters');
  }
  const capabilities = input.capabilities ?? [];
  if (!Array.isArray(capabilities)
    || capabilities.some((capability) => typeof capability !== 'string' || !capabilityPattern.test(capability))
    || new Set(capabilities).size !== capabilities.length) {
    throw configurationError('capabilities must be a unique array of stable identifiers');
  }
  return Object.freeze({
    apiVersion: AUTHME_EXTENSION_API_VERSION,
    id: input.id,
    kind: input.kind,
    displayName: input.displayName.trim(),
    capabilities: Object.freeze([...capabilities].sort()),
  });
}

function validateImplementation(manifest, implementation) {
  if (!implementation || typeof implementation !== 'object') {
    throw configurationError(`${manifest.id} implementation must be an object`);
  }
  if (implementation.enabledFor !== undefined && typeof implementation.enabledFor !== 'function') {
    throw configurationError(`${manifest.id}.enabledFor must be a function`);
  }
  if (manifest.kind === 'authenticator') {
    const singleStep = typeof implementation.authenticate === 'function';
    const ceremony = typeof implementation.begin === 'function' && typeof implementation.complete === 'function';
    if (!singleStep && !ceremony) {
      throw configurationError(`${manifest.id} must implement authenticate() or begin()/complete()`);
    }
  }
  if (manifest.kind === 'federation'
    && (typeof implementation.initiate !== 'function' || typeof implementation.consume !== 'function')) {
    throw configurationError(`${manifest.id} must implement initiate() and consume()`);
  }
  if (manifest.kind === 'provisioning' && typeof implementation.createRouter !== 'function') {
    throw configurationError(`${manifest.id} must implement createRouter()`);
  }
}

export class IdentityExtensionRegistry {
  #entries = new Map();

  register({ manifest: inputManifest, implementation }) {
    const manifest = normalizeManifest(inputManifest);
    validateImplementation(manifest, implementation);
    if (this.#entries.has(manifest.id)) throw configurationError(`duplicate id: ${manifest.id}`);
    const entry = Object.freeze({ manifest, implementation });
    this.#entries.set(manifest.id, entry);
    return entry;
  }

  get(id, kind) {
    const entry = this.#entries.get(id);
    if (!entry || (kind && entry.manifest.kind !== kind)) return null;
    return entry;
  }

  forRealm(kind, realm) {
    if (!kinds.has(kind)) throw configurationError('kind is not supported');
    return [...this.#entries.values()].filter(({ manifest, implementation }) => (
      manifest.kind === kind && (implementation.enabledFor?.(realm) ?? true)
    ));
  }

  describe(realm) {
    return [...this.#entries.values()]
      .filter(({ implementation }) => implementation.enabledFor?.(realm) ?? true)
      .map(({ manifest }) => manifest);
  }
}

export function createIdentityExtensionRegistry(extensions = []) {
  const registry = new IdentityExtensionRegistry();
  for (const extension of extensions) registry.register(extension);
  return registry;
}
