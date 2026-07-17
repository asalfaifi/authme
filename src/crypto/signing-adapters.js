const externalProviders = new Set(['aws-kms', 'gcp-kms', 'azure-key-vault', 'pkcs11']);

function adapterContract(adapter, provider) {
  if (!adapter || typeof adapter !== 'object'
    || typeof adapter.loadJwks !== 'function'
    || typeof adapter.sign !== 'function'
    || typeof adapter.rotate !== 'function') {
    throw new TypeError(`Signing adapter module for ${provider} must provide loadJwks, sign, and rotate methods`);
  }
  return adapter;
}

export async function loadSigningKeyAdapters(config, importer = (specifier) => import(specifier)) {
  const required = new Set(Object.values(config.signingKeyProvidersByRealm)
    .map(({ provider }) => provider)
    .filter((provider) => externalProviders.has(provider)));
  const adapters = new Map();
  for (const provider of required) {
    const specifier = config.signingAdapterModules?.[provider];
    if (!specifier) throw new Error(`AUTHME_SIGNING_ADAPTER_MODULES_JSON must configure a module for ${provider}`);
    let loaded;
    try {
      loaded = await importer(specifier);
    } catch (error) {
      throw new Error(`Unable to load signing adapter module for ${provider}`, { cause: error });
    }
    const exported = loaded.createSigningAdapter ?? loaded.default;
    const policies = Object.fromEntries(Object.entries(config.signingKeyProvidersByRealm)
      .filter(([, policy]) => policy.provider === provider));
    const adapter = typeof exported === 'function'
      ? await exported({ provider, policies: structuredClone(policies) })
      : exported;
    adapters.set(provider, adapterContract(adapter, provider));
  }
  return adapters;
}
