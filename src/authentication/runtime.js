import { createIdentityExtensionRegistry } from './registry.js';
import { createLdapExtension } from '../federation/ldap.js';
import { createOidcFederationExtension } from '../federation/oidc.js';
import { createSamlFederationExtension } from '../federation/saml-broker.js';
import { createAdapterSamlReplayCache } from '../federation/saml-replay-cache.js';
import { createAdapterFederationStateStore } from '../federation/state-store.js';
import {
  MemoryFederatedIdentityRepository,
  PostgresFederatedIdentityRepository,
} from '../repositories/federated-identity-repository.js';
import { PostgresScimRepository } from '../repositories/scim-repository.js';
import { createScimExtension } from '../scim/extension.js';
import { createScimTokenAuthenticator } from '../scim/config.js';

function anyEnabled(byRealm) {
  return Object.values(byRealm).some((entries) => entries.length > 0);
}

export function createIdentityRuntime({ config, data, store, disabledPasswordHash, logger, fetch }) {
  const stateStore = createAdapterFederationStateStore(data.adapterFor);
  const federatedIdentities = data.pool
    ? new PostgresFederatedIdentityRepository(data.pool, { disabledPasswordHash })
    : new MemoryFederatedIdentityRepository(store, { disabledPasswordHash });
  const ldap = createLdapExtension({ providersByRealm: config.ldapProvidersByRealm, logger });
  const oidc = createOidcFederationExtension({
    providersByRealm: config.oidcProvidersByRealm,
    stateStore,
    fetch,
  });
  const saml = createSamlFederationExtension({
    providersByRealm: config.samlProvidersByRealm,
    replayCacheFor: (realm) => createAdapterSamlReplayCache(data.adapterFor(realm)),
  });
  let scimRepository = null;
  if (anyEnabled(config.scimTokensByRealm)) {
    if (!data.pool) throw new Error('SCIM provisioning requires PostgreSQL, including in development mode');
    scimRepository = new PostgresScimRepository(data.pool, {
      hashPassword: async (password) => {
        const { hashPassword } = await import('../crypto/password.js');
        return hashPassword(password, config.passwordPepper);
      },
      disabledPasswordHash,
    });
  }
  const scim = createScimExtension({
    enabledFor: (realm) => (config.scimTokensByRealm[realm]?.length ?? 0) > 0,
  });
  const registry = createIdentityExtensionRegistry([ldap, oidc, saml, scim]);

  // Construct every SAML broker at startup so invalid keys, certificates, or
  // endpoints fail readiness instead of surfacing on the first login.
  for (const [realm, configured] of Object.entries(config.samlProvidersByRealm)) {
    for (const provider of configured) saml.implementation.metadataFor(realm, provider.id);
  }

  return Object.freeze({
    registry,
    stateStore,
    federatedIdentities,
    scimRepository,
    scimAuthenticate: createScimTokenAuthenticator(config.scimTokensByRealm),
    ldap,
    oidc,
    saml,
    scim,
    federationEntriesFor(realm) {
      return registry.forRealm('federation', realm);
    },
  });
}
