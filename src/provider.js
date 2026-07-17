import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import Provider, { errors, ExternalSigningKey, interactionPolicy } from 'oidc-provider';
import {
  grantType as cibaGrantType,
  handler as cibaGrantHandler,
  parameters as cibaGrantParameters,
} from 'oidc-provider/lib/actions/grants/ciba.js';
import { DEFAULTS as oidcClientMetadataDefaults } from 'oidc-provider/lib/consts/client_attributes.js';
import oidcInstance from 'oidc-provider/lib/helpers/weak_cache.js';
import { authenticationSatisfiesFlow } from './authentication/flow-policy.js';
import { issuerFor } from './config.js';
import { createMtlsFeatureConfiguration } from './security/mtls.js';
import {
  renderDeviceConfirmation,
  renderDeviceInput,
  renderDeviceSuccess,
  renderError as renderUiError,
  renderLogoutConfirmation,
  renderLogoutSuccess,
} from './ui/render.js';
import { SAML_IDP_BRIDGE_CLIENT_ID } from './federation/saml-idp.js';
import { applyClaimMappers, expandCompositeRoles } from './repositories/management-store.js';

// oidc-provider 9.9.1 otherwise defaults every client to signed JWT introspection responses.
delete oidcClientMetadataDefaults.introspection_signed_response_alg;

const keycloakRoutes = Object.freeze({
  authorization: '/protocol/openid-connect/auth',
  backchannel_authentication: '/protocol/openid-connect/ext/ciba/auth',
  challenge: '/protocol/openid-connect/challenge',
  code_verification: '/device',
  device_authorization: '/protocol/openid-connect/auth/device',
  end_session: '/protocol/openid-connect/logout',
  introspection: '/protocol/openid-connect/token/introspect',
  jwks: '/protocol/openid-connect/certs',
  pushed_authorization_request: '/protocol/openid-connect/ext/par/request',
  registration: '/clients-registrations/openid-connect',
  revocation: '/protocol/openid-connect/revoke',
  token: '/protocol/openid-connect/token',
  userinfo: '/protocol/openid-connect/userinfo',
});

const baseClientAuthMethods = Object.freeze([
  'client_secret_basic',
  'private_key_jwt',
  'client_secret_jwt',
  'none',
]);
const mtlsClientAuthMethods = Object.freeze([
  'tls_client_auth',
  'self_signed_tls_client_auth',
]);
const clientAuthMethods = Object.freeze([...baseClientAuthMethods, ...mtlsClientAuthMethods]);
const privateKeyJwtSigningAlgorithms = Object.freeze(['RS256', 'ES256', 'PS256']);
const clientSecretJwtSigningAlgorithms = Object.freeze(['HS256']);
const clientAuthSigningAlgorithms = Object.freeze([
  ...privateKeyJwtSigningAlgorithms,
  ...clientSecretJwtSigningAlgorithms,
]);
const privateJwkMembers = Object.freeze(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv']);
const clientAssertionClockSkew = 60;
const clientAssertionMaxLifetime = 300;
const cibaRequestTtl = 600;
const cibaProductionPollInterval = 5;
const cibaDevelopmentPollInterval = 1;
const cibaGrant = 'urn:openid:params:grant-type:ciba';
const fapiProfile = '2.0';
const fapiClientAuthMethods = Object.freeze([
  'private_key_jwt',
  'tls_client_auth',
  'self_signed_tls_client_auth',
]);
const fapiSigningAlgorithms = Object.freeze(['PS256', 'ES256']);
const fapiAuthorizationCodeTtl = 60;

export const ADMIN_CONSOLE_CLIENT_ID = 'authme-admin-console';
export const ACCOUNT_CONSOLE_CLIENT_ID = 'authme-account-console';

const REQUEST_OBJECT_SIGNING_ALGORITHMS = Object.freeze(['RS256', 'PS256', 'ES256']);

function applyFapiClientProfile(metadata) {
  if (metadata.fapi_profile === undefined) return;
  if (metadata.fapi_profile !== fapiProfile) {
    throw new Error(`fapi_profile must be ${fapiProfile} when provided`);
  }

  if (metadata.token_endpoint_auth_method === 'private_key_jwt') {
    metadata.token_endpoint_auth_signing_alg ??= metadata.request_object_signing_alg ?? 'PS256';
  }

  const grantTypes = metadata.grant_types ?? ['authorization_code'];
  if (grantTypes.includes('authorization_code')) {
    metadata.request_object_signing_alg ??= metadata.token_endpoint_auth_signing_alg ?? 'PS256';
    metadata.authorization_signed_response_alg ??= 'PS256';
    metadata.id_token_signed_response_alg ??= 'PS256';
    metadata.require_pushed_authorization_requests = true;
    metadata.require_signed_request_object = true;
    metadata.response_modes ??= ['jwt'];
  }
}

function validateFapiClientSecurity(metadata, { mtlsEnabled = true } = {}) {
  if (metadata.fapi_profile === undefined) return;
  if (metadata.fapi_profile !== fapiProfile) {
    throw new Error(`fapi_profile must be ${fapiProfile} when provided`);
  }

  const method = metadata.token_endpoint_auth_method ?? 'client_secret_basic';
  if (!fapiClientAuthMethods.includes(method)) {
    throw new Error('FAPI 2.0 clients must use private_key_jwt or mutual-TLS client authentication');
  }
  if (method === 'private_key_jwt'
    && !fapiSigningAlgorithms.includes(metadata.token_endpoint_auth_signing_alg)) {
    throw new Error('FAPI 2.0 private_key_jwt clients must use PS256 or ES256');
  }

  const dpopBound = metadata.dpop_bound_access_tokens === true;
  const mtlsBound = metadata.tls_client_certificate_bound_access_tokens === true;
  if (dpopBound === mtlsBound) {
    throw new Error('FAPI 2.0 clients must require exactly one DPoP or mutual-TLS sender-constrained access-token mechanism');
  }
  if (mtlsBound && !mtlsEnabled) {
    throw new Error('FAPI 2.0 mutual-TLS sender-constrained access tokens require mTLS proxy configuration');
  }

  const grantTypes = metadata.grant_types ?? ['authorization_code'];
  if (grantTypes.length !== 1 || grantTypes[0] !== 'authorization_code') {
    throw new Error('AuthMe FAPI 2.0 clients must use only the authorization_code grant');
  }
  if (!fapiSigningAlgorithms.includes(metadata.request_object_signing_alg)) {
    throw new Error('FAPI 2.0 authorization-code clients must sign Request Objects with PS256 or ES256');
  }
  if (!fapiSigningAlgorithms.includes(metadata.authorization_signed_response_alg)) {
    throw new Error('FAPI 2.0 authorization-code clients must use PS256 or ES256 JARM responses');
  }
  if (!fapiSigningAlgorithms.includes(metadata.id_token_signed_response_alg)) {
    throw new Error('FAPI 2.0 authorization-code clients must sign ID Tokens with PS256 or ES256');
  }
  if (!Array.isArray(metadata.response_modes)
    || metadata.response_modes.length === 0
    || metadata.response_modes.some((mode) => mode !== 'jwt')) {
    throw new Error('FAPI 2.0 authorization-code clients must use response_mode jwt');
  }
}

function adminConsoleClient(config) {
  return {
    client_id: ADMIN_CONSOLE_CLIENT_ID,
    client_name: 'AuthMe administration console',
    token_endpoint_auth_method: 'none',
    redirect_uris: [`${config.publicUrl}/admin/oidc/callback`],
    post_logout_redirect_uris: [`${config.publicUrl}/admin/`],
    web_origins: [config.publicUrl],
    response_types: ['code'],
    grant_types: ['authorization_code'],
    application_type: 'web',
    subject_type: 'public',
    scope: 'openid profile email roles',
  };
}

function samlIdpBridgeClient(config, realm) {
  const endpoint = `${config.publicUrl}/realms/${realm}/protocol/saml`;
  return {
    client_id: SAML_IDP_BRIDGE_CLIENT_ID,
    client_name: 'AuthMe SAML identity provider',
    token_endpoint_auth_method: 'none',
    redirect_uris: [`${endpoint}/continue`],
    post_logout_redirect_uris: [`${endpoint}/logout/continue`],
    response_types: ['code'],
    grant_types: ['authorization_code'],
    application_type: 'web',
    subject_type: 'public',
    scope: 'openid',
  };
}

function accountConsoleClient(config, realm) {
  return {
    client_id: ACCOUNT_CONSOLE_CLIENT_ID,
    client_name: 'AuthMe account console',
    token_endpoint_auth_method: 'none',
    redirect_uris: [`${config.publicUrl}/realms/${realm}/account/oidc/callback`],
    post_logout_redirect_uris: [`${config.publicUrl}/realms/${realm}/account/`],
    web_origins: [config.publicUrl],
    response_types: ['code'],
    grant_types: ['authorization_code'],
    application_type: 'web',
    subject_type: 'public',
    scope: 'openid profile email',
  };
}

function developmentClients(realm) {
  return [{
    client_id: 'authme-dev',
    client_name: 'AuthMe development client',
    client_secret: 'authme-dev-secret-change-me',
    token_endpoint_auth_method: 'client_secret_basic',
    redirect_uris: ['http://127.0.0.1:3001/callback'],
    post_logout_redirect_uris: ['http://127.0.0.1:3001/'],
    web_origins: ['http://127.0.0.1:3001'],
    response_types: ['code'],
    grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
    application_type: 'web',
    scope: 'openid profile email roles groups offline_access',
  }, {
    client_id: 'authme-dev-service',
    client_name: 'AuthMe development service',
    client_secret: 'authme-dev-service-secret-change-me',
    token_endpoint_auth_method: 'client_secret_basic',
    redirect_uris: [],
    response_types: [],
    grant_types: ['client_credentials'],
  }];
}

export function configuredClientsForRealm(config, realm) {
  const clients = structuredClone(config.clientsByRealm[realm] ?? []);
  const reserved = [ADMIN_CONSOLE_CLIENT_ID, ACCOUNT_CONSOLE_CLIENT_ID, SAML_IDP_BRIDGE_CLIENT_ID]
    .find((clientId) => clients.some((client) => client.client_id === clientId));
  if (reserved) {
    throw new Error(`${reserved} is reserved for a built-in AuthMe client`);
  }
  if (config.devMode && clients.length === 0) clients.push(...developmentClients(realm));
  clients.push(adminConsoleClient(config), accountConsoleClient(config, realm));
  if (config.samlIdentityProvidersByRealm?.[realm]) clients.push(samlIdpBridgeClient(config, realm));
  return clients;
}

export function corsAllowed(origin, client) {
  return Array.isArray(client.web_origins) && client.web_origins.includes(origin);
}

function accountClaims(user) {
  const resourceAccess = Object.fromEntries(Object.entries(user.clientRoles ?? {})
    .filter(([, roles]) => Array.isArray(roles) && roles.length)
    .map(([clientId, roles]) => [clientId, { roles: [...roles] }]));
  return {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    preferred_username: user.username,
    name: user.name,
    given_name: user.givenName,
    family_name: user.familyName,
    groups: user.groups,
    realm_access: { roles: user.roles },
    resource_access: resourceAccess,
  };
}

function normalizedAudience(value) {
  try { return new URL(value).href; } catch { return undefined; }
}

export function pairwiseSubjectIdentifier(subjectSalt, realm, accountId, sector) {
  return createHmac('sha256', subjectSalt)
    .update(`${realm}\u0000${accountId}\u0000${sector}`)
    .digest('base64url');
}

export function findConfiguredResourceServer(resourceServers, audience) {
  const normalized = normalizedAudience(audience);
  if (!normalized) return undefined;
  return resourceServers.find((resourceServer) => resourceServer.audience === normalized);
}

function multiResourceRequestAllowed(ctx, resourceServers, clientId) {
  const requested = ctx.oidc.params.resource;
  if (!Array.isArray(requested)) return true;
  const audiences = [...new Set(requested.map(normalizedAudience).filter(Boolean))];
  if (audiences.length <= 1) return true;
  return audiences.every((audience) => {
    const resourceServer = findConfiguredResourceServer(resourceServers, audience);
    return resourceServer?.authorizedClientIds.includes(clientId)
      && resourceServer.multiResourceClientIds.includes(clientId);
  });
}

export function resourceTokenClaims(resourceServer, user, scopes) {
  if (!resourceServer || !user) return undefined;
  const granted = scopes instanceof Set ? scopes : new Set(String(scopes ?? '').split(' ').filter(Boolean));
  const claims = {};
  if (granted.has('roles')) {
    if (resourceServer.includeRealmRoles) claims.realm_access = { roles: [...user.roles] };
    const resourceAccess = {};
    for (const clientId of resourceServer.roleClientIds) {
      const roles = user.clientRoles?.[clientId];
      if (Array.isArray(roles) && roles.length) resourceAccess[clientId] = { roles: [...roles] };
    }
    if (Object.keys(resourceAccess).length) claims.resource_access = resourceAccess;
  }
  if (granted.has('groups') && resourceServer.includeGroups) claims.groups = [...user.groups];
  return Object.keys(claims).length ? claims : undefined;
}

export function clientCanIntrospectToken(resourceServers, clientId, token, clientAuthMethod) {
  if (token.clientId === clientId) return true;
  if (clientAuthMethod === 'none') return false;
  const audiences = Array.isArray(token.aud) ? token.aud : [token.aud];
  return audiences.some((audience) => {
    const resourceServer = findConfiguredResourceServer(resourceServers, audience);
    return resourceServer?.introspectionClientIds.includes(clientId);
  });
}

function secureUiResponse(ctx) {
  ctx.type = 'html';
  ctx.set('Cache-Control', 'no-store');
  ctx.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  ctx.set('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()');
}

function isLoopback(hostname) {
  return hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

function isPrivateOrLoopbackAddress(hostname) {
  const address = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const name = address.endsWith('.') ? address.slice(0, -1) : address;
  if (name === 'localhost' || name.endsWith('.localhost')) return true;

  const version = isIP(address);
  if (version === 4) {
    const [first, second] = address.split('.').map(Number);
    return first === 10
      || first === 127
      || (first === 169 && second === 254)
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168);
  }
  if (version === 6) {
    if (address === '::' || address === '::1') return true;
    const first = Number.parseInt(address.split(':', 1)[0], 16);
    if ((first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80) return true;
    if (address.startsWith('::ffff:')) {
      const [high, low] = address.slice(7).split(':').map((part) => Number.parseInt(part, 16));
      return isPrivateOrLoopbackAddress(`${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`);
    }
  }
  return false;
}

function validateClientJwks(metadata) {
  for (const key of metadata.jwks?.keys ?? []) {
    if (!key || typeof key !== 'object') continue;
    const privateMember = privateJwkMembers.find((member) => Object.hasOwn(key, member));
    if (privateMember) throw new Error(`jwks must not contain private key material (${privateMember})`);
  }

  if (!metadata.jwks_uri) return;
  let url;
  try {
    url = new URL(metadata.jwks_uri);
  } catch {
    throw new Error('jwks_uri must be a valid URL');
  }
  if (url.protocol !== 'https:') throw new Error('jwks_uri must use HTTPS');
  if (url.username || url.password || url.hash) throw new Error('jwks_uri cannot contain credentials or a fragment');
  if (isPrivateOrLoopbackAddress(url.hostname)) {
    throw new Error('jwks_uri must not target a private, loopback, or link-local address');
  }
}

function validateWebOrigins(metadata, { development = false } = {}) {
  const origins = metadata.web_origins;
  if (origins === undefined) return;
  if (!Array.isArray(origins)) throw new Error('web_origins must be an array');
  const unique = new Set();
  for (const origin of origins) {
    if (typeof origin !== 'string') throw new Error('web_origins entries must be strings');
    let url;
    try {
      url = new URL(origin);
    } catch {
      throw new Error('web_origins entries must be valid origins');
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== origin) {
      throw new Error('web_origins entries must be exact HTTP(S) origins without a path, query, fragment, credentials, or wildcard');
    }
    if (!development && url.protocol !== 'https:') {
      throw new Error('web_origins entries must use HTTPS in production');
    }
    if (unique.has(origin)) throw new Error('web_origins entries must be unique');
    unique.add(origin);
  }
}

function validateInlineClientJwks(metadata) {
  if (metadata.jwks === undefined) return;
  if (!metadata.jwks || !Array.isArray(metadata.jwks.keys)) {
    throw new Error('jwks must be a JSON Web Key Set');
  }
  for (const key of metadata.jwks.keys) {
    if (!key || Array.isArray(key) || typeof key !== 'object') {
      throw new Error('jwks keys must be JSON Web Keys');
    }
    if (key.kty === 'oct') {
      throw new Error('inline jwks must contain public keys only');
    }
  }
}

function validateClientSecurity(metadata, { development = false, mtlsEnabled = true } = {}) {
  applyFapiClientProfile(metadata);
  const grantTypes = metadata.grant_types ?? ['authorization_code'];
  if (grantTypes.some((type) => type === 'implicit' || type === 'password')) {
    throw new Error('Implicit and password grants are not supported');
  }
  const method = metadata.token_endpoint_auth_method ?? 'client_secret_basic';
  if (!clientAuthMethods.includes(method)) {
    throw new Error(`Unsupported token endpoint authentication method: ${method}`);
  }
  if (!mtlsEnabled && mtlsClientAuthMethods.includes(method)) {
    throw new Error(`Token endpoint authentication method ${method} requires mTLS proxy configuration`);
  }
  if (metadata.token_endpoint_auth_signing_alg !== undefined) {
    const allowed = method === 'private_key_jwt'
      ? privateKeyJwtSigningAlgorithms
      : method === 'client_secret_jwt' ? clientSecretJwtSigningAlgorithms : [];
    if (!allowed.includes(metadata.token_endpoint_auth_signing_alg)) {
      throw new Error(`Unsupported token endpoint authentication signing algorithm: ${metadata.token_endpoint_auth_signing_alg}`);
    }
  }
  if (metadata.subject_type !== undefined && !['public', 'pairwise'].includes(metadata.subject_type)) {
    throw new Error(`Unsupported subject type: ${metadata.subject_type}`);
  }
  if (grantTypes.includes(cibaGrant)) {
    if (method === 'none') throw new Error('CIBA requires confidential client authentication');
    if (metadata.backchannel_token_delivery_mode !== 'poll') {
      throw new Error('CIBA clients must use poll backchannel token delivery mode');
    }
    if (metadata.backchannel_user_code_parameter === true) {
      throw new Error('CIBA user codes are not supported');
    }
  }
  if (metadata.request_object_signing_alg !== undefined
    && !REQUEST_OBJECT_SIGNING_ALGORITHMS.includes(metadata.request_object_signing_alg)) {
    throw new Error(`Unsupported request object signing algorithm: ${metadata.request_object_signing_alg}`);
  }
  validateInlineClientJwks(metadata);
  validateClientJwks(metadata);
  validateWebOrigins(metadata, { development });
  if (!development) {
    for (const field of ['redirect_uris', 'post_logout_redirect_uris']) {
      for (const value of metadata[field] ?? []) {
        const url = new URL(value);
        const nativeLoopback = metadata.application_type === 'native' && url.protocol === 'http:' && isLoopback(url.hostname);
        if (url.protocol !== 'https:' && !nativeLoopback) throw new Error(`${field} must use HTTPS except for native loopback clients`);
        if (url.username || url.password || url.hash) throw new Error(`${field} entries cannot contain credentials or fragments`);
      }
    }
    for (const field of ['sector_identifier_uri', 'backchannel_logout_uri', 'frontchannel_logout_uri']) {
      if (!metadata[field]) continue;
      const url = new URL(metadata[field]);
      if (url.protocol !== 'https:') throw new Error(`${field} must use HTTPS`);
      if (url.username || url.password || url.hash) throw new Error(`${field} cannot contain credentials or a fragment`);
    }
    if (method.startsWith('client_secret') && Buffer.byteLength(metadata.client_secret ?? '') < 32) {
      throw new Error('Confidential client secrets must contain at least 32 bytes');
    }
  }
  validateFapiClientSecurity(metadata, { mtlsEnabled });
}

export async function createRealmProvider({ realm, config, store, data, management, Adapter, jwks, logger, auditWriter }) {
  const issuer = issuerFor(config, realm);
  const clientAssertionAudiences = new Set([
    issuer,
    `${issuer}${keycloakRoutes.token}`,
  ]);
  const cibaClientAssertionAudience = `${issuer}${keycloakRoutes.backchannel_authentication}`;
  const cibaPollInterval = config.devMode ? cibaDevelopmentPollInterval : cibaProductionPollInterval;
  const organizationContextAdapter = new Adapter('AuthMeOrganizationContext');
  const resourceServers = config.resourceServersByRealm[realm];
  const clients = configuredClientsForRealm(config, realm);
  const mtls = createMtlsFeatureConfiguration(config);
  const enabledClientAuthMethods = config.mtls.enabled ? clientAuthMethods : baseClientAuthMethods;
  const configuredFlows = management ? await management.listAuthenticationFlows(realm) : [];
  const configuredClientScopes = management ? await management.listClientScopes(realm) : [];
  const baseAcrValues = ['urn:authme:loa:1', 'urn:authme:loa:2'];
  const baseScopes = [
    'openid', 'offline_access', 'profile', 'email', 'phone', 'address', 'roles', 'groups', 'organization',
  ];
  const supportedAcrValues = [...new Set([
    ...baseAcrValues,
    ...configuredFlows.filter((flow) => flow.enabled).map((flow) => flow.acr),
  ])];
  const policy = interactionPolicy.base();
  if (management) {
    policy.get('login').checks.add(new interactionPolicy.Check(
      'authme_authentication_flow',
      'the configured authentication flow has not been satisfied',
      async (ctx) => {
        const accountId = ctx.oidc.session?.accountId;
        const organizationContext = ctx.oidc.params.organization;
        if (accountId && organizationContext) {
          const organizations = await management.listUserOrganizations(realm, accountId);
          const authorized = organizations.some((organization) => (
            organization.id === organizationContext || organization.alias === organizationContext
          ));
          if (!authorized) return interactionPolicy.Check.REQUEST_PROMPT;
        }
        const requestedAcrs = String(ctx.oidc.params.acr_values ?? '').split(' ').filter(Boolean);
        const flow = await management.resolveAuthenticationFlow(realm, {
          clientId: ctx.oidc.client?.clientId,
          requestedAcrs,
        });
        if (!flow || !accountId) return interactionPolicy.Check.NO_NEED_TO_PROMPT;
        if (ctx.oidc.session.acr !== flow.acr) return interactionPolicy.Check.REQUEST_PROMPT;
        const user = await store.findUserById(realm, accountId);
        if (!user?.enabled || !authenticationSatisfiesFlow(flow, ctx.oidc.session.amr, user)) {
          return interactionPolicy.Check.REQUEST_PROMPT;
        }
        if (flow.maxAgeSeconds && ctx.oidc.session.past(flow.maxAgeSeconds)) {
          return interactionPolicy.Check.REQUEST_PROMPT;
        }
        return interactionPolicy.Check.NO_NEED_TO_PROMPT;
      },
      ({ oidc }) => ({
        acr: oidc.session?.acr,
        clientId: oidc.client?.clientId,
        organization: oidc.params.organization,
      }),
    ));
  }
  let cibaAuthenticationDeviceHandler;
  for (const client of clients) {
    validateClientSecurity(client, { development: config.devMode, mtlsEnabled: config.mtls.enabled });
  }

  function cibaRequestedAcrs(request) {
    return String(request.params?.acr_values ?? '').split(' ').filter(Boolean);
  }

  async function cibaAuthenticationFlow(request) {
    if (!management) return undefined;
    return management.resolveAuthenticationFlow(realm, {
      clientId: request.clientId,
      requestedAcrs: cibaRequestedAcrs(request),
    });
  }

  function publicCibaAuthenticationFlow(flow) {
    if (!flow) return null;
    return Object.freeze({
      alias: flow.alias,
      acr: flow.acr,
      maxAgeSeconds: flow.maxAgeSeconds,
      steps: Object.freeze(flow.steps.map((step) => Object.freeze({ ...step }))),
    });
  }

  async function managedIdentityClaims(user, clientId, organizationContext, grantedScopes = []) {
    if (!management) return accountClaims(user);
    const scopeNames = grantedScopes instanceof Set
      ? [...grantedScopes]
      : String(grantedScopes ?? '').split(' ').filter(Boolean);
    const clientRoleIds = Object.keys(user.clientRoles ?? {});
    const [roles, groups, organizations, mappers, clientRoleDefinitions] = await Promise.all([
      management.listRoles(realm),
      management.listGroups(realm),
      management.listUserOrganizations(realm, user.id),
      clientId ? management.effectiveClaimMappers(realm, clientId, scopeNames) : [],
      Promise.all(clientRoleIds.map(async (roleClientId) => [
        roleClientId,
        await management.listClientRoles(realm, roleClientId),
      ])),
    ]);
    const groupRoles = groups
      .filter((group) => user.groups?.includes(group.path))
      .flatMap((group) => group.roles);
    const contextualOrganizations = organizationContext
      ? organizations.filter((organization) => organization.id === organizationContext || organization.alias === organizationContext)
      : organizations;
    if (organizationContext && contextualOrganizations.length === 0) {
      throw new errors.AccessDenied('The account is no longer a member of the requested organization');
    }
    const expandedRoles = expandCompositeRoles([...(user.roles ?? []), ...groupRoles], roles);
    const definitionsByClient = new Map(clientRoleDefinitions);
    const expandedClientRoles = Object.fromEntries(clientRoleIds.map((roleClientId) => [
      roleClientId,
      expandCompositeRoles(user.clientRoles[roleClientId], definitionsByClient.get(roleClientId) ?? []),
    ]));
    const enriched = { ...user, roles: expandedRoles, clientRoles: expandedClientRoles };
    return {
      ...accountClaims(enriched),
      organizations: contextualOrganizations.map((organization) => ({
        id: organization.id,
        alias: organization.alias,
        name: organization.name,
        roles: organization.roles,
      })),
      ...applyClaimMappers({ user: enriched, organizations: contextualOrganizations, mappers }),
    };
  }

  async function organizationContextFor(ctx, token) {
    if (ctx?.oidc?.params?.organization) return ctx.oidc.params.organization;
    const grantId = token?.grantId
      ?? ctx?.oidc?.entities?.AuthorizationCode?.grantId
      ?? ctx?.oidc?.entities?.RefreshToken?.grantId
      ?? ctx?.oidc?.entities?.AccessToken?.grantId;
    if (!grantId) return undefined;
    return (await organizationContextAdapter.find(grantId))?.organizationId;
  }

  async function secureRegistrationPolicy(ctx, properties) {
    if (ctx.oidc.client?.fapi_profile === fapiProfile
      && properties.fapi_profile !== fapiProfile) {
      throw new errors.InvalidClientMetadata('FAPI 2.0 clients cannot remove their fapi_profile');
    }
    try {
      validateClientSecurity(properties, { development: config.devMode, mtlsEnabled: config.mtls.enabled });
    } catch (error) {
      throw new errors.InvalidClientMetadata(error.message);
    }
    const initialToken = ctx.oidc.entities.InitialAccessToken;
    if (initialToken) {
      const claimed = await data.claimInitialAccessToken(realm, initialToken.jti);
      if (!claimed) throw new errors.InvalidToken('initial access token was already used');
      await initialToken.destroy();
    }
  }

  const provider = new Provider(issuer, {
    adapter: Adapter,
    clients,
    jwks,
    routes: keycloakRoutes,
    extraParams: ['organization'],
    acrValues: supportedAcrValues,
    scopes: [...new Set([
      ...baseScopes,
      ...configuredClientScopes.map((scope) => scope.name),
    ])],
    responseTypes: ['code'],
    clientAuthMethods: enabledClientAuthMethods,
    enabledJWA: {
      clientAuthSigningAlgValues: clientAuthSigningAlgorithms,
      requestObjectSigningAlgValues: [...REQUEST_OBJECT_SIGNING_ALGORITHMS],
    },
    async loadExistingGrant(ctx) {
      const grantId = ctx.oidc.result?.consent?.grantId
        || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);
      if (ctx.oidc.params.organization && !ctx.oidc.result?.consent?.grantId) return undefined;
      if (grantId) return ctx.oidc.provider.Grant.find(grantId);
      if (ctx.oidc.client.clientId !== SAML_IDP_BRIDGE_CLIENT_ID || !ctx.oidc.session.accountId) {
        return undefined;
      }
      const grant = new ctx.oidc.provider.Grant({
        accountId: ctx.oidc.session.accountId,
        clientId: SAML_IDP_BRIDGE_CLIENT_ID,
      });
      grant.addOIDCScope('openid');
      await grant.save();
      return grant;
    },
    async assertJwtClientAuthClaimsAndHeader(ctx, claims, _header, client) {
      const validAudience = client?.fapi_profile === fapiProfile
        ? claims.aud === issuer
        : typeof claims.aud === 'string'
          && (clientAssertionAudiences.has(claims.aud)
            || (ctx.oidc.route === 'backchannel_authentication' && claims.aud === cibaClientAssertionAudience));
      if (!validAudience) {
        throw new errors.InvalidClientAuth('audience (aud) is not accepted for this endpoint');
      }
      if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) {
        throw new errors.InvalidClientAuth('issued at (iat) must be provided as a NumericDate');
      }
      const now = Math.floor(Date.now() / 1000);
      if (Math.abs(now - claims.iat) > clientAssertionClockSkew) {
        throw new errors.InvalidClientAuth(`issued at (iat) must be within ${clientAssertionClockSkew} seconds of the current time`);
      }
      if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)
        || claims.exp - claims.iat > clientAssertionMaxLifetime) {
        throw new errors.InvalidClientAuth(`client assertion lifetime (exp - iat) must not exceed ${clientAssertionMaxLifetime} seconds`);
      }
    },
    subjectTypes: ['public', 'pairwise'],
    extraClientMetadata: {
      properties: ['web_origins', 'fapi_profile'],
      validator(_ctx, key, _value, metadata) {
        try {
          if (key === 'web_origins') validateWebOrigins(metadata, { development: config.devMode });
          if (key === 'fapi_profile') {
            applyFapiClientProfile(metadata);
            validateFapiClientSecurity(metadata, { mtlsEnabled: config.mtls.enabled });
          }
        } catch (error) {
          metadata.invalidate(error.message);
        }
      },
    },
    claims: {
      address: ['address'],
      email: ['email', 'email_verified'],
      phone: ['phone_number', 'phone_number_verified'],
      profile: ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'],
      roles: ['realm_access', 'resource_access'],
      groups: ['groups'],
      organization: ['organizations'],
    },
    cookies: {
      keys: [...config.cookieKeys],
      long: { httpOnly: true, sameSite: 'lax', secure: !config.devMode, overwrite: true },
      short: { httpOnly: true, sameSite: 'lax', secure: !config.devMode, overwrite: true },
      names: {
        session: `authme_${realm}_session`,
        interaction: `authme_${realm}_interaction`,
        resume: `authme_${realm}_resume`,
      },
    },
    interactions: {
      policy,
      url(_ctx, interaction) {
        return `/realms/${realm}/interaction/${interaction.uid}`;
      },
    },
    features: {
      backchannelLogout: { enabled: true },
      ciba: {
        enabled: true,
        deliveryModes: ['poll'],
        async processLoginHintToken() {
          return undefined;
        },
        async processLoginHint(_ctx, loginHint) {
          if (typeof loginHint !== 'string' || loginHint.length > 254 || loginHint.trim().length === 0) {
            return undefined;
          }
          const user = await store.findUserByLogin(realm, loginHint);
          const locked = user?.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now();
          return user?.enabled && !locked ? user.id : undefined;
        },
        async verifyUserCode(_ctx, _account, userCode) {
          if (userCode !== undefined) throw new errors.InvalidUserCode('user codes are not supported');
        },
        async validateBindingMessage(_ctx, bindingMessage) {
          if (bindingMessage !== undefined && !/^[a-zA-Z0-9-._+/!?#]{1,20}$/.test(bindingMessage)) {
            throw new errors.InvalidBindingMessage('binding_message must be 1 to 20 basic display characters');
          }
        },
        async validateRequestContext(_ctx, requestContext) {
          if (requestContext !== undefined) throw new errors.InvalidRequest('request_context is not supported');
        },
        async triggerAuthenticationDevice(ctx, request, account, client) {
          ctx.body.interval = cibaPollInterval;
          if (cibaAuthenticationDeviceHandler) {
            const requestedAcrs = cibaRequestedAcrs(request);
            const authenticationFlow = await cibaAuthenticationFlow(request);
            await cibaAuthenticationDeviceHandler(Object.freeze({
              realm,
              authReqId: request.jti,
              accountId: account.accountId,
              clientId: client.clientId,
              bindingMessage: request.params.binding_message,
              expiresAt: request.exp ?? Math.floor(Date.now() / 1000) + request.remainingTTL,
              scopes: Object.freeze(request.scope.split(' ')),
              requestedAcrs: Object.freeze(requestedAcrs),
              authenticationFlow: publicCibaAuthenticationFlow(authenticationFlow),
            }));
          }
        },
      },
      claimsParameter: {
        enabled: true,
        async assertClaimsParameter(_ctx, requestedClaims) {
          const supported = new Set([
            'sub', 'sid', 'auth_time', 'acr', 'amr', 'iss', 'address', 'email', 'email_verified',
            'phone_number', 'phone_number_verified', 'name', 'family_name', 'given_name',
            'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website',
            'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at', 'groups',
            'realm_access', 'resource_access', 'organizations',
          ]);
          const clientId = _ctx.oidc?.client?.clientId;
          const requestedScopes = String(_ctx.oidc?.params?.scope ?? '').split(' ').filter(Boolean);
          for (const mapper of clientId && management
            ? await management.effectiveClaimMappers(realm, clientId, requestedScopes)
            : []) {
            if (typeof mapper.config?.claim === 'string') supported.add(mapper.config.claim);
          }
          for (const section of ['id_token', 'userinfo']) {
            for (const claim of Object.keys(requestedClaims?.[section] ?? {})) {
              if (!supported.has(claim)) throw new errors.InvalidRequest(`unsupported requested claim: ${claim}`);
            }
          }
        },
      },
      clientCredentials: { enabled: true },
      devInteractions: { enabled: false },
      deviceFlow: {
        enabled: true,
        async userCodeInputSource(ctx, form, _out, error) {
          const message = error
            ? 'The device code is invalid, expired, or already used. Check the code and try again.'
            : '';
          secureUiResponse(ctx);
          ctx.body = renderDeviceInput({ realm, form, error: message });
        },
        async userCodeConfirmSource(ctx, form, client, _deviceInfo, userCode) {
          secureUiResponse(ctx);
          ctx.body = renderDeviceConfirmation({
            realm,
            form,
            clientName: client.clientName || client.clientId,
            userCode,
          });
        },
        async successSource(ctx) {
          secureUiResponse(ctx);
          ctx.body = renderDeviceSuccess({
            realm,
            clientName: ctx.oidc.client?.clientName || ctx.oidc.client?.clientId || 'your application',
          });
        },
      },
      dPoP: { enabled: true },
      externalSigningSupport: {
        enabled: jwks.keys.some((key) => key instanceof ExternalSigningKey),
        ack: jwks.keys.some((key) => key instanceof ExternalSigningKey) ? 'experimental-01' : undefined,
      },
      fapi: {
        enabled: true,
        profile(_ctx, client) {
          return client?.fapi_profile === fapiProfile ? fapiProfile : undefined;
        },
      },
      introspection: {
        enabled: true,
        async allowedPolicy(_ctx, client, token) {
          return clientCanIntrospectToken(resourceServers, client.clientId, token, client.clientAuthMethod);
        },
      },
      jwtIntrospection: { enabled: true },
      jwtResponseModes: { enabled: true },
      mTLS: mtls,
      pushedAuthorizationRequests: { enabled: true },
      registration: {
        enabled: config.enableDynamicRegistration,
        initialAccessToken: config.enableDynamicRegistration,
        policies: config.enableDynamicRegistration ? { 'authme-secure-client': secureRegistrationPolicy } : undefined,
      },
      registrationManagement: { enabled: config.enableDynamicRegistration },
      requestObjects: {
        enabled: true,
        async assertJwtClaimsAndHeader(ctx, claims, _header, client) {
          const isFapi = client?.fapi_profile === fapiProfile;
          const isCiba = ctx.oidc.route === 'backchannel_authentication';
          if (!isFapi && !isCiba) return;
          const required = new Set([
            ...(isFapi ? ['exp', 'aud', 'nbf'] : []),
            ...(isCiba ? ['exp', 'iat', 'nbf', 'jti'] : []),
          ]);
          const now = Math.floor(Date.now() / 1000);
          if ([...required].some((claim) => claims[claim] === undefined)
            || !Number.isFinite(claims.exp) || !Number.isFinite(claims.nbf)) {
            throw new errors.InvalidRequestObject('Request Object claims are invalid');
          }
          if (isFapi && (claims.exp <= claims.nbf
            || claims.exp - claims.nbf > 3600
            || now - claims.nbf > 3600 + clientAssertionClockSkew)) {
            throw new errors.InvalidRequestObject('FAPI 2.0 Request Object lifetime is invalid');
          }
          if (isCiba && (typeof claims.jti !== 'string' || claims.jti.length === 0 || claims.jti.length > 256
            || !Number.isFinite(claims.iat)
            || Math.abs(now - claims.iat) > clientAssertionClockSkew
            || claims.exp <= claims.iat || claims.exp - claims.iat > cibaRequestTtl)) {
            throw new errors.InvalidRequestObject('CIBA Request Object claims are invalid');
          }
          if (!isCiba) return;
          const unique = await ctx.oidc.provider.ReplayDetection.unique(
            `ciba-request:${client.clientId}\u0000`,
            claims.jti,
            claims.exp,
          );
          if (!unique) throw new errors.InvalidRequestObject('CIBA Request Object has already been used');
        },
      },
      resourceIndicators: {
        enabled: resourceServers.length > 0,
        async defaultResource(_ctx, _client, grantedResources) {
          if (Array.isArray(grantedResources) && grantedResources.length === 1) {
            return grantedResources[0];
          }
          return grantedResources;
        },
        async useGrantedResource(_ctx, token) {
          return token.resource !== undefined;
        },
        async getResourceServerInfo(ctx, audience, client) {
          const resourceServer = findConfiguredResourceServer(resourceServers, audience);
          if (!resourceServer || !resourceServer.authorizedClientIds.includes(client.clientId)) {
            throw new errors.InvalidTarget('client is not authorized to use the requested resource');
          }
          if (!multiResourceRequestAllowed(ctx, resourceServers, client.clientId)) {
            throw new errors.InvalidTarget('client is not authorized to combine the requested resources');
          }
          return {
            audience: resourceServer.audience,
            scope: resourceServer.scopes.join(' '),
            accessTokenFormat: resourceServer.accessTokenFormat,
          };
        },
      },
      revocation: {
        enabled: true,
        async allowedPolicy(_ctx, client, token) {
          return token.clientId === client.clientId;
        },
      },
      rpInitiatedLogout: {
        enabled: true,
        async logoutSource(ctx, form) {
          secureUiResponse(ctx);
          const client = ctx.oidc.client;
          ctx.body = renderLogoutConfirmation({
            realm,
            form,
            clientName: client?.clientName || client?.clientId || '',
          });
        },
        async postLogoutSuccessSource(ctx) {
          secureUiResponse(ctx);
          const client = ctx.oidc.client;
          ctx.body = renderLogoutSuccess({
            realm,
            clientName: client?.clientName || client?.clientId || '',
          });
        },
      },
      userinfo: { enabled: true },
      jwtUserinfo: { enabled: true },
    },
    ttl: {
      AccessToken: config.accessTokenTtl,
      AuthorizationCode(_ctx, _code, client) {
        return client?.fapi_profile === fapiProfile
          ? Math.min(config.authorizationCodeTtl, fapiAuthorizationCodeTtl)
          : config.authorizationCodeTtl;
      },
      ClientCredentials: config.accessTokenTtl,
      BackchannelAuthenticationRequest: cibaRequestTtl,
      DeviceCode: 600,
      Grant: 14 * 24 * 60 * 60,
      IdToken: config.accessTokenTtl,
      Interaction: 600,
      RefreshToken: 14 * 24 * 60 * 60,
      Session: config.sessionTtl,
    },
    pkce: { required: () => true },
    rotateRefreshToken: true,
    issueRefreshToken(_ctx, client, code) {
      return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
    },
    async findAccount(ctx, id, token) {
      const user = await store.findUserById(realm, id);
      if (!user?.enabled) return undefined;
      const clientId = ctx.oidc?.client?.clientId;
      const organizationContext = await organizationContextFor(ctx, token);
      const grantedScopes = token?.scope ?? ctx.oidc?.entities?.AccessToken?.scope ?? ctx.oidc?.params?.scope;
      return {
        accountId: user.id,
        async claims() {
          return managedIdentityClaims(user, clientId, organizationContext, grantedScopes);
        },
      };
    },
    async extraTokenClaims(ctx, token) {
      if (!token.accountId) return undefined;
      const user = await store.findUserById(realm, token.accountId);
      if (!user?.enabled) return undefined;
      const managedClaims = await managedIdentityClaims(
        user,
        token.clientId ?? ctx?.oidc?.client?.clientId,
        await organizationContextFor(ctx, token),
        token.scopes,
      );
      const customClaims = Object.fromEntries(Object.entries(managedClaims).filter(([name]) => ![
        'sub', 'email', 'email_verified', 'preferred_username', 'name', 'given_name',
        'family_name', 'groups', 'realm_access', 'resource_access', 'organizations',
      ].includes(name)));
      if (token.scopes?.has('organization')) customClaims.organizations = managedClaims.organizations;
      if (token.aud === undefined) return Object.keys(customClaims).length ? customClaims : undefined;
      const audiences = Array.isArray(token.aud) ? token.aud : [token.aud];
      if (audiences.length !== 1) return Object.keys(customClaims).length ? customClaims : undefined;
      const resourceServer = findConfiguredResourceServer(resourceServers, audiences[0]);
      if (!resourceServer) return Object.keys(customClaims).length ? customClaims : undefined;
      const expandedClientRoles = Object.fromEntries(Object.entries(managedClaims.resource_access ?? {}).map(
        ([roleClientId, value]) => [roleClientId, value.roles],
      ));
      return {
        ...resourceTokenClaims(resourceServer, {
          ...user,
          roles: managedClaims.realm_access?.roles ?? [],
          clientRoles: expandedClientRoles,
        }, token.scopes),
        ...customClaims,
      };
    },
    async pairwiseIdentifier(_ctx, accountId, client) {
      const sector = client.sectorIdentifier;
      if (!sector) throw new Error('Pairwise client has no resolved sector identifier');
      return pairwiseSubjectIdentifier(config.subjectSalt, realm, accountId, sector);
    },
    clientBasedCORS(_ctx, origin, client) {
      return corsAllowed(origin, client);
    },
    discovery: {
      service_documentation: 'https://github.com/asalfaifi/authme',
      op_policy_uri: 'https://github.com/asalfaifi/authme/blob/main/SECURITY.md',
    },
    fetchResponseBodyLimits: {
      'client_id metadata document': 5 * 1024,
      jwks_uri: 1024 * 1024,
      sector_identifier_uri: 64 * 1024,
    },
    async fetch(url, options) {
      const target = new URL(url);
      if (target.protocol !== 'https:') throw new Error('External OIDC metadata must use HTTPS');
      if (!options?.dispatcher) throw new Error('External OIDC metadata requires SSRF protection');
      // Redirects are rejected so an accepted HTTPS metadata URI cannot
      // downgrade transport or escape the provider's per-request SSRF checks.
      return globalThis.fetch(target, { ...options, redirect: 'manual' });
    },
    async renderError(ctx, out) {
      secureUiResponse(ctx);
      ctx.body = renderUiError({
        realm,
        title: 'Authorization request failed',
        message: out.error_description || out.error || 'The authorization request could not be completed safely.',
      });
    },
  });

  provider.registerGrantType(cibaGrantType, async (ctx) => {
    const authReqId = ctx.oidc.params.auth_req_id;
    if (typeof authReqId === 'string' && !/^[A-Za-z0-9._-]{20,256}$/.test(authReqId)) {
      throw new errors.InvalidGrant('backchannel authentication request not found');
    }
    if (typeof authReqId === 'string' && authReqId.length > 0) {
      const result = await provider.BackchannelAuthenticationRequest.adapter.checkCibaPoll(
        authReqId,
        ctx.oidc.client.clientId,
        cibaPollInterval,
      );
      if (result.status === 'slow_down') {
        ctx.set('Retry-After', String(result.interval));
        throw new errors.SlowDown();
      }
    }
    return cibaGrantHandler(ctx);
  }, cibaGrantParameters);

  async function completeCiba({ authReqId, accountId, approved, acr, amr, authTime }) {
    if (typeof approved !== 'boolean') throw new TypeError('CIBA completion requires an explicit authorization decision');
    const request = await provider.BackchannelAuthenticationRequest.find(authReqId, { ignoreExpiration: true });
    if (!request || request.isExpired || request.consumed || request.grantId || request.error) {
      throw new errors.InvalidGrant('backchannel authentication request is unavailable');
    }
    if (request.accountId !== accountId) throw new errors.InvalidGrant('backchannel authentication request account mismatch');
    if (!approved) {
      await provider.backchannelResult(request, new errors.AccessDenied('The end-user denied the authentication request'));
      return;
    }
    if (typeof acr !== 'string' || acr.length === 0
      || !Array.isArray(amr) || amr.length === 0 || amr.some((value) => typeof value !== 'string' || value.length === 0)
      || !Number.isSafeInteger(authTime) || authTime < request.iat - clientAssertionClockSkew
      || authTime > Math.floor(Date.now() / 1000) + clientAssertionClockSkew) {
      throw new TypeError('approved CIBA results require valid acr, amr, and authTime authentication evidence');
    }
    const user = await store.findUserById(realm, accountId);
    const locked = user?.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now();
    if (!user?.enabled || locked) throw new errors.AccessDenied('The account cannot authorize this request');
    const requestedAcrs = cibaRequestedAcrs(request);
    const authenticationFlow = await cibaAuthenticationFlow(request);
    const staleAuthentication = authenticationFlow?.maxAgeSeconds !== null
      && authenticationFlow?.maxAgeSeconds !== undefined
      && Math.floor(Date.now() / 1000) - authTime > authenticationFlow.maxAgeSeconds;
    if ((requestedAcrs.length > 0 && !requestedAcrs.includes(acr))
      || (authenticationFlow && (acr !== authenticationFlow.acr
        || !authenticationSatisfiesFlow(authenticationFlow, amr, user)
        || staleAuthentication))) {
      throw new errors.AccessDenied('CIBA authentication evidence does not satisfy the requested authentication flow');
    }

    const grant = new provider.Grant({ accountId, clientId: request.clientId });
    grant.addOIDCScope(request.scope);
    const claimNames = new Set([
      ...Object.keys(request.claims?.id_token ?? {}),
      ...Object.keys(request.claims?.userinfo ?? {}),
    ]);
    if (claimNames.size) grant.addOIDCClaims([...claimNames]);
    for (const audience of Array.isArray(request.resource) ? request.resource : [request.resource]) {
      const resourceServer = audience && findConfiguredResourceServer(resourceServers, audience);
      if (!resourceServer) continue;
      const scopes = request.scope.split(' ').filter((scope) => resourceServer.scopes.includes(scope));
      if (scopes.length) grant.addResourceScope(audience, scopes.join(' '));
    }
    const grantId = await grant.save();
    try {
      await provider.backchannelResult(request, grant, { acr, amr: [...amr], authTime });
    } catch (error) {
      await provider.Grant.adapter.destroy(grantId).catch(() => {});
      throw error;
    }
  }

  Object.defineProperty(provider, 'authmeOrganizationContexts', {
    value: Object.freeze({
      async set(grantId, accountId, requestedOrganization) {
        if (!management || !requestedOrganization) return undefined;
        const organizations = await management.listUserOrganizations(realm, accountId);
        const organization = organizations.find((candidate) => (
          candidate.id === requestedOrganization || candidate.alias === requestedOrganization
        ));
        if (!organization) throw new errors.AccessDenied('The account is not a member of the requested organization');
        await organizationContextAdapter.upsert(grantId, {
          grantId,
          accountId,
          organizationId: organization.id,
        }, 14 * 24 * 60 * 60);
        return organization.id;
      },
      async find(grantId) {
        return organizationContextAdapter.find(grantId);
      },
    }),
  });
  Object.defineProperty(provider, 'authmeManagementMetadata', {
    value: Object.freeze({
      async synchronize() {
        const [flows, clientScopes] = await Promise.all([
          management?.listAuthenticationFlows(realm) ?? [],
          management?.listClientScopes(realm) ?? [],
        ]);
        const configuration = oidcInstance(provider).configuration;
        configuration.acrValues = new Set([
          ...baseAcrValues,
          ...flows.filter((flow) => flow.enabled).map((flow) => flow.acr),
        ]);
        configuration.scopes = new Set([
          ...baseScopes,
          ...clientScopes.map((scope) => scope.name),
        ]);
      },
    }),
  });
  Object.defineProperty(provider, 'authmeCiba', {
    value: Object.freeze({
      complete: completeCiba,
      setAuthenticationDeviceHandler(handler) {
        if (typeof handler !== 'function') throw new TypeError('CIBA authentication-device handler must be a function');
        if (cibaAuthenticationDeviceHandler) throw new Error('CIBA authentication-device handler is already configured');
        cibaAuthenticationDeviceHandler = handler;
      },
      async approveForDevelopment(authReqId) {
        if (!config.devMode) throw new Error('development CIBA approval is disabled');
        const request = await provider.BackchannelAuthenticationRequest.find(authReqId);
        if (!request) throw new errors.InvalidGrant('backchannel authentication request is unavailable');
        await completeCiba({
          authReqId,
          accountId: request.accountId,
          approved: true,
          acr: 'urn:authme:loa:1',
          amr: ['dev-ciba'],
          authTime: Math.floor(Date.now() / 1000),
        });
      },
    }),
  });
  provider.middleware.unshift(async (ctx, next) => {
    if (ctx.method === 'GET' && ctx.path === keycloakRoutes.authorization) {
      const clientId = ctx.query.client_id;
      if (typeof clientId === 'string') {
        const client = await provider.Client.find(clientId).catch(() => undefined);
        if (client?.fapi_profile === fapiProfile) ctx.query.response_mode = 'jwt';
      }
    }
    await next();
  });
  provider.middleware.unshift(async (ctx, next) => {
    await next();
    if (ctx.oidc?.route === 'discovery' && ctx.body) {
      ctx.body.backchannel_user_code_parameter_supported = false;
    }
  });

  provider.proxy = config.trustProxy;
  if (config.trustProxy) provider.maxIpsCount = 1;
  function writeProviderAudit(eventName, { artifact, ctx, error } = {}) {
    const event = {
      realm,
      type: `oidc.${eventName}`,
      subjectId: artifact?.accountId ?? ctx?.oidc?.session?.accountId,
      clientId: artifact?.clientId ?? ctx?.oidc?.client?.clientId,
      ip: ctx?.ip,
      userAgent: ctx?.get?.('user-agent'),
      metadata: error ? { error: error.error ?? error.name ?? 'Error' } : {},
    };
    const options = error ? {
      sampleKey: createHmac('sha256', config.passwordPepper)
        .update(`${realm}\u0000${eventName}\u0000${event.ip ?? 'unknown'}\u0000${event.clientId ?? 'none'}\u0000${event.metadata.error}`)
        .digest('base64url'),
      sampleWindowMs: 10_000,
    } : undefined;
    const outcome = auditWriter.enqueue(event, options);
    logger[error && outcome === 'accepted' ? 'warn' : 'debug'](
      { realm, event: eventName, clientId: event.clientId, err: error, auditOutcome: outcome },
      'OIDC event',
    );
  }

  for (const eventName of [
    'access_token.issued', 'access_token.saved', 'access_token.destroyed',
    'authorization_code.saved', 'authorization_code.consumed',
    'backchannel_authentication_request.saved', 'backchannel_authentication_request.consumed', 'backchannel_authentication_request.destroyed',
    'client_credentials.issued', 'client_credentials.saved', 'client_credentials.destroyed',
    'device_code.saved', 'device_code.consumed', 'device_code.destroyed',
    'initial_access_token.saved', 'initial_access_token.destroyed',
    'refresh_token.saved', 'refresh_token.consumed', 'refresh_token.destroyed',
    'registration_access_token.saved', 'registration_access_token.destroyed',
    'session.destroyed',
  ]) provider.on(eventName, (artifact) => writeProviderAudit(eventName, { artifact }));

  for (const eventName of [
    'authorization.accepted', 'authorization.success', 'backchannel.success',
    'device_authorization.success', 'end_session.success', 'grant.revoked', 'grant.success', 'interaction.ended', 'interaction.started',
    'pushed_authorization_request.success', 'registration_create.success',
    'registration_delete.success', 'registration_update.success',
  ]) {
    provider.on(eventName, (ctx) => writeProviderAudit(eventName, { ctx }));
  }

  for (const eventName of [
    'authorization.error', 'backchannel.error', 'grant.error', 'introspection.error',
    'registration_create.error', 'registration_delete.error', 'registration_read.error',
    'registration_update.error', 'revocation.error', 'server_error', 'userinfo.error',
  ]) provider.on(eventName, (ctx, error) => writeProviderAudit(eventName, { ctx, error }));

  return provider;
}

export { keycloakRoutes };
export { validateClientSecurity };
