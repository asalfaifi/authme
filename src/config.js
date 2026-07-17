import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';
import { parseLdapProviders } from './federation/ldap.js';
import { parseOidcProviders } from './federation/oidc.js';
import { parseSamlIdentityProviders, parseSamlProviders } from './federation/saml-config.js';
import { parseScimTokens } from './scim/config.js';

const booleanValue = z
  .string()
  .optional()
  .transform((value) => ['1', 'true', 'yes', 'on'].includes((value ?? '').toLowerCase()));

const optionalString = z.preprocess(
  (value) => value === '' ? undefined : value,
  z.string().trim().min(1).optional(),
);

const moduleSpecifier = z.preprocess(
  (value) => value === '' ? undefined : value,
  z.string().trim().min(1).max(2048).refine((value) => !/[\r\n\0]/u.test(value), 'module specifier contains invalid characters').optional(),
);

function assertFederationProviderIdsUnique(realms, catalogs) {
  for (const realm of realms) {
    const seen = new Map();
    for (const [kind, providers] of catalogs) {
      for (const provider of providers[realm] ?? []) {
        const existing = seen.get(provider.id);
        if (existing) {
          throw new Error(`Realm ${realm} federation provider id ${provider.id} is duplicated across ${existing} and ${kind}`);
        }
        seen.set(provider.id, kind);
      }
    }
  }
}

const rawSchema = z.object({
  AUTHME_PUBLIC_URL: z.string().url().optional(),
  AUTHME_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  AUTHME_REALMS: z.string().optional(),
  AUTHME_DEV_MODE: booleanValue,
  AUTHME_TRUST_PROXY: booleanValue,
  AUTHME_MTLS_CLIENT_CERT_HEADER: optionalString,
  AUTHME_MTLS_CLIENT_CERT_VERIFIED_HEADER: optionalString,
  AUTHME_MTLS_CLIENT_CERT_VERIFIED_VALUE: optionalString,
  AUTHME_MTLS_TRUSTED_PROXY_CIDRS: optionalString,
  AUTHME_COOKIE_KEYS: z.string().optional(),
  AUTHME_CSRF_SECRET: z.string().optional(),
  AUTHME_PASSWORD_PEPPER: z.string().optional(),
  AUTHME_SUBJECT_SALT: z.string().optional(),
  AUTHME_FIELD_ENCRYPTION_KEY: z.string().optional(),
  AUTHME_ADMIN_TOKEN: z.string().optional(),
  AUTHME_JWKS_DIR: z.string().optional(),
  AUTHME_SIGNING_KEY_PROVIDERS_JSON: z.string().optional(),
  AUTHME_SIGNING_ADAPTER_MODULES_JSON: z.string().optional(),
  AUTHME_ACCOUNT_EMAIL_MODULE: moduleSpecifier,
  AUTHME_CLIENTS_JSON: z.string().optional(),
  AUTHME_RESOURCE_SERVERS_JSON: z.string().optional(),
  AUTHME_LDAP_PROVIDERS_JSON: z.string().optional(),
  AUTHME_OIDC_PROVIDERS_JSON: z.string().optional(),
  AUTHME_SAML_PROVIDERS_JSON: z.string().optional(),
  AUTHME_SAML_IDP_JSON: z.string().optional(),
  AUTHME_SCIM_TOKENS_JSON: z.string().optional(),
  AUTHME_ENABLE_DYNAMIC_REGISTRATION: booleanValue,
  AUTHME_DEV_ADMIN_PASSWORD: z.string().optional(),
  AUTHME_LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).optional(),
  AUTHME_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).optional(),
  AUTHME_AUTHORIZATION_CODE_TTL_SECONDS: z.coerce.number().int().min(30).max(300).optional(),
  AUTHME_SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(2592000).optional(),
  AUTHME_WEBAUTHN_CHALLENGE_TTL_SECONDS: z.coerce.number().int().min(60).max(300).optional(),
  AUTHME_AUDIT_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).optional(),
  DATABASE_URL: z.string().optional(),
  REDIS_URL: z.preprocess((value) => value === '' ? undefined : value, z.string().url().optional()),
});

const httpHeaderName = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const reservedMtlsHeaders = new Set([
  'authorization', 'cookie', 'forwarded', 'host',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
]);

function mtlsHeaderName(value, setting) {
  if (!httpHeaderName.test(value) || value.length > 128) {
    throw new Error(`${setting} must be a valid HTTP header name`);
  }
  const normalized = value.toLowerCase();
  if (reservedMtlsHeaders.has(normalized)) {
    throw new Error(`${setting} cannot use a routing, credential, or forwarding header`);
  }
  return normalized;
}

function mtlsTrustedProxyCidrs(value) {
  if (!value) return [];
  const result = [];
  const seen = new Set();
  for (const input of value.split(',').map((entry) => entry.trim()).filter(Boolean)) {
    if (seen.has(input)) throw new Error('AUTHME_MTLS_TRUSTED_PROXY_CIDRS contains duplicate entries');
    seen.add(input);
    const separator = input.lastIndexOf('/');
    const address = separator === -1 ? input : input.slice(0, separator);
    const family = isIP(address);
    const prefix = separator === -1 ? undefined : Number(input.slice(separator + 1));
    const maxPrefix = family === 4 ? 32 : 128;
    if (!family || (prefix !== undefined && (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix))) {
      throw new Error(`Invalid AUTHME_MTLS_TRUSTED_PROXY_CIDRS entry: ${input}`);
    }
    result.push({ address, family, prefix });
  }
  return result;
}

function mtlsConfiguration(raw) {
  const configured = [
    raw.AUTHME_MTLS_CLIENT_CERT_VERIFIED_HEADER,
    raw.AUTHME_MTLS_CLIENT_CERT_VERIFIED_VALUE,
    raw.AUTHME_MTLS_TRUSTED_PROXY_CIDRS,
  ].some((value) => value !== undefined);
  if (!raw.AUTHME_MTLS_CLIENT_CERT_HEADER) {
    if (configured) throw new Error('AUTHME_MTLS_CLIENT_CERT_HEADER is required when other mTLS settings are configured');
    return deepFreeze({ enabled: false, trustedProxyCidrs: [] });
  }
  if (!raw.AUTHME_TRUST_PROXY) {
    throw new Error('AUTHME_TRUST_PROXY must be enabled when mTLS proxy headers are configured');
  }

  const clientCertHeader = mtlsHeaderName(
    raw.AUTHME_MTLS_CLIENT_CERT_HEADER,
    'AUTHME_MTLS_CLIENT_CERT_HEADER',
  );
  const clientCertVerifiedHeader = mtlsHeaderName(
    raw.AUTHME_MTLS_CLIENT_CERT_VERIFIED_HEADER ?? 'x-ssl-client-verify',
    'AUTHME_MTLS_CLIENT_CERT_VERIFIED_HEADER',
  );
  if (clientCertHeader === clientCertVerifiedHeader) {
    throw new Error('The mTLS certificate and verification headers must be distinct');
  }
  const clientCertVerifiedValue = raw.AUTHME_MTLS_CLIENT_CERT_VERIFIED_VALUE ?? 'SUCCESS';
  if (clientCertVerifiedValue.length > 128 || /[\r\n]/u.test(clientCertVerifiedValue)) {
    throw new Error('AUTHME_MTLS_CLIENT_CERT_VERIFIED_VALUE must be a single header value of at most 128 characters');
  }
  const trustedProxyCidrs = mtlsTrustedProxyCidrs(raw.AUTHME_MTLS_TRUSTED_PROXY_CIDRS);
  if (!trustedProxyCidrs.length) {
    throw new Error('AUTHME_MTLS_TRUSTED_PROXY_CIDRS is required when mTLS proxy headers are configured');
  }
  return deepFreeze({
    enabled: true,
    clientCertHeader,
    clientCertVerifiedHeader,
    clientCertVerifiedValue,
    trustedProxyCidrs,
  });
}

function secret(value, name, devMode, bytes = 32) {
  if (!value) {
    if (!devMode) throw new Error(`${name} is required outside development mode`);
    return randomBytes(bytes).toString('base64url');
  }
  if (Buffer.byteLength(value) < bytes) throw new Error(`${name} must contain at least ${bytes} bytes`);
  if (!devMode && /(?:replace[-_ ]?with|change[-_ ]?me|example[-_ ]?secret)/i.test(value)) {
    throw new Error(`${name} still contains an example placeholder`);
  }
  return value;
}

function encryptionKey(value, devMode) {
  if (!value) {
    if (!devMode) throw new Error('AUTHME_FIELD_ENCRYPTION_KEY is required outside development mode');
    return randomBytes(32);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== 32) throw new Error('AUTHME_FIELD_ENCRYPTION_KEY must be a base64url-encoded 32-byte key');
  return decoded;
}

function realmNames(value) {
  const names = (value ?? 'master').split(',').map((item) => item.trim()).filter(Boolean);
  if (!names.length) throw new Error('AUTHME_REALMS must contain at least one realm');
  for (const name of names) {
    if (!/^[a-z][a-z0-9-]{0,62}$/.test(name)) {
      throw new Error(`Invalid realm name: ${name}`);
    }
  }
  if (new Set(names).size !== names.length) throw new Error('AUTHME_REALMS contains duplicate realm names');
  return Object.freeze(names);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function clientsByRealm(value, realms) {
  if (!value) return Object.fromEntries(realms.map((realm) => [realm, []]));
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error('AUTHME_CLIENTS_JSON must contain valid JSON', { cause: error });
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('AUTHME_CLIENTS_JSON must be an object keyed by realm');
  }
  const result = {};
  for (const realm of realms) {
    const clients = parsed[realm] ?? [];
    if (!Array.isArray(clients)) throw new Error(`AUTHME_CLIENTS_JSON.${realm} must be an array`);
    result[realm] = deepFreeze(structuredClone(clients).map((client, index) => {
      const name = `AUTHME_CLIENTS_JSON.${realm}[${index}]`;
      if (!client || Array.isArray(client) || typeof client !== 'object') {
        throw new Error(`${name} must be an object`);
      }
      if (client.fapi_profile !== undefined && client.fapi_profile !== '2.0') {
        throw new Error(`${name}.fapi_profile must be 2.0 when provided`);
      }
      if (client.allow_user_registration !== undefined && typeof client.allow_user_registration !== 'boolean') {
        throw new Error(`${name}.allow_user_registration must be a boolean when provided`);
      }
      return client;
    }));
  }
  return deepFreeze(result);
}

function signingKeyProvidersByRealm(value, realms) {
  if (!value) return deepFreeze(Object.fromEntries(realms.map((realm) => [realm, {
    provider: 'file', algorithm: 'RS256', materialReference: `${realm}.json`, rotationDays: 30, overlapSeconds: 2_592_000,
  }])));
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) { throw new Error('AUTHME_SIGNING_KEY_PROVIDERS_JSON must contain valid JSON', { cause: error }); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('AUTHME_SIGNING_KEY_PROVIDERS_JSON must be an object keyed by realm');
  const result = {};
  for (const realm of realms) {
    const input = parsed[realm];
    if (!input || Array.isArray(input) || typeof input !== 'object') throw new Error(`AUTHME_SIGNING_KEY_PROVIDERS_JSON.${realm} is required`);
    const known = new Set(['provider', 'algorithm', 'material_reference', 'rotation_days', 'overlap_seconds']);
    for (const field of Object.keys(input)) if (!known.has(field)) throw new Error(`AUTHME_SIGNING_KEY_PROVIDERS_JSON.${realm}.${field} is not supported`);
    if (!['file', 'aws-kms', 'gcp-kms', 'azure-key-vault', 'pkcs11'].includes(input.provider)) throw new Error(`AUTHME_SIGNING_KEY_PROVIDERS_JSON.${realm}.provider is unsupported`);
    if (!['RS256', 'PS256', 'ES256'].includes(input.algorithm ?? 'RS256')) throw new Error(`AUTHME_SIGNING_KEY_PROVIDERS_JSON.${realm}.algorithm is unsupported`);
    if (typeof input.material_reference !== 'string' || input.material_reference.length < 1 || input.material_reference.length > 4096 || /[\r\n]/u.test(input.material_reference)) throw new Error(`AUTHME_SIGNING_KEY_PROVIDERS_JSON.${realm}.material_reference is required`);
    const rotationDays = input.rotation_days ?? 30;
    const overlapSeconds = input.overlap_seconds ?? 2_592_000;
    if (!Number.isInteger(rotationDays) || rotationDays < 1 || rotationDays > 365) throw new Error(`AUTHME_SIGNING_KEY_PROVIDERS_JSON.${realm}.rotation_days must be between 1 and 365`);
    if (!Number.isInteger(overlapSeconds) || overlapSeconds < 3600 || overlapSeconds > 31_536_000) throw new Error(`AUTHME_SIGNING_KEY_PROVIDERS_JSON.${realm}.overlap_seconds must be between 3600 and 31536000`);
    result[realm] = {
      provider: input.provider,
      algorithm: input.algorithm ?? 'RS256',
      materialReference: input.material_reference,
      rotationDays,
      overlapSeconds,
    };
  }
  return deepFreeze(result);
}

function signingAdapterModules(value) {
  if (!value) return deepFreeze({});
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) { throw new Error('AUTHME_SIGNING_ADAPTER_MODULES_JSON must contain valid JSON', { cause: error }); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('AUTHME_SIGNING_ADAPTER_MODULES_JSON must be an object keyed by signing provider');
  const result = {};
  for (const [provider, specifier] of Object.entries(parsed)) {
    if (!['aws-kms', 'gcp-kms', 'azure-key-vault', 'pkcs11'].includes(provider)) {
      throw new Error(`AUTHME_SIGNING_ADAPTER_MODULES_JSON.${provider} is not a supported external signing provider`);
    }
    if (typeof specifier !== 'string' || !specifier.trim() || specifier.length > 2048 || /[\r\n\0]/u.test(specifier)) {
      throw new Error(`AUTHME_SIGNING_ADAPTER_MODULES_JSON.${provider} must be a module specifier`);
    }
    result[provider] = specifier.trim();
  }
  return deepFreeze(result);
}

const oauthScope = /^[\x21\x23-\x5b\x5d-\x7e]+$/;

function stringArray(value, name, { required = false } = {}) {
  if (value === undefined && !required) return [];
  if (!Array.isArray(value) || (required && value.length === 0)) {
    throw new Error(`${name} must be ${required ? 'a non-empty' : 'an'} array`);
  }
  if (value.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new Error(`${name} must contain non-empty strings`);
  }
  if (new Set(value).size !== value.length) throw new Error(`${name} must not contain duplicates`);
  return [...value];
}

function resourceServersByRealm(value, realms, devMode) {
  if (!value) return deepFreeze(Object.fromEntries(realms.map((realm) => [realm, []])));
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error('AUTHME_RESOURCE_SERVERS_JSON must contain valid JSON', { cause: error });
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('AUTHME_RESOURCE_SERVERS_JSON must be an object keyed by realm');
  }

  const result = {};
  for (const realm of realms) {
    const servers = parsed[realm] ?? [];
    if (!Array.isArray(servers)) throw new Error(`AUTHME_RESOURCE_SERVERS_JSON.${realm} must be an array`);
    const audiences = new Set();
    result[realm] = servers.map((input, index) => {
      const name = `AUTHME_RESOURCE_SERVERS_JSON.${realm}[${index}]`;
      if (!input || Array.isArray(input) || typeof input !== 'object') throw new Error(`${name} must be an object`);
      const known = new Set([
        'audience', 'scopes', 'authorized_client_ids', 'introspection_client_ids',
        'multi_resource_client_ids', 'role_client_ids', 'include_realm_roles',
        'include_groups', 'access_token_format',
      ]);
      for (const field of Object.keys(input)) {
        if (!known.has(field)) throw new Error(`${name}.${field} is not supported`);
      }

      let audience;
      try { audience = new URL(input.audience); } catch { throw new Error(`${name}.audience must be an absolute URI`); }
      if (audience.hash) throw new Error(`${name}.audience cannot contain a fragment`);
      if (audience.username || audience.password) throw new Error(`${name}.audience cannot contain credentials`);
      const developmentLoopback = devMode && audience.protocol === 'http:'
        && ['127.0.0.1', '[::1]', '::1', 'localhost'].includes(audience.hostname);
      if (audience.protocol !== 'https:' && !developmentLoopback) {
        throw new Error(`${name}.audience must use HTTPS except for development loopback resources`);
      }
      const normalizedAudience = audience.href;
      if (audiences.has(normalizedAudience)) throw new Error(`${name}.audience is duplicated in realm ${realm}`);
      audiences.add(normalizedAudience);

      const scopes = stringArray(input.scopes, `${name}.scopes`, { required: true });
      if (scopes.some((scope) => !oauthScope.test(scope))) throw new Error(`${name}.scopes contains an invalid OAuth scope value`);
      const authorizedClientIds = stringArray(input.authorized_client_ids, `${name}.authorized_client_ids`, { required: true });
      const multiResourceClientIds = stringArray(input.multi_resource_client_ids, `${name}.multi_resource_client_ids`);
      if (multiResourceClientIds.some((clientId) => !authorizedClientIds.includes(clientId))) {
        throw new Error(`${name}.multi_resource_client_ids must be a subset of authorized_client_ids`);
      }
      const introspectionClientIds = stringArray(input.introspection_client_ids, `${name}.introspection_client_ids`);
      const roleClientIds = stringArray(input.role_client_ids, `${name}.role_client_ids`);
      if (input.include_realm_roles !== undefined && typeof input.include_realm_roles !== 'boolean') {
        throw new Error(`${name}.include_realm_roles must be a boolean`);
      }
      if (input.include_groups !== undefined && typeof input.include_groups !== 'boolean') {
        throw new Error(`${name}.include_groups must be a boolean`);
      }
      const accessTokenFormat = input.access_token_format ?? 'jwt';
      if (!['jwt', 'opaque'].includes(accessTokenFormat)) throw new Error(`${name}.access_token_format must be jwt or opaque`);

      return {
        audience: normalizedAudience,
        scopes,
        authorizedClientIds,
        multiResourceClientIds,
        introspectionClientIds,
        roleClientIds,
        includeRealmRoles: input.include_realm_roles ?? false,
        includeGroups: input.include_groups ?? false,
        accessTokenFormat,
      };
    });
  }
  return deepFreeze(result);
}

export function loadConfig(environment = process.env) {
  const raw = rawSchema.parse(environment);
  const devMode = raw.AUTHME_DEV_MODE;
  const port = raw.AUTHME_PORT ?? 3000;
  const publicUrl = new URL(raw.AUTHME_PUBLIC_URL ?? `http://127.0.0.1:${port}`);
  if (publicUrl.search || publicUrl.hash) throw new Error('AUTHME_PUBLIC_URL cannot contain a query or fragment');
  if (publicUrl.pathname !== '/') throw new Error('AUTHME_PUBLIC_URL must be an origin without a path');
  if (publicUrl.username || publicUrl.password) throw new Error('AUTHME_PUBLIC_URL cannot contain credentials');
  if (!devMode && publicUrl.protocol !== 'https:') throw new Error('AUTHME_PUBLIC_URL must use HTTPS outside development mode');

  const realms = realmNames(raw.AUTHME_REALMS);
  const cookieKeys = (raw.AUTHME_COOKIE_KEYS ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (!cookieKeys.length && devMode) cookieKeys.push(randomBytes(32).toString('base64url'));
  if (!devMode && cookieKeys.length < 2) {
    throw new Error('AUTHME_COOKIE_KEYS must contain at least two comma-separated keys for safe rotation');
  }
  if (cookieKeys.some((key) => Buffer.byteLength(key) < 32)) {
    throw new Error('Every AUTHME_COOKIE_KEYS entry must contain at least 32 bytes');
  }
  if (new Set(cookieKeys).size !== cookieKeys.length) {
    throw new Error('AUTHME_COOKIE_KEYS must contain distinct keys for rotation');
  }
  if (!devMode && cookieKeys.some((key) => /(?:replace[-_ ]?with|change[-_ ]?me|example[-_ ]?secret)/i.test(key))) {
    throw new Error('AUTHME_COOKIE_KEYS still contains an example placeholder');
  }
  if (!devMode && !raw.DATABASE_URL) throw new Error('DATABASE_URL is required outside development mode');
  const signingKeyProviders = signingKeyProvidersByRealm(raw.AUTHME_SIGNING_KEY_PROVIDERS_JSON, realms);
  if (!devMode && !raw.AUTHME_JWKS_DIR
    && Object.values(signingKeyProviders).some((provider) => provider.provider === 'file')) {
    throw new Error('AUTHME_JWKS_DIR is required outside development mode for file-backed signing keys');
  }

  const clients = clientsByRealm(raw.AUTHME_CLIENTS_JSON, realms);
  const normalizedPublicUrl = publicUrl.toString().replace(/\/$/, '');
  const ldapProviders = parseLdapProviders(raw.AUTHME_LDAP_PROVIDERS_JSON, { realms, devMode });
  const oidcProviders = parseOidcProviders(raw.AUTHME_OIDC_PROVIDERS_JSON, { realms, devMode });
  const samlProviders = parseSamlProviders(raw.AUTHME_SAML_PROVIDERS_JSON, {
    realms, publicUrl: normalizedPublicUrl,
  });
  assertFederationProviderIdsUnique(realms, [
    ['LDAP', ldapProviders], ['OIDC', oidcProviders], ['SAML', samlProviders],
  ]);
  const config = {
    devMode,
    trustProxy: raw.AUTHME_TRUST_PROXY,
    mtls: mtlsConfiguration(raw),
    publicUrl: normalizedPublicUrl,
    port,
    realms,
    cookieKeys: Object.freeze(cookieKeys),
    csrfSecret: secret(raw.AUTHME_CSRF_SECRET, 'AUTHME_CSRF_SECRET', devMode),
    passwordPepper: secret(raw.AUTHME_PASSWORD_PEPPER, 'AUTHME_PASSWORD_PEPPER', devMode),
    subjectSalt: secret(raw.AUTHME_SUBJECT_SALT, 'AUTHME_SUBJECT_SALT', devMode),
    fieldEncryptionKey: encryptionKey(raw.AUTHME_FIELD_ENCRYPTION_KEY, devMode),
    adminToken: secret(raw.AUTHME_ADMIN_TOKEN, 'AUTHME_ADMIN_TOKEN', devMode),
    jwksDir: raw.AUTHME_JWKS_DIR,
    signingKeyProvidersByRealm: signingKeyProviders,
    signingAdapterModules: signingAdapterModules(raw.AUTHME_SIGNING_ADAPTER_MODULES_JSON),
    accountEmailModule: raw.AUTHME_ACCOUNT_EMAIL_MODULE,
    clientsByRealm: clients,
    resourceServersByRealm: resourceServersByRealm(raw.AUTHME_RESOURCE_SERVERS_JSON, realms, devMode),
    ldapProvidersByRealm: ldapProviders,
    oidcProvidersByRealm: oidcProviders,
    samlProvidersByRealm: samlProviders,
    samlIdentityProvidersByRealm: parseSamlIdentityProviders(raw.AUTHME_SAML_IDP_JSON, {
      realms, publicUrl: normalizedPublicUrl,
    }),
    scimTokensByRealm: parseScimTokens(raw.AUTHME_SCIM_TOKENS_JSON, { realms, devMode }),
    enableDynamicRegistration: raw.AUTHME_ENABLE_DYNAMIC_REGISTRATION,
    devAdminPassword: raw.AUTHME_DEV_ADMIN_PASSWORD ?? 'AuthMe-Change-Me-Now-2026!',
    logLevel: raw.AUTHME_LOG_LEVEL ?? 'info',
    accessTokenTtl: raw.AUTHME_ACCESS_TOKEN_TTL_SECONDS ?? 300,
    authorizationCodeTtl: raw.AUTHME_AUTHORIZATION_CODE_TTL_SECONDS ?? 60,
    sessionTtl: raw.AUTHME_SESSION_TTL_SECONDS ?? 28800,
    webauthnChallengeTtl: raw.AUTHME_WEBAUTHN_CHALLENGE_TTL_SECONDS ?? 300,
    auditRetentionDays: raw.AUTHME_AUDIT_RETENTION_DAYS ?? 90,
    databaseUrl: raw.DATABASE_URL,
    redisUrl: raw.REDIS_URL,
  };
  return Object.freeze(config);
}

export function issuerFor(config, realm) {
  if (!config.realms.includes(realm)) throw new Error(`Unknown realm: ${realm}`);
  return `${config.publicUrl}/realms/${realm}`;
}
