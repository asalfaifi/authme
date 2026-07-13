import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { parseLdapProviders } from './federation/ldap.js';
import { parseOidcProviders } from './federation/oidc.js';
import { parseSamlProviders } from './federation/saml-config.js';
import { parseScimTokens } from './scim/config.js';

const booleanValue = z
  .string()
  .optional()
  .transform((value) => ['1', 'true', 'yes', 'on'].includes((value ?? '').toLowerCase()));

const rawSchema = z.object({
  AUTHME_PUBLIC_URL: z.string().url().optional(),
  AUTHME_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  AUTHME_REALMS: z.string().optional(),
  AUTHME_DEV_MODE: booleanValue,
  AUTHME_TRUST_PROXY: booleanValue,
  AUTHME_COOKIE_KEYS: z.string().optional(),
  AUTHME_CSRF_SECRET: z.string().optional(),
  AUTHME_PASSWORD_PEPPER: z.string().optional(),
  AUTHME_SUBJECT_SALT: z.string().optional(),
  AUTHME_FIELD_ENCRYPTION_KEY: z.string().optional(),
  AUTHME_ADMIN_TOKEN: z.string().optional(),
  AUTHME_JWKS_DIR: z.string().optional(),
  AUTHME_CLIENTS_JSON: z.string().optional(),
  AUTHME_RESOURCE_SERVERS_JSON: z.string().optional(),
  AUTHME_LDAP_PROVIDERS_JSON: z.string().optional(),
  AUTHME_OIDC_PROVIDERS_JSON: z.string().optional(),
  AUTHME_SAML_PROVIDERS_JSON: z.string().optional(),
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
    result[realm] = deepFreeze(structuredClone(clients));
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
        'role_client_ids', 'include_realm_roles', 'include_groups', 'access_token_format',
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
  if (!devMode && !raw.AUTHME_JWKS_DIR) throw new Error('AUTHME_JWKS_DIR is required outside development mode');

  const clients = clientsByRealm(raw.AUTHME_CLIENTS_JSON, realms);
  const normalizedPublicUrl = publicUrl.toString().replace(/\/$/, '');
  const config = {
    devMode,
    trustProxy: raw.AUTHME_TRUST_PROXY,
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
    clientsByRealm: clients,
    resourceServersByRealm: resourceServersByRealm(raw.AUTHME_RESOURCE_SERVERS_JSON, realms, devMode),
    ldapProvidersByRealm: parseLdapProviders(raw.AUTHME_LDAP_PROVIDERS_JSON, { realms, devMode }),
    oidcProvidersByRealm: parseOidcProviders(raw.AUTHME_OIDC_PROVIDERS_JSON, { realms, devMode }),
    samlProvidersByRealm: parseSamlProviders(raw.AUTHME_SAML_PROVIDERS_JSON, { realms, publicUrl: normalizedPublicUrl }),
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
