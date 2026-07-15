import { createHash } from 'node:crypto';

const realmNamePattern = /^[a-z][a-z0-9-]{0,62}$/u;
const roleNamePattern = /^[a-zA-Z0-9:._/-]{1,128}$/u;
const providerIdPattern = /^[a-z][a-z0-9-]{1,31}$/u;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const supportedScopes = new Set([
  'openid', 'offline_access', 'profile', 'email', 'phone', 'address', 'roles', 'groups',
]);
const ignoredKeycloakScopes = new Set(['acr', 'basic', 'microprofile-jwt', 'web-origins']);
const confidentialClientAuthenticationMethods = new Set([
  'client_secret_basic', 'client_secret_jwt', 'private_key_jwt', 'tls_client_auth',
]);
const prototypeShapedKeys = new Set(['__proto__', 'constructor', 'prototype']);
// These placeholders are intentionally too short to satisfy AuthMe's production
// client-secret policy. An artifact cannot become deployable by accident.
const clientSecretPlaceholder = '__ROTATE__';
const bindSecretPlaceholder = '__ROTATE__';
const sensitiveAttributeName = /(?:password|passwd|secret|token|credential|private[-_. ]?key)/iu;

const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

export class KeycloakImportError extends TypeError {
  constructor(path, message, options) {
    super(`Invalid Keycloak realm export at ${path}: ${message}`, options);
    this.name = 'KeycloakImportError';
    this.code = 'KEYCLOAK_IMPORT_INVALID';
    this.path = path;
  }
}

function invalid(path, message, cause) {
  throw new KeycloakImportError(path, message, cause ? { cause } : undefined);
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function record(value, path) {
  if (!isRecord(value)) invalid(path, 'must be an object');
  return value;
}

function optionalRecord(value, path) {
  return value === undefined ? {} : record(value, path);
}

function array(value, path) {
  if (!Array.isArray(value)) invalid(path, 'must be an array');
  return value;
}

function optionalArray(value, path) {
  return value === undefined ? [] : array(value, path);
}

function requiredString(value, path) {
  if (typeof value !== 'string' || !value.trim()) invalid(path, 'must be a non-empty string');
  if (/\p{Cc}/u.test(value)) invalid(path, 'cannot contain control characters');
  return value.trim();
}

function optionalString(value, path) {
  if (value === undefined || value === null || value === '') return undefined;
  return requiredString(value, path);
}

function boolean(value, fallback, path) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') invalid(path, 'must be a boolean');
  return value;
}

function optionalBooleans(input, path, fields) {
  for (const field of fields) {
    if (input[field] !== undefined && typeof input[field] !== 'boolean') {
      invalid(`${path}.${field}`, 'must be a boolean');
    }
  }
}

function configValue(value) {
  if (Array.isArray(value)) return value[0];
  return value;
}

function configString(configuration, key) {
  const value = configValue(configuration[key]);
  if (value === undefined || value === null || value === '') return undefined;
  return String(value).trim();
}

function configBoolean(configuration, key, fallback = false) {
  const value = configString(configuration, key);
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(compare);
}

function sortedRecord(entries) {
  return Object.fromEntries([...entries].sort(([left], [right]) => compare(left, right)));
}

function namespaceEntries(value, path) {
  const input = optionalRecord(value, path);
  const entries = Object.entries(input);
  for (const [key] of entries) {
    if (prototypeShapedKeys.has(key)) {
      invalid(`${path}.${key}`, `prototype-shaped record namespace key ${JSON.stringify(key)} is not allowed`);
    }
  }
  return entries;
}

function normalizeStringList(value, path, { split = false } = {}) {
  if (value === undefined || value === null || value === '') return [];
  const values = Array.isArray(value) ? value : split && typeof value === 'string' ? value.split(/\s+/u) : [value];
  return uniqueSorted(values.map((item, index) => requiredString(item, `${path}[${index}]`)));
}

function normalizeAttributes(value, path, report, item, {
  category = 'user-attribute', target = 'users[].attributes',
} = {}) {
  const input = optionalRecord(value, path);
  const entries = [];
  for (const key of Object.keys(input).sort(compare)) {
    if (sensitiveAttributeName.test(key)) {
      report.unsupported(category, `${path}.${key}`, target, item,
        'Attribute was skipped because its name indicates credential or secret material.');
      continue;
    }
    const raw = input[key];
    const values = Array.isArray(raw) ? raw : [raw];
    if (values.some((entry) => !['string', 'number', 'boolean'].includes(typeof entry))) {
      report.unsupported(category, `${path}.${key}`, target, item,
        'Only scalar string, number, and boolean attribute values are portable.');
      continue;
    }
    entries.push([key, uniqueSorted(values.map(String))]);
  }
  return sortedRecord(entries);
}

function deterministicUuid(realm, username) {
  const bytes = createHash('sha256').update(`authme-keycloak-import\0${realm}\0${username}`).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort(compare).map((key) => [key, canonicalize(value[key])]));
}

export function stableJsonStringify(value, space = 2) {
  return `${JSON.stringify(canonicalize(value), null, space)}\n`;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function reportBuilder(realm) {
  const buckets = {
    mapped: [],
    transformedWithWarnings: [],
    unsupportedOrSkipped: [],
  };
  const add = (bucket, category, source, target, item, reason) => {
    const entry = { category, source, target, item };
    if (reason) entry.reason = reason;
    buckets[bucket].push(entry);
  };
  return {
    mapped: (...arguments_) => add('mapped', ...arguments_),
    warning: (...arguments_) => add('transformedWithWarnings', ...arguments_),
    unsupported: (...arguments_) => add('unsupportedOrSkipped', ...arguments_),
    finish() {
      const entryCompare = (left, right) => compare(
        [left.category, left.source, left.target, left.item, left.reason ?? ''].join('\0'),
        [right.category, right.source, right.target, right.item, right.reason ?? ''].join('\0'),
      );
      for (const entries of Object.values(buckets)) entries.sort(entryCompare);
      return {
        schemaVersion: 'authme.keycloak-compatibility-report/v1',
        realm,
        summary: {
          mapped: buckets.mapped.length,
          transformedWithWarnings: buckets.transformedWithWarnings.length,
          unsupportedOrSkipped: buckets.unsupportedOrSkipped.length,
        },
        ...buckets,
      };
    },
  };
}

function normalizePublicUrl(value, path) {
  let url;
  try { url = new URL(value); } catch (error) { invalid(path, 'must be an absolute URL', error); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    invalid(path, 'must be an HTTP(S) URL without credentials, query, or fragment');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
    invalid(path, 'must use HTTPS except for development loopback');
  }
  if (url.pathname !== '/' && url.pathname !== '') invalid(path, 'must be an origin without a path');
  return url.origin;
}

function resolveIssuer(source, realmName, options, report) {
  if (options.issuer !== undefined) {
    const issuer = requiredString(options.issuer, 'options.issuer').replace(/\/$/u, '');
    let url;
    try { url = new URL(issuer); } catch (error) { invalid('options.issuer', 'must be an absolute URL', error); }
    if (!['http:', 'https:'].includes(url.protocol)
      || (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname)))
      || url.username || url.password || url.search || url.hash
      || !url.pathname.endsWith(`/realms/${encodeURIComponent(realmName)}`)) {
      invalid('options.issuer', `must end with /realms/${encodeURIComponent(realmName)} and contain no credentials, query, or fragment`);
    }
    const prefix = url.pathname.slice(0, -`/realms/${encodeURIComponent(realmName)}`.length);
    if (prefix) invalid('options.issuer', 'cannot contain a path before /realms/{realm}; AuthMe is mounted at the origin');
    report.mapped('realm', 'options.issuer', 'realm.issuer', realmName);
    return { issuer, publicUrl: url.origin };
  }

  if (options.publicUrl !== undefined) {
    const publicUrl = normalizePublicUrl(requiredString(options.publicUrl, 'options.publicUrl'), 'options.publicUrl');
    report.mapped('realm', 'options.publicUrl', 'environment.AUTHME_PUBLIC_URL', realmName);
    return { issuer: `${publicUrl}/realms/${realmName}`, publicUrl };
  }

  const attributes = optionalRecord(source.attributes, 'attributes');
  const frontendUrl = optionalString(attributes.frontendUrl, 'attributes.frontendUrl');
  if (frontendUrl) {
    let value = frontendUrl.replace(/\/$/u, '');
    const realmSuffix = `/realms/${encodeURIComponent(realmName)}`;
    if (value.endsWith(realmSuffix)) value = value.slice(0, -realmSuffix.length);
    try {
      const publicUrl = normalizePublicUrl(value, 'attributes.frontendUrl');
      report.mapped('realm', 'attributes.frontendUrl', 'environment.AUTHME_PUBLIC_URL', realmName);
      return { issuer: `${publicUrl}/realms/${realmName}`, publicUrl };
    } catch (error) {
      if (!(error instanceof KeycloakImportError)) throw error;
      report.unsupported('realm', 'attributes.frontendUrl', 'environment.AUTHME_PUBLIC_URL', realmName,
        'The Keycloak frontend URL is not an origin that AuthMe can mount directly; supply --public-url.');
    }
  }

  report.warning('realm', 'realm', 'realm.issuer', realmName,
    'The export does not identify its public origin; supply --public-url before deployment.');
  return { issuer: null, publicUrl: null };
}

function mapIntegerSetting(source, sourceField, targetField, minimum, maximum, report, realmName) {
  if (source[sourceField] === undefined) return undefined;
  const value = source[sourceField];
  if (!Number.isSafeInteger(value)) invalid(sourceField, 'must be an integer');
  if (value < minimum || value > maximum) {
    report.unsupported('realm-lifetime', sourceField, `environment.${targetField}`, realmName,
      `Value is outside AuthMe's supported ${minimum}-${maximum} second range; the AuthMe default will be used.`);
    return undefined;
  }
  report.mapped('realm-lifetime', sourceField, `environment.${targetField}`, realmName);
  return value;
}

function mapRealm(source, realmName, options, report) {
  const { issuer, publicUrl } = resolveIssuer(source, realmName, options, report);
  const accessToken = mapIntegerSetting(source, 'accessTokenLifespan', 'AUTHME_ACCESS_TOKEN_TTL_SECONDS', 60, 3600, report, realmName);
  const authorizationCode = mapIntegerSetting(source, 'accessCodeLifespan', 'AUTHME_AUTHORIZATION_CODE_TTL_SECONDS', 30, 300, report, realmName);
  const session = mapIntegerSetting(source, 'ssoSessionIdleTimeout', 'AUTHME_SESSION_TTL_SECONDS', 300, 2_592_000, report, realmName);
  if (session !== undefined) {
    report.warning('realm-lifetime', 'ssoSessionIdleTimeout', 'realm.tokenLifetimes.session', realmName,
      'Keycloak has separate idle/max/offline session policies; AuthMe has one configured session TTL. Review the mapped idle value.');
  }
  if (source.ssoSessionMaxLifespan !== undefined) {
    if (!Number.isSafeInteger(source.ssoSessionMaxLifespan)) invalid('ssoSessionMaxLifespan', 'must be an integer');
    report.unsupported('realm-lifetime', 'ssoSessionMaxLifespan', 'realm.tokenLifetimes', realmName,
      'AuthMe does not have a separate Keycloak SSO maximum lifespan setting.');
  }
  report.mapped('realm', 'realm', 'realm.name', realmName);
  const enabled = boolean(source.enabled, true, 'enabled');
  if (!enabled) {
    report.warning('realm', 'enabled', 'realm.enabled', realmName,
      'AuthMe runtime realm selection does not preserve a disabled Keycloak realm automatically; do not deploy it until intentionally enabled.');
  }
  return {
    realm: {
      name: realmName,
      displayName: optionalString(source.displayName, 'displayName') ?? realmName,
      enabled,
      issuer,
      tokenLifetimes: {
        ...(accessToken !== undefined ? { accessToken } : {}),
        ...(authorizationCode !== undefined ? { authorizationCode } : {}),
        ...(session !== undefined ? { session } : {}),
      },
    },
    publicUrl,
    lifetimes: { accessToken, authorizationCode, session },
  };
}

function safeRoleNames(value, path, report, item, target) {
  const result = [];
  for (const [index, raw] of optionalArray(value, path).entries()) {
    const name = requiredString(raw, `${path}[${index}]`);
    if (!roleNamePattern.test(name)) {
      report.unsupported('role-assignment', `${path}[${index}]`, target, item,
        'Role name is outside AuthMe\'s 128-character portable role-name profile.');
      continue;
    }
    result.push(name);
  }
  return uniqueSorted(result);
}

function mapRoleList(value, path, report, namespace) {
  const names = new Set();
  const roles = [];
  for (const [index, raw] of optionalArray(value, path).entries()) {
    const input = record(raw, `${path}[${index}]`);
    optionalBooleans(input, `${path}[${index}]`, ['composite', 'clientRole']);
    const name = requiredString(input.name, `${path}[${index}].name`);
    if (!roleNamePattern.test(name)) {
      report.unsupported('role', `${path}[${index}]`, `roles.${namespace}`, name,
        'Role name is outside AuthMe\'s portable role-name profile.');
      continue;
    }
    if (names.has(name)) invalid(`${path}[${index}].name`, `duplicates role ${name}`);
    names.add(name);
    roles.push({
      name,
      ...(optionalString(input.description, `${path}[${index}].description`) ? { description: input.description.trim() } : {}),
    });
    if (input.composite === true || (isRecord(input.composites) && Object.keys(input.composites).length)) {
      report.warning('role', `${path}[${index}].composites`, `roles.${namespace}`, name,
        'The role name was retained, but composite-role expansion is not supported and must be materialized explicitly.');
    } else {
      report.mapped('role', `${path}[${index}]`, `roles.${namespace}`, name);
    }
  }
  return roles.sort((left, right) => compare(left.name, right.name));
}

function mapRoles(source, report) {
  const input = optionalRecord(source.roles, 'roles');
  const realm = mapRoleList(input.realm, 'roles.realm', report, 'realm');
  const clients = [];
  for (const [clientId, roles] of namespaceEntries(input.client, 'roles.client').sort(([left], [right]) => compare(left, right))) {
    clients.push([clientId, mapRoleList(roles, `roles.client.${clientId}`, report, `clients.${clientId}`)]);
  }
  return { realm, clients: sortedRecord(clients) };
}

function normalizeClientRoleAssignments(value, path, report, item, target) {
  return sortedRecord(namespaceEntries(value, path).sort(([left], [right]) => compare(left, right)).map(([clientId, roles]) => [
    clientId,
    safeRoleNames(roles, `${path}.${clientId}`, report, item, `${target}.${clientId}`),
  ]).filter(([, roles]) => roles.length));
}

function normalizeGroupPath(value, path, report, item) {
  if (typeof value !== 'string' || !value.trim()) invalid(path, 'must be a non-empty string');
  const normalized = value.startsWith('/') ? value : `/${value}`;
  if (normalized.length > 256 || /\p{Cc}/u.test(normalized) || normalized.includes('//')) {
    report.unsupported('group-membership', path, 'users[].groups', item,
      'Group path is outside AuthMe\'s canonical group-path profile.');
    return undefined;
  }
  return normalized;
}

function mapGroups(source, report) {
  const groups = [];
  const paths = new Set();
  const walk = (values, sourcePath, parentPath) => {
    for (const [index, raw] of optionalArray(values, sourcePath).entries()) {
      const path = `${sourcePath}[${index}]`;
      const input = record(raw, path);
      const name = requiredString(input.name, `${path}.name`);
      if (name.includes('/')) {
        report.unsupported('group', path, 'groups', name,
          'A Keycloak group name containing / cannot be represented as an unambiguous AuthMe group path.');
        continue;
      }
      const groupPath = `${parentPath}/${name}`;
      if (groupPath.length > 256) {
        report.unsupported('group', path, 'groups', name, 'Flattened group path exceeds AuthMe\'s 256-character limit.');
        continue;
      }
      if (paths.has(groupPath)) invalid(`${path}.name`, `duplicates group path ${groupPath}`);
      paths.add(groupPath);
      const realmRoles = safeRoleNames(input.realmRoles, `${path}.realmRoles`, report, groupPath, 'groups[].realmRoles');
      const clientRoles = normalizeClientRoleAssignments(input.clientRoles, `${path}.clientRoles`, report, groupPath, 'groups[].clientRoles');
      const group = {
        ...(optionalString(input.id, `${path}.id`) ? { id: input.id.trim() } : {}),
        name,
        path: groupPath,
        parentPath: parentPath || null,
        attributes: normalizeAttributes(input.attributes, `${path}.attributes`, report, groupPath, {
          category: 'group-attribute', target: 'groups[].attributes',
        }),
        realmRoles,
        clientRoles,
      };
      groups.push(group);
      report.mapped('group', path, 'groups', groupPath);
      if (realmRoles.length || Object.keys(clientRoles).length) {
        report.warning('group-role-mapping', path, 'groups[].realmRoles/clientRoles', groupPath,
          'Assignments are retained on the group and materialized onto imported users because AuthMe emits flat user entitlements.');
      }
      if (input.path !== undefined && input.path !== groupPath) {
        report.warning('group', `${path}.path`, 'groups[].path', groupPath,
          'The path was recomputed from the exported hierarchy to avoid trusting an inconsistent path field.');
      }
      const children = input.subGroups ?? input.subgroups;
      if (input.subGroups !== undefined && input.subgroups !== undefined) invalid(path, 'cannot contain both subGroups and subgroups');
      walk(children, `${path}.${input.subGroups !== undefined ? 'subGroups' : 'subgroups'}`, groupPath);
    }
  };
  walk(source.groups, 'groups', '');
  return groups.sort((left, right) => compare(left.path, right.path));
}

function isLoopback(hostname) {
  return ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(hostname.toLowerCase());
}

function exactUri(raw, path, { origin = false, native = false } = {}) {
  if (typeof raw !== 'string' || !raw.trim()) return undefined;
  const value = raw.trim();
  if (/[+*{}]/u.test(value)) return undefined;
  let url;
  try { url = new URL(value); } catch { return undefined; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) return undefined;
  if (origin && (url.origin !== value || url.search)) return undefined;
  if (url.protocol !== 'https:' && !(native && url.protocol === 'http:' && isLoopback(url.hostname))) return undefined;
  return origin ? url.origin : url.toString();
}

function mapUriList(values, path, report, item, target, options) {
  const result = [];
  for (const [index, raw] of optionalArray(values, path).entries()) {
    const value = requiredString(raw, `${path}[${index}]`);
    const mapped = exactUri(value, `${path}[${index}]`, options);
    if (!mapped) {
      report.unsupported('client-uri', `${path}[${index}]`, target, item,
        'Wildcard, relative, non-HTTP(S), insecure non-loopback, credential-bearing, or fragmented URI was skipped.');
      continue;
    }
    result.push(mapped);
  }
  return uniqueSorted(result);
}

function clientAttribute(client, name) {
  const attributes = optionalRecord(client.attributes, 'clients[].attributes');
  return configString(attributes, name);
}

function mapClientAuthentication(client, path, report, clientId) {
  if (client.publicClient === true) {
    report.mapped('client-authentication', `${path}.publicClient`, 'clients[].token_endpoint_auth_method', clientId);
    return { token_endpoint_auth_method: 'none' };
  }
  const type = (optionalString(client.clientAuthenticatorType, `${path}.clientAuthenticatorType`) ?? 'client-secret').toLowerCase();
  if (['client-secret', 'secret'].includes(type)) {
    report.warning('client-authentication', `${path}.clientAuthenticatorType`, 'clients[].token_endpoint_auth_method', clientId,
      'Mapped to client_secret_basic; rotate and inject a new AuthMe client secret before deployment.');
    return { token_endpoint_auth_method: 'client_secret_basic', client_secret: clientSecretPlaceholder };
  }
  if (type === 'client-secret-jwt') {
    const algorithm = clientAttribute(client, 'token.endpoint.auth.signing.alg') ?? 'HS256';
    if (algorithm !== 'HS256') {
      report.unsupported('client-authentication', `${path}.clientAuthenticatorType`, 'clients', clientId,
        `client_secret_jwt algorithm ${algorithm} is not supported by AuthMe.`);
      return undefined;
    }
    report.warning('client-authentication', `${path}.clientAuthenticatorType`, 'clients[].token_endpoint_auth_method', clientId,
      'Mapped to client_secret_jwt with HS256; rotate and inject a new AuthMe client secret before deployment.');
    return {
      token_endpoint_auth_method: 'client_secret_jwt',
      token_endpoint_auth_signing_alg: 'HS256',
      client_secret: clientSecretPlaceholder,
    };
  }
  if (['signed-jwt', 'private-key-jwt'].includes(type)) {
    const jwksUri = clientAttribute(client, 'jwks.url');
    const algorithm = clientAttribute(client, 'token.endpoint.auth.signing.alg') ?? 'RS256';
    if (!jwksUri || !['RS256', 'PS256', 'ES256'].includes(algorithm) || !exactUri(jwksUri, `${path}.attributes.jwks.url`)) {
      report.unsupported('client-authentication', `${path}.clientAuthenticatorType`, 'clients', clientId,
        'private_key_jwt requires an HTTPS public JWKS URI and an AuthMe-supported RS256, PS256, or ES256 algorithm.');
      return undefined;
    }
    report.mapped('client-authentication', `${path}.clientAuthenticatorType`, 'clients[].token_endpoint_auth_method', clientId);
    return {
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: algorithm,
      jwks_uri: new URL(jwksUri).toString(),
    };
  }
  report.unsupported('client-authentication', `${path}.clientAuthenticatorType`, 'clients', clientId,
    `Keycloak client authenticator ${type} has no automatic AuthMe mapping.`);
  return undefined;
}

function mapperScope(mapper, path, report, item) {
  const input = record(mapper, path);
  const protocol = optionalString(input.protocol, `${path}.protocol`) ?? 'openid-connect';
  const type = optionalString(input.protocolMapper, `${path}.protocolMapper`) ?? '';
  const name = optionalString(input.name, `${path}.name`) ?? (type || 'unnamed mapper');
  const configuration = optionalRecord(input.config, `${path}.config`);
  if (protocol !== 'openid-connect') {
    report.unsupported('protocol-mapper', path, 'clients[].scope', `${item}:${name}`,
      'Only OpenID Connect protocol mappers can be classified by this tool.');
    return [];
  }
  if (type.includes('realm-role-mapper') || type.includes('client-role-mapper')) {
    report.mapped('protocol-mapper', path, 'clients[].scope:roles', `${item}:${name}`);
    return ['roles'];
  }
  if (type.includes('group-membership-mapper')) {
    if (configString(configuration, 'full.path') === 'false') {
      report.warning('protocol-mapper', path, 'clients[].scope:groups', `${item}:${name}`,
        'AuthMe always emits canonical full group paths.');
    } else {
      report.mapped('protocol-mapper', path, 'clients[].scope:groups', `${item}:${name}`);
    }
    return ['groups'];
  }
  if (type.includes('usermodel-attribute-mapper') || type.includes('usermodel-property-mapper')) {
    const claim = configString(configuration, 'claim.name');
    const attribute = configString(configuration, 'user.attribute') ?? configString(configuration, 'user.attribute.name');
    const standard = new Map([
      ['email', 'email'], ['email_verified', 'emailVerified'], ['preferred_username', 'username'],
      ['name', 'name'], ['given_name', 'givenName'], ['family_name', 'familyName'],
    ]);
    if (claim && attribute && standard.get(claim) === attribute) {
      report.mapped('protocol-mapper', path, 'users[]', `${item}:${name}`);
      return [];
    }
  }
  report.unsupported('protocol-mapper', path, 'clients[].scope', `${item}:${name}`,
    'Custom, scripted, audience, hardcoded, or non-standard claim transforms require manual AuthMe claim-policy review.');
  return [];
}

function indexClientScopes(source) {
  const scopes = new Map();
  for (const [index, raw] of optionalArray(source.clientScopes, 'clientScopes').entries()) {
    const input = record(raw, `clientScopes[${index}]`);
    const name = requiredString(input.name, `clientScopes[${index}].name`);
    if (scopes.has(name)) invalid(`clientScopes[${index}].name`, `duplicates client scope ${name}`);
    scopes.set(name, { input, path: `clientScopes[${index}]` });
  }
  return scopes;
}

function mappedClientScopes(client, path, source, scopeIndex, report, clientId) {
  const sourceScopeNames = uniqueSorted([
    ...normalizeStringList(client.defaultClientScopes ?? source.defaultDefaultClientScopes, `${path}.defaultClientScopes`),
    ...normalizeStringList(client.optionalClientScopes ?? source.defaultOptionalClientScopes, `${path}.optionalClientScopes`),
  ]);
  const result = new Set(['openid']);
  for (const name of sourceScopeNames) {
    if (supportedScopes.has(name)) {
      result.add(name);
      report.mapped('client-scope', `${path}.clientScopes`, 'clients[].scope', `${clientId}:${name}`);
    } else if (!ignoredKeycloakScopes.has(name)) {
      report.unsupported('client-scope', `${path}.clientScopes`, 'clients[].scope', `${clientId}:${name}`,
        'The scope is not in AuthMe\'s configured built-in scope set.');
    }
    const scope = scopeIndex.get(name);
    if (scope) {
      for (const [index, mapper] of optionalArray(scope.input.protocolMappers, `${scope.path}.protocolMappers`).entries()) {
        for (const mapped of mapperScope(mapper, `${scope.path}.protocolMappers[${index}]`, report, clientId)) result.add(mapped);
      }
    }
  }
  for (const [index, mapper] of optionalArray(client.protocolMappers, `${path}.protocolMappers`).entries()) {
    for (const mapped of mapperScope(mapper, `${path}.protocolMappers[${index}]`, report, clientId)) result.add(mapped);
  }
  return [...result].filter((scope) => supportedScopes.has(scope)).sort(compare).join(' ');
}

function mapClients(source, report) {
  const clients = [];
  const seen = new Set();
  const scopeIndex = indexClientScopes(source);
  for (const [index, raw] of optionalArray(source.clients, 'clients').entries()) {
    const path = `clients[${index}]`;
    const input = record(raw, path);
    optionalBooleans(input, path, [
      'enabled', 'publicClient', 'bearerOnly', 'standardFlowEnabled', 'implicitFlowEnabled',
      'directAccessGrantsEnabled', 'serviceAccountsEnabled', 'consentRequired', 'fullScopeAllowed',
      'authorizationServicesEnabled',
    ]);
    const clientId = requiredString(input.clientId, `${path}.clientId`);
    if (seen.has(clientId)) invalid(`${path}.clientId`, `duplicates client ${clientId}`);
    seen.add(clientId);
    if (clientId === 'authme-admin-console') {
      report.unsupported('client', path, 'clients', clientId, 'Client ID is reserved by AuthMe.');
      continue;
    }
    if (input.enabled === false) {
      report.unsupported('client', path, 'clients', clientId,
        'Disabled Keycloak clients are omitted so the import cannot accidentally enable them.');
      continue;
    }
    const protocol = optionalString(input.protocol, `${path}.protocol`) ?? 'openid-connect';
    if (protocol !== 'openid-connect') {
      report.unsupported('client', path, 'clients', clientId,
        `Protocol ${protocol} is not an AuthMe relying-party protocol.`);
      continue;
    }
    if (input.bearerOnly === true) {
      report.unsupported('client', path, 'clients', clientId,
        'Keycloak bearer-only clients require an explicit AuthMe resource-server policy and cannot be inferred safely.');
      continue;
    }
    const authentication = mapClientAuthentication(input, path, report, clientId);
    if (!authentication) {
      if (input.serviceAccountsEnabled === true) {
        report.unsupported('client-authentication', `${path}.clientAuthenticatorType`, 'clients', clientId,
          'Client was skipped because its service account does not have a safely mapped confidential client authentication method.');
      }
      continue;
    }
    const publicClient = authentication.token_endpoint_auth_method === 'none';
    if (input.serviceAccountsEnabled === true
      && !confidentialClientAuthenticationMethods.has(authentication.token_endpoint_auth_method)) {
      report.unsupported('client-authentication', `${path}.publicClient/${path}.serviceAccountsEnabled`, 'clients', clientId,
        'Client was skipped because Keycloak enables a service account without confidential client authentication; public clients must never receive client_credentials.');
      continue;
    }
    const rawRedirects = optionalArray(input.redirectUris, `${path}.redirectUris`);
    const native = publicClient && rawRedirects.length > 0 && rawRedirects.every((value) => {
      try {
        const url = new URL(value);
        return url.protocol === 'http:' && isLoopback(url.hostname);
      } catch { return false; }
    });
    const redirectUris = mapUriList(rawRedirects, `${path}.redirectUris`, report, clientId,
      'clients[].redirect_uris', { native });
    const webOrigins = mapUriList(input.webOrigins, `${path}.webOrigins`, report, clientId,
      'clients[].web_origins', { origin: true, native });
    const postLogoutRaw = input.postLogoutRedirectUris ?? (clientAttribute(input, 'post.logout.redirect.uris')?.split('##').filter(Boolean));
    const postLogoutRedirectUris = mapUriList(postLogoutRaw, `${path}.postLogoutRedirectUris`, report, clientId,
      'clients[].post_logout_redirect_uris', { native });

    const grantTypes = [];
    if (boolean(input.standardFlowEnabled, true, `${path}.standardFlowEnabled`)) {
      if (redirectUris.length) grantTypes.push('authorization_code', 'refresh_token');
      else report.unsupported('client-grant', `${path}.standardFlowEnabled`, 'clients[].grant_types', clientId,
        'Authorization Code was omitted because no exact compatible redirect URI remains.');
    }
    if (input.serviceAccountsEnabled === true) grantTypes.push('client_credentials');
    if (configBoolean(optionalRecord(input.attributes, `${path}.attributes`), 'oauth2.device.authorization.grant.enabled')) {
      grantTypes.push('urn:ietf:params:oauth:grant-type:device_code');
    }
    if (configBoolean(optionalRecord(input.attributes, `${path}.attributes`), 'oidc.ciba.grant.enabled')) {
      if (publicClient) {
        report.unsupported('client-grant', `${path}.attributes.oidc.ciba.grant.enabled`, 'clients[].grant_types', clientId,
          'AuthMe CIBA requires confidential client authentication.');
      } else {
        grantTypes.push('urn:openid:params:grant-type:ciba');
      }
    }
    if (input.implicitFlowEnabled === true) {
      report.unsupported('client-grant', `${path}.implicitFlowEnabled`, 'clients[].grant_types', clientId,
        'Implicit and hybrid flows are not supported.');
    }
    if (input.directAccessGrantsEnabled === true) {
      report.unsupported('client-grant', `${path}.directAccessGrantsEnabled`, 'clients[].grant_types', clientId,
        'The OAuth password/direct-access grant is deliberately not supported.');
    }
    const uniqueGrantTypes = uniqueSorted(grantTypes);
    if (!uniqueGrantTypes.length) {
      report.unsupported('client', path, 'clients', clientId, 'Client has no safely mappable enabled grant type.');
      continue;
    }

    if (uniqueGrantTypes.includes('authorization_code')) {
      const pkce = clientAttribute(input, 'pkce.code.challenge.method');
      if (pkce === 'S256') {
        report.mapped('client-pkce', `${path}.attributes.pkce.code.challenge.method`, 'global PKCE policy', clientId);
      } else {
        report.warning('client-pkce', `${path}.attributes.pkce.code.challenge.method`, 'global PKCE policy', clientId,
          'AuthMe requires PKCE S256 for every Authorization Code client; the relying party must use S256.');
      }
    }
    if (input.consentRequired === true || input.fullScopeAllowed === true) {
      report.warning('client-policy', path, 'clients', clientId,
        'Keycloak consent/full-scope semantics are not copied; review AuthMe scope, consent, and resource policies.');
    }
    if (input.authorizationServicesEnabled === true || isRecord(input.authorizationSettings)) {
      report.unsupported('authorization-services', `${path}.authorizationSettings`, 'clients', clientId,
        'Keycloak Authorization Services/UMA policy is not supported; ordinary OIDC client settings were retained.');
    }

    const responseTypes = uniqueGrantTypes.includes('authorization_code') ? ['code'] : [];
    const scope = mappedClientScopes(input, path, source, scopeIndex, report, clientId);
    if (uniqueGrantTypes.includes('refresh_token') && !scope.split(' ').includes('offline_access')) {
      report.warning('client-grant', `${path}.standardFlowEnabled`, 'clients[].grant_types', clientId,
        'AuthMe issues refresh tokens only when offline_access is allowed, requested, and granted.');
    }
    const client = {
      client_id: clientId,
      ...(optionalString(input.name, `${path}.name`) ? { client_name: input.name.trim() } : {}),
      ...authentication,
      redirect_uris: redirectUris,
      ...(postLogoutRedirectUris.length ? { post_logout_redirect_uris: postLogoutRedirectUris } : {}),
      ...(webOrigins.length ? { web_origins: webOrigins } : {}),
      response_types: responseTypes,
      grant_types: uniqueGrantTypes,
      application_type: native ? 'native' : 'web',
      scope,
      ...(uniqueGrantTypes.includes('urn:openid:params:grant-type:ciba') ? { backchannel_token_delivery_mode: 'poll' } : {}),
    };
    clients.push(client);
    report.mapped('client', path, 'clients', clientId);
  }
  return clients.sort((left, right) => compare(left.client_id, right.client_id));
}

function normalizeProviderId(alias, path, report) {
  if (providerIdPattern.test(alias)) return alias;
  let id = alias.toLowerCase().replace(/[^a-z0-9-]+/gu, '-').replace(/^-+|-+$/gu, '');
  if (!/^[a-z]/u.test(id)) id = `idp-${id}`;
  if (id.length < 2) id = `${id || 'id'}p`;
  id = id.slice(0, 32).replace(/-+$/u, '');
  if (!providerIdPattern.test(id)) {
    report.unsupported('identity-provider', path, 'federation', alias,
      'Provider alias cannot be transformed into AuthMe\'s provider identifier profile.');
    return undefined;
  }
  report.warning('identity-provider', path, 'federation[].id', alias,
    `Provider alias was normalized to ${id}; update links and operator references.`);
  return id;
}

function providerUrl(value, path) {
  if (!value) return undefined;
  let url;
  try { url = new URL(value); } catch { return undefined; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) return undefined;
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) return undefined;
  return url.toString();
}

function oidcIssuer(value) {
  if (!value || value !== value.trim()) return undefined;
  let url;
  try { url = new URL(value); } catch { return undefined; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) return undefined;
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) return undefined;
  // Issuer identifiers use exact string comparison, including a trailing slash.
  return value;
}

function samlEntityId(value) {
  if (!value || value !== value.trim()) return undefined;
  let url;
  try { url = new URL(value); } catch { return undefined; }
  if (!url.protocol || url.username || url.password || url.hash) return undefined;
  return value;
}

function exactHttpsUrl(value) {
  if (!value || value !== value.trim()) return undefined;
  let url;
  try { url = new URL(value); } catch { return undefined; }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return undefined;
  return url.toString();
}

function oidcMapperClaims(mappers, alias, report) {
  const claims = {};
  for (const { input, path } of mappers) {
    const name = optionalString(input.name, `${path}.name`) ?? optionalString(input.identityProviderMapper, `${path}.identityProviderMapper`) ?? 'mapper';
    const type = optionalString(input.identityProviderMapper, `${path}.identityProviderMapper`) ?? '';
    const configuration = optionalRecord(input.config, `${path}.config`);
    if (!type.includes('oidc')) continue;
    const claim = configString(configuration, 'claim');
    const userAttribute = configString(configuration, 'user.attribute');
    const target = new Map([['username', 'username_claim'], ['groups', 'groups_claim'], ['roles', 'roles_claim']]).get(userAttribute);
    if (claim && target) {
      if (claims[target] !== undefined && claims[target] !== claim) {
        invalid(path, `conflicts with another ${target} mapping for identity provider ${alias}`);
      }
      claims[target] = claim;
      report.mapped('identity-provider-mapper', path, `federation.oidc[].${target}`, `${alias}:${name}`);
    } else {
      report.unsupported('identity-provider-mapper', path, 'federation.oidc', `${alias}:${name}`,
        'Only direct OIDC username, groups, and roles claim mappings are configurable in AuthMe.');
    }
  }
  return claims;
}

function samlMapperAttributes(mappers, alias, report) {
  const entries = [];
  const targetNames = new Map([
    ['username', 'username'], ['email', 'email'], ['firstName', 'givenName'], ['lastName', 'familyName'],
    ['groups', 'groups'], ['roles', 'roles'],
  ]);
  for (const { input, path } of mappers) {
    const name = optionalString(input.name, `${path}.name`) ?? optionalString(input.identityProviderMapper, `${path}.identityProviderMapper`) ?? 'mapper';
    const type = optionalString(input.identityProviderMapper, `${path}.identityProviderMapper`) ?? '';
    if (!type.includes('saml')) continue;
    const configuration = optionalRecord(input.config, `${path}.config`);
    const attribute = configString(configuration, 'attribute.name') ?? configString(configuration, 'attribute.friendly.name');
    const target = targetNames.get(configString(configuration, 'user.attribute'));
    if (attribute && target) {
      if (entries.some(([existing]) => existing === target)) {
        invalid(path, `duplicates ${target} mapping for identity provider ${alias}`);
      }
      entries.push([target, attribute]);
      report.mapped('identity-provider-mapper', path, `federation.saml[].attribute_mapping.${target}`, `${alias}:${name}`);
    } else {
      report.unsupported('identity-provider-mapper', path, 'federation.saml', `${alias}:${name}`,
        'Only direct SAML profile, group, and role attribute mappings are configurable in AuthMe.');
    }
  }
  return sortedRecord(entries);
}

function componentEntries(source) {
  if (source.components === undefined) return [];
  if (Array.isArray(source.components)) {
    return source.components.map((raw, index) => ({
      input: record(raw, `components[${index}]`), path: `components[${index}]`, componentType: undefined,
    }));
  }
  const components = record(source.components, 'components');
  const result = [];
  for (const componentType of Object.keys(components).sort(compare)) {
    for (const [index, raw] of array(components[componentType], `components.${componentType}`).entries()) {
      const path = `components.${componentType}[${index}]`;
      result.push({ input: record(raw, path), path, componentType });
    }
  }
  return result;
}

function certificatePem(value) {
  if (!value) return undefined;
  if (value.includes('-----BEGIN CERTIFICATE-----')) return value.trim();
  const compact = value.replace(/\s+/gu, '');
  if (!/^[A-Za-z0-9+/=]+$/u.test(compact) || compact.length < 64) return undefined;
  return `-----BEGIN CERTIFICATE-----\n${compact.match(/.{1,64}/gu).join('\n')}\n-----END CERTIFICATE-----`;
}

function identityProviderMappers(source) {
  const result = new Map();
  for (const [index, raw] of optionalArray(source.identityProviderMappers, 'identityProviderMappers').entries()) {
    const path = `identityProviderMappers[${index}]`;
    const input = record(raw, path);
    const alias = requiredString(input.identityProviderAlias, `${path}.identityProviderAlias`);
    if (!result.has(alias)) result.set(alias, []);
    result.get(alias).push({ input, path });
  }
  return result;
}

function mapIdentityProviders(source, report) {
  const oidc = [];
  const saml = [];
  const aliases = new Map();
  const seenAliases = new Set();
  const ids = new Set();
  const mappers = identityProviderMappers(source);
  for (const [index, raw] of optionalArray(source.identityProviders, 'identityProviders').entries()) {
    const path = `identityProviders[${index}]`;
    const input = record(raw, path);
    optionalBooleans(input, path, ['enabled', 'trustEmail', 'storeToken', 'linkOnly']);
    const alias = requiredString(input.alias, `${path}.alias`);
    if (seenAliases.has(alias)) invalid(`${path}.alias`, `duplicates identity provider ${alias}`);
    seenAliases.add(alias);
    if (input.enabled === false) {
      report.unsupported('identity-provider', path, 'federation', alias,
        'Disabled identity providers are omitted so the import cannot accidentally enable them.');
      continue;
    }
    const id = normalizeProviderId(alias, `${path}.alias`, report);
    if (!id) continue;
    if (ids.has(id)) invalid(`${path}.alias`, `normalizes to duplicate provider id ${id}`);
    ids.add(id);
    const type = requiredString(input.providerId, `${path}.providerId`).toLowerCase();
    const configuration = optionalRecord(input.config, `${path}.config`);
    const providerMappers = mappers.get(alias) ?? [];
    if (['oidc', 'keycloak-oidc'].includes(type)) {
      const issuer = oidcIssuer(configString(configuration, 'issuer'));
      const authorizationEndpoint = providerUrl(configString(configuration, 'authorizationUrl'), `${path}.config.authorizationUrl`);
      const tokenEndpoint = providerUrl(configString(configuration, 'tokenUrl'), `${path}.config.tokenUrl`);
      const jwksUri = providerUrl(configString(configuration, 'jwksUrl') ?? configString(configuration, 'jwksUri'), `${path}.config.jwksUrl`);
      const clientId = configString(configuration, 'clientId');
      if (!issuer || !authorizationEndpoint || !tokenEndpoint || !jwksUri || !clientId) {
        report.unsupported('identity-provider', path, 'federation.oidc', alias,
          'OIDC provider is missing an exact issuer, authorization endpoint, token endpoint, JWKS URI, or client ID.');
        continue;
      }
      const authMethod = configString(configuration, 'clientAuthMethod') ?? 'client_secret_post';
      if (!['client_secret_basic', 'client_secret_post'].includes(authMethod)) {
        report.unsupported('identity-provider', `${path}.config.clientAuthMethod`, 'federation.oidc', alias,
          `Upstream OIDC authentication method ${authMethod} is not supported.`);
        continue;
      }
      const scopes = uniqueSorted(['openid', ...normalizeStringList(configString(configuration, 'defaultScope'), `${path}.config.defaultScope`, { split: true })]);
      oidc.push({
        id,
        display_name: optionalString(input.displayName, `${path}.displayName`) ?? alias,
        issuer,
        authorization_endpoint: authorizationEndpoint,
        token_endpoint: tokenEndpoint,
        jwks_uri: jwksUri,
        ...(providerUrl(configString(configuration, 'userInfoUrl'), `${path}.config.userInfoUrl`)
          ? { userinfo_endpoint: providerUrl(configString(configuration, 'userInfoUrl'), `${path}.config.userInfoUrl`) } : {}),
        client_id: clientId,
        client_secret: clientSecretPlaceholder,
        token_endpoint_auth_method: authMethod,
        scopes,
        ...oidcMapperClaims(providerMappers, alias, report),
        require_email: true,
        jit_provisioning: !configBoolean(configuration, 'linkOnly'),
      });
      aliases.set(alias, { id, issuer, type: 'oidc' });
      report.warning('identity-provider', path, 'federation.oidc', alias,
        'Provider endpoints were mapped, but its source client secret was omitted; rotate and inject a new secret.');
      continue;
    }
    if (type === 'saml') {
      const entityId = samlEntityId(configString(configuration, 'entityId'));
      const ssoUrl = exactHttpsUrl(configString(configuration, 'singleSignOnServiceUrl'));
      const signingCertificate = certificatePem(configString(configuration, 'signingCertificate'));
      if (!entityId || !ssoUrl || !signingCertificate) {
        report.unsupported('identity-provider', path, 'federation.saml', alias,
          'SAML provider is missing an HTTPS entity ID, SSO URL, or usable signing certificate.');
        continue;
      }
      saml.push({
        id,
        display_name: optionalString(input.displayName, `${path}.displayName`) ?? alias,
        idp_entity_id: entityId,
        idp_sso_url: ssoUrl,
        idp_signing_certificates: [signingCertificate],
        attribute_mapping: samlMapperAttributes(providerMappers, alias, report),
        trust_email: configBoolean(configuration, 'trustEmail'),
        jit_provisioning: !configBoolean(configuration, 'linkOnly'),
      });
      aliases.set(alias, { id, issuer: entityId, type: 'saml' });
      report.mapped('identity-provider', path, 'federation.saml', alias);
      continue;
    }
    report.unsupported('identity-provider', path, 'federation', alias,
      `Provider type ${type} has no automatic AuthMe federation mapping.`);
  }
  for (const [alias, values] of mappers) {
    if (aliases.has(alias)) continue;
    for (const { input, path } of values) {
      const name = optionalString(input.name, `${path}.name`) ?? 'mapper';
      report.unsupported('identity-provider-mapper', path, 'federation', `${alias}:${name}`,
        'Mapper belongs to an identity provider that was not mapped.');
    }
  }
  return {
    oidc: oidc.sort((left, right) => compare(left.id, right.id)),
    saml: saml.sort((left, right) => compare(left.id, right.id)),
    aliases,
  };
}

function mapLdapProviders(source, report) {
  const components = componentEntries(source);
  const providers = [];
  const ids = new Set();
  for (const { input, path } of components) {
    if ((optionalString(input.providerId, `${path}.providerId`) ?? '').toLowerCase() !== 'ldap') continue;
    const name = optionalString(input.name, `${path}.name`) ?? optionalString(input.id, `${path}.id`) ?? 'ldap';
    const id = normalizeProviderId(name, `${path}.name`, report);
    if (!id) continue;
    if (ids.has(id)) invalid(`${path}.name`, `normalizes to duplicate LDAP provider id ${id}`);
    ids.add(id);
    const configuration = optionalRecord(input.config, `${path}.config`);
    if (!configBoolean(configuration, 'enabled', true)) {
      report.unsupported('ldap-provider', path, 'federation.ldap', name,
        'Disabled LDAP provider was omitted so the import cannot accidentally enable it.');
      continue;
    }
    const url = configString(configuration, 'connectionUrl');
    const userBaseDn = configString(configuration, 'usersDn');
    const startTls = configBoolean(configuration, 'startTls');
    let parsedUrl;
    try { parsedUrl = new URL(url); } catch { parsedUrl = undefined; }
    if (!parsedUrl || !['ldap:', 'ldaps:'].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password
      || parsedUrl.search || parsedUrl.hash || (parsedUrl.pathname && parsedUrl.pathname !== '/') || !userBaseDn
      || (parsedUrl.protocol === 'ldap:' && !startTls) || (parsedUrl.protocol === 'ldaps:' && startTls)) {
      report.unsupported('ldap-provider', path, 'federation.ldap', name,
        'LDAP provider requires an LDAP(S) origin, user base DN, and either LDAPS or valid StartTLS configuration.');
      continue;
    }
    const bindDn = configString(configuration, 'bindDn');
    const hasBindCredential = configString(configuration, 'bindCredential') !== undefined;
    if (Boolean(bindDn) !== hasBindCredential) {
      report.unsupported('ldap-provider', path, 'federation.ldap', name,
        'Bind DN and bind credential must either both be configured or both be absent.');
      continue;
    }
    const mappings = {
      username_attribute: configString(configuration, 'usernameLDAPAttribute') ?? 'uid',
      email_attribute: 'mail',
      display_name_attribute: 'displayName',
      given_name_attribute: 'givenName',
      family_name_attribute: 'sn',
      external_id_attribute: configString(configuration, 'uuidLDAPAttribute') ?? 'entryUUID',
    };
    for (const component of components.filter(({ input: candidate }) => candidate.parentId === input.id)) {
      const mapperType = optionalString(component.input.providerId, `${component.path}.providerId`) ?? '';
      const mapperConfig = optionalRecord(component.input.config, `${component.path}.config`);
      if (mapperType === 'user-attribute-ldap-mapper') {
        const model = configString(mapperConfig, 'user.model.attribute');
        const ldap = configString(mapperConfig, 'ldap.attribute');
        const target = new Map([
          ['email', 'email_attribute'], ['firstName', 'given_name_attribute'], ['lastName', 'family_name_attribute'],
          ['username', 'username_attribute'],
        ]).get(model);
        if (target && ldap) {
          mappings[target] = ldap;
          report.mapped('ldap-mapper', component.path, `federation.ldap[].${target}`, `${name}:${model}`);
        } else {
          report.unsupported('ldap-mapper', component.path, 'federation.ldap', `${name}:${component.input.name ?? mapperType}`,
            'Only direct LDAP username/email/given-name/family-name attribute mappings are portable.');
        }
      } else {
        report.unsupported('ldap-mapper', component.path, 'federation.ldap', `${name}:${component.input.name ?? mapperType}`,
          'LDAP group/role synchronization and custom mapper semantics are not supported by AuthMe\'s authentication baseline.');
      }
    }
    const objectClasses = (configString(configuration, 'userObjectClasses') ?? 'person').split(',').map((value) => value.trim()).filter(Boolean);
    const ldapAttributePattern = /^[a-zA-Z][a-zA-Z0-9-]{0,63}$/u;
    if (!objectClasses.length || !ldapAttributePattern.test(objectClasses[0])
      || Object.values(mappings).some((value) => !ldapAttributePattern.test(value))) {
      report.unsupported('ldap-provider', path, 'federation.ldap', name,
        'LDAP object class or mapped attribute name is outside AuthMe\'s portable LDAP attribute profile.');
      continue;
    }
    providers.push({
      id,
      display_name: name,
      url: parsedUrl.href.replace(/\/$/u, ''),
      start_tls: startTls,
      ...(bindDn ? { bind_dn: bindDn, bind_password: bindSecretPlaceholder } : {}),
      user_base_dn: userBaseDn,
      user_object_class: objectClasses[0] ?? 'person',
      login_attributes: uniqueSorted([mappings.username_attribute, mappings.email_attribute, 'userPrincipalName', 'sAMAccountName']),
      ...mappings,
      groups_attribute: 'memberOf',
      jit_provisioning: configBoolean(configuration, 'importEnabled', true),
    });
    report.warning('ldap-provider', path, 'federation.ldap', name,
      bindDn
        ? 'LDAP authentication settings were mapped, but the bind credential was omitted; rotate and inject it. Synchronization semantics were not copied.'
        : 'LDAP authentication settings were mapped for anonymous search; synchronization semantics were not copied.');
  }
  for (const { input, path, componentType } of components) {
    const providerId = optionalString(input.providerId, `${path}.providerId`) ?? 'unknown';
    if (providerId === 'ldap' || input.parentId !== undefined) continue;
    const item = optionalString(input.name, `${path}.name`) ?? providerId;
    if (componentType?.includes('KeyProvider')) {
      report.unsupported('realm-component', path, 'realm', item,
        'Keycloak signing/encryption key providers and key material are never imported.');
    } else if (componentType?.includes('UserStorageProvider') || ['kerberos', 'custom'].includes(providerId)) {
      report.unsupported('user-storage-provider', path, 'federation', item,
        `User storage provider ${providerId} has no automatic AuthMe mapping.`);
    } else {
      report.unsupported('realm-component', path, 'realm', item,
        'Keycloak component configuration has no automatic AuthMe mapping.');
    }
  }
  return providers.sort((left, right) => compare(left.id, right.id));
}

function materializedGroupRoles(groupPaths, groupsByPath) {
  const realmRoles = [];
  const clientRoles = new Map();
  for (const membership of groupPaths) {
    let path = membership;
    while (path) {
      const group = groupsByPath.get(path);
      if (group) {
        realmRoles.push(...group.realmRoles);
        for (const [clientId, roles] of Object.entries(group.clientRoles)) {
          if (!clientRoles.has(clientId)) clientRoles.set(clientId, []);
          clientRoles.get(clientId).push(...roles);
        }
      }
      const separator = path.lastIndexOf('/');
      path = separator > 0 ? path.slice(0, separator) : '';
    }
  }
  return {
    realmRoles: uniqueSorted(realmRoles),
    clientRoles: sortedRecord([...clientRoles].map(([clientId, roles]) => [clientId, uniqueSorted(roles)])),
  };
}

function mergeClientRoles(direct, inherited) {
  const keys = uniqueSorted([...Object.keys(direct), ...Object.keys(inherited)]);
  return sortedRecord(keys.map((clientId) => [clientId, uniqueSorted([
    ...(Object.hasOwn(direct, clientId) ? direct[clientId] : []),
    ...(Object.hasOwn(inherited, clientId) ? inherited[clientId] : []),
  ])]));
}

function mapUsers(source, realmName, groups, providerAliases, report) {
  const users = [];
  const federatedIdentities = [];
  const usernames = new Set();
  const sourceUsernames = new Set();
  const emails = new Set();
  const groupsByPath = new Map(groups.map((group) => [group.path, group]));
  for (const [index, raw] of optionalArray(source.users, 'users').entries()) {
    const path = `users[${index}]`;
    const input = record(raw, path);
    const username = requiredString(input.username, `${path}.username`);
    const sourceUsernameKey = username.toLowerCase();
    if (sourceUsernames.has(sourceUsernameKey)) invalid(`${path}.username`, `duplicates username ${username}`);
    sourceUsernames.add(sourceUsernameKey);
    const serviceAccountClientId = optionalString(input.serviceAccountClientId, `${path}.serviceAccountClientId`);
    if (serviceAccountClientId) {
      report.unsupported('service-account-user', path, 'clients[].grant_types/resource policy', serviceAccountClientId,
        'Keycloak service-account users and their role assignments are not local AuthMe users; reconcile Client Credentials and resource policy manually.');
      continue;
    }
    const usernameKey = username.toLowerCase();
    if (usernames.has(usernameKey) || emails.has(usernameKey)) {
      invalid(`${path}.username`, `duplicates an existing username or email (${username})`);
    }
    const rawEmail = optionalString(input.email, `${path}.email`);
    if (!rawEmail) {
      report.unsupported('user', path, 'users', username,
        'User has no email address, which AuthMe requires for a local account.');
      continue;
    }
    const email = rawEmail.toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(email) || email.length > 254) {
      report.unsupported('user', `${path}.email`, 'users', username,
        'Email is outside AuthMe\'s local-account email profile.');
      continue;
    }
    if (emails.has(email) || (usernames.has(email) && email !== usernameKey)) {
      invalid(`${path}.email`, `duplicates an existing username or email (${email})`);
    }
    usernames.add(usernameKey);
    emails.add(email);
    const sourceId = optionalString(input.id, `${path}.id`);
    const id = sourceId && uuidPattern.test(sourceId) ? sourceId : deterministicUuid(realmName, username);
    if (!sourceId || id !== sourceId) {
      report.warning('user-subject', `${path}.id`, 'users[].id', username,
        'A deterministic UUID was derived because the exported Keycloak ID was absent or not a UUID; review subject continuity.');
    }
    const groupPaths = uniqueSorted(optionalArray(input.groups, `${path}.groups`).map((group, groupIndex) =>
      normalizeGroupPath(group, `${path}.groups[${groupIndex}]`, report, username)).filter(Boolean));
    for (const groupPath of groupPaths) {
      if (!groupsByPath.has(groupPath)) {
        report.warning('group-membership', `${path}.groups`, 'users[].groups', `${username}:${groupPath}`,
          'Membership path is not defined in this export; it was retained for partial-export compatibility.');
      }
    }
    const inherited = materializedGroupRoles(groupPaths, groupsByPath);
    const directRoles = safeRoleNames(input.realmRoles, `${path}.realmRoles`, report, username, 'users[].roles');
    const directClientRoles = normalizeClientRoleAssignments(input.clientRoles, `${path}.clientRoles`, report, username, 'users[].clientRoles');
    const credentials = optionalArray(input.credentials, `${path}.credentials`);
    const credentialTypes = uniqueSorted(credentials.map((credential, credentialIndex) => {
      const value = record(credential, `${path}.credentials[${credentialIndex}]`);
      return optionalString(value.type, `${path}.credentials[${credentialIndex}].type`) ?? 'unknown';
    }));
    for (const type of credentialTypes) {
      report.unsupported('user-credential', `${path}.credentials`, 'users[].credentialMigration', `${username}:${type}`,
        type === 'password'
          ? 'Keycloak password hash records are not portable to AuthMe; require reset or a separately reviewed hash bridge.'
          : 'Existing Keycloak MFA/passkey/recovery credential material is not imported; require fresh AuthMe enrollment.');
    }
    if (input.totp === true && !credentialTypes.includes('otp')) {
      report.unsupported('user-credential', `${path}.totp`, 'users[].credentialMigration', `${username}:otp`,
        'Keycloak TOTP state is not portable; require fresh AuthMe enrollment.');
    }
    const requiredActions = normalizeStringList(input.requiredActions, `${path}.requiredActions`);
    for (const action of requiredActions) {
      report.unsupported('required-action', `${path}.requiredActions`, 'users', `${username}:${action}`,
        'Keycloak required-action workflows are not imported.');
    }
    const inheritedRoleCount = inherited.realmRoles.length
      + Object.values(inherited.clientRoles).reduce((total, roles) => total + roles.length, 0);
    if (inheritedRoleCount) {
      report.warning('group-role-mapping', `${path}.groups`, 'users[].roles/clientRoles', username,
        'Group and ancestor-group role assignments were materialized onto the user.');
    }
    const name = [optionalString(input.firstName, `${path}.firstName`), optionalString(input.lastName, `${path}.lastName`)]
      .filter(Boolean).join(' ') || username;
    users.push({
      id,
      realm: realmName,
      username,
      email,
      emailVerified: boolean(input.emailVerified, false, `${path}.emailVerified`),
      name,
      givenName: optionalString(input.firstName, `${path}.firstName`) ?? '',
      familyName: optionalString(input.lastName, `${path}.lastName`) ?? '',
      enabled: boolean(input.enabled, true, `${path}.enabled`),
      attributes: normalizeAttributes(input.attributes, `${path}.attributes`, report, username),
      roles: uniqueSorted([...directRoles, ...inherited.realmRoles]),
      groups: groupPaths,
      clientRoles: mergeClientRoles(directClientRoles, inherited.clientRoles),
      credentialMigration: {
        password: credentialTypes.includes('password') ? 'reset-required' : 'not-exported-or-not-present',
        mfa: credentialTypes.some((type) => type !== 'password') || input.totp === true
          ? 'reenrollment-required' : 'not-exported-or-not-present',
      },
    });
    report.mapped('user', path, 'users', username);
    if (rawEmail !== email) {
      report.warning('user', `${path}.email`, 'users[].email', username,
        'Email was normalized to lowercase to match AuthMe account lookup semantics.');
    }

    for (const [identityIndex, rawIdentity] of optionalArray(input.federatedIdentities, `${path}.federatedIdentities`).entries()) {
      const identityPath = `${path}.federatedIdentities[${identityIndex}]`;
      const identity = record(rawIdentity, identityPath);
      const alias = requiredString(identity.identityProvider, `${identityPath}.identityProvider`);
      const provider = providerAliases.get(alias);
      const externalSubject = optionalString(identity.userId, `${identityPath}.userId`);
      if (!provider || !externalSubject) {
        report.unsupported('federated-identity', identityPath, 'federation.federatedIdentities', `${username}:${alias}`,
          'Link requires a mapped provider and an immutable exported external subject.');
        continue;
      }
      federatedIdentities.push({
        realm: realmName,
        userId: id,
        providerId: provider.id,
        issuer: provider.issuer,
        externalSubject,
      });
      report.mapped('federated-identity', identityPath, 'federation.federatedIdentities', `${username}:${alias}`);
    }
  }
  users.sort((left, right) => compare(left.username, right.username));
  federatedIdentities.sort((left, right) => compare(
    `${left.userId}\0${left.providerId}\0${left.externalSubject}`,
    `${right.userId}\0${right.providerId}\0${right.externalSubject}`,
  ));
  return { users, federatedIdentities };
}

function reportUnsupportedRealmFeatures(source, report, realmName) {
  const features = [
    ['authenticationFlows', 'Custom authentication flows and executions are not portable.'],
    ['authenticatorConfig', 'Custom authenticator configuration is not portable.'],
    ['requiredActions', 'Realm required-action workflows are not imported.'],
    ['organizations', 'Keycloak organizations are not supported by this import model.'],
    ['scopeMappings', 'Keycloak scope mappings require manual AuthMe resource/scope policy review.'],
    ['clientInitialAccess', 'Initial access tokens are runtime credentials and are never imported.'],
  ];
  for (const [field, reason] of features) {
    const value = source[field];
    const active = Array.isArray(value) ? value.length > 0 : isRecord(value) ? Object.keys(value).length > 0 : Boolean(value);
    if (active) report.unsupported('realm-feature', field, 'realm', realmName, reason);
  }
  if (typeof source.passwordPolicy === 'string' && source.passwordPolicy.trim()) {
    report.unsupported('realm-feature', 'passwordPolicy', 'realm', realmName,
      'Keycloak password-policy expressions do not map to AuthMe\'s fixed Argon2id/password policy.');
  }
  if (source.otpPolicyType !== undefined || source.webAuthnPolicyRpEntityName !== undefined
    || source.webAuthnPolicyPasswordlessRpEntityName !== undefined) {
    report.unsupported('realm-feature', 'otpPolicy/webAuthnPolicy', 'realm', realmName,
      'Existing Keycloak MFA/WebAuthn policy and credentials require an AuthMe policy review and fresh enrollment.');
  }
  if (isRecord(source.smtpServer) && Object.keys(source.smtpServer).length) {
    report.unsupported('realm-feature', 'smtpServer', 'realm', realmName,
      'SMTP configuration, including any credentials, is not copied into the import artifact or report.');
  }
  for (const field of ['offlineSessions', 'userSessions', 'accessTokens', 'refreshTokens']) {
    if (Array.isArray(source[field]) && source[field].length) {
      report.unsupported('runtime-state', field, 'realm', realmName,
        'Runtime tokens and sessions are deliberately not imported.');
    }
  }
}

function validateTopLevel(source) {
  for (const field of ['clients', 'clientScopes', 'groups', 'users', 'identityProviders', 'identityProviderMappers']) {
    if (source[field] !== undefined && !Array.isArray(source[field])) invalid(field, 'must be an array');
  }
  if (source.components !== undefined && !Array.isArray(source.components) && !isRecord(source.components)) {
    invalid('components', 'must be an array or an object of component arrays');
  }
  if (source.roles !== undefined && !isRecord(source.roles)) invalid('roles', 'must be an object');
}

export function transformKeycloakRealm(sourceInput, options = {}) {
  const source = record(sourceInput, '$');
  const settings = record(options, 'options');
  if (settings.issuer !== undefined && settings.publicUrl !== undefined) {
    invalid('options', 'issuer and publicUrl are mutually exclusive');
  }
  validateTopLevel(source);
  const realmName = requiredString(source.realm, 'realm');
  if (!realmNamePattern.test(realmName)) {
    invalid('realm', 'must match AuthMe realm names: lowercase letter followed by lowercase letters, digits, or hyphens');
  }
  const report = reportBuilder(realmName);
  const realmMapping = mapRealm(source, realmName, settings, report);
  const clients = mapClients(source, report);
  const roles = mapRoles(source, report);
  const groups = mapGroups(source, report);
  const idp = mapIdentityProviders(source, report);
  const ldap = mapLdapProviders(source, report);
  const { users, federatedIdentities } = mapUsers(source, realmName, groups, idp.aliases, report);
  reportUnsupportedRealmFeatures(source, report, realmName);

  const environment = {
    ...(realmMapping.publicUrl ? { AUTHME_PUBLIC_URL: realmMapping.publicUrl } : {}),
    AUTHME_REALMS: realmName,
    ...(realmMapping.lifetimes.accessToken !== undefined
      ? { AUTHME_ACCESS_TOKEN_TTL_SECONDS: realmMapping.lifetimes.accessToken } : {}),
    ...(realmMapping.lifetimes.authorizationCode !== undefined
      ? { AUTHME_AUTHORIZATION_CODE_TTL_SECONDS: realmMapping.lifetimes.authorizationCode } : {}),
    ...(realmMapping.lifetimes.session !== undefined
      ? { AUTHME_SESSION_TTL_SECONDS: realmMapping.lifetimes.session } : {}),
    AUTHME_CLIENTS_JSON: { [realmName]: clients },
    AUTHME_LDAP_PROVIDERS_JSON: { [realmName]: ldap },
    AUTHME_OIDC_PROVIDERS_JSON: { [realmName]: idp.oidc },
    AUTHME_SAML_PROVIDERS_JSON: { [realmName]: idp.saml },
  };
  const config = {
    schemaVersion: 'authme.keycloak-import/v1',
    realm: realmMapping.realm,
    clients,
    roles,
    groups,
    users,
    federation: {
      ldap,
      oidc: idp.oidc,
      saml: idp.saml,
      federatedIdentities,
    },
    environment,
  };
  return deepFreeze({ config, report: report.finish() });
}

export const transformKeycloakRealmExport = transformKeycloakRealm;
export const importKeycloakRealm = transformKeycloakRealm;

export function formatCompatibilityReport(reportInput) {
  const report = record(reportInput, 'report');
  const sections = [
    ['Mapped', report.mapped],
    ['Transformed with warnings', report.transformedWithWarnings],
    ['Unsupported or skipped', report.unsupportedOrSkipped],
  ];
  const lines = [
    'Keycloak compatibility report',
    `Realm: ${report.realm}`,
    `Summary: ${report.summary.mapped} mapped; ${report.summary.transformedWithWarnings} transformed with warnings; ${report.summary.unsupportedOrSkipped} unsupported or skipped`,
  ];
  for (const [title, rawEntries] of sections) {
    const entries = array(rawEntries, `report.${title}`);
    lines.push('', `${title} (${entries.length})`);
    if (!entries.length) {
      lines.push('- None');
      continue;
    }
    for (const entry of entries) {
      const reason = entry.reason ? ` — ${entry.reason}` : '';
      lines.push(`- [${entry.category}] ${entry.item}: ${entry.source} -> ${entry.target}${reason}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

export const renderCompatibilityReport = formatCompatibilityReport;
