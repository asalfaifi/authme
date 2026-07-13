import { isIP } from 'node:net';
import { z } from 'zod';

import { AUTHME_EXTENSION_API_VERSION } from '../authentication/registry.js';

const attributeName = z.string().regex(/^[a-zA-Z][a-zA-Z0-9-]{0,63}$/);
const providerId = z.string().regex(/^[a-z][a-z0-9-]{1,31}$/);
const providerSchema = z.object({
  id: providerId,
  display_name: z.string().trim().min(1).max(100),
  url: z.string().url(),
  start_tls: z.boolean().optional().default(false),
  allow_insecure_development: z.boolean().optional().default(false),
  ca_certificate: z.string().min(1).optional(),
  bind_dn: z.string().trim().min(1).max(2048).optional(),
  bind_password: z.string().min(1).max(4096).optional(),
  user_base_dn: z.string().trim().min(1).max(2048),
  user_object_class: attributeName.optional().default('person'),
  login_attributes: z.array(attributeName).min(1).max(5).optional().default(['uid', 'mail', 'userPrincipalName', 'sAMAccountName']),
  username_attribute: attributeName.optional().default('uid'),
  email_attribute: attributeName.optional().default('mail'),
  display_name_attribute: attributeName.optional().default('displayName'),
  given_name_attribute: attributeName.optional().default('givenName'),
  family_name_attribute: attributeName.optional().default('sn'),
  external_id_attribute: attributeName.optional().default('entryUUID'),
  groups_attribute: attributeName.optional().default('memberOf'),
  roles_attribute: attributeName.optional(),
  jit_provisioning: z.boolean().optional().default(false),
  connect_timeout_ms: z.number().int().min(500).max(20_000).optional().default(5_000),
  operation_timeout_ms: z.number().int().min(500).max(20_000).optional().default(5_000),
}).strict();

function freezeProviders(value) {
  for (const providers of Object.values(value)) {
    for (const provider of providers) Object.freeze(provider);
    Object.freeze(providers);
  }
  return Object.freeze(value);
}

function configurationError(message, cause) {
  return Object.assign(new Error(`Invalid LDAP provider configuration: ${message}`, cause ? { cause } : undefined), {
    code: 'AUTHME_LDAP_CONFIGURATION_INVALID',
  });
}

export function parseLdapProviders(value, { realms, devMode }) {
  if (!value) return freezeProviders(Object.fromEntries(realms.map((realm) => [realm, []])));
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) {
    throw configurationError('AUTHME_LDAP_PROVIDERS_JSON must contain valid JSON', error);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw configurationError('AUTHME_LDAP_PROVIDERS_JSON must be an object keyed by realm');
  }
  const unknownRealms = Object.keys(parsed).filter((realm) => !realms.includes(realm));
  if (unknownRealms.length) throw configurationError(`unknown realms: ${unknownRealms.join(', ')}`);

  const result = {};
  for (const realm of realms) {
    if (!Array.isArray(parsed[realm] ?? [])) throw configurationError(`${realm} must be an array`);
    const ids = new Set();
    result[realm] = (parsed[realm] ?? []).map((input, index) => {
      const validation = providerSchema.safeParse(input);
      if (!validation.success) {
        const issue = validation.error.issues[0];
        throw configurationError(`${realm}[${index}].${issue.path.join('.') || 'provider'}: ${issue.message}`);
      }
      const provider = validation.data;
      if (ids.has(provider.id)) throw configurationError(`${realm} contains duplicate provider id ${provider.id}`);
      ids.add(provider.id);
      if (Boolean(provider.bind_dn) !== Boolean(provider.bind_password)) {
        throw configurationError(`${realm}.${provider.id} must set both bind_dn and bind_password`);
      }
      let url;
      try { url = new URL(provider.url); } catch (error) { throw configurationError(`${realm}.${provider.id}.url is invalid`, error); }
      if (!['ldap:', 'ldaps:'].includes(url.protocol) || url.username || url.password || url.search || url.hash
        || (url.pathname && url.pathname !== '/')) {
        throw configurationError(`${realm}.${provider.id}.url must contain only an LDAP(S) origin`);
      }
      if (url.protocol === 'ldaps:' && provider.start_tls) {
        throw configurationError(`${realm}.${provider.id} cannot use StartTLS with ldaps://`);
      }
      const loopback = isIP(url.hostname) ? ['127.0.0.1', '::1'].includes(url.hostname) : url.hostname === 'localhost';
      if (url.protocol === 'ldap:' && !provider.start_tls
        && !(devMode && loopback && provider.allow_insecure_development)) {
        throw configurationError(`${realm}.${provider.id} must use ldaps:// or StartTLS`);
      }
      if (provider.allow_insecure_development && !(devMode && loopback)) {
        throw configurationError(`${realm}.${provider.id}.allow_insecure_development is limited to development loopback`);
      }
      return {
        id: provider.id,
        displayName: provider.display_name,
        url: url.href.replace(/\/$/, ''),
        startTls: provider.start_tls,
        caCertificate: provider.ca_certificate,
        bindDn: provider.bind_dn,
        bindPassword: provider.bind_password,
        userBaseDn: provider.user_base_dn,
        userObjectClass: provider.user_object_class,
        loginAttributes: [...new Set(provider.login_attributes)],
        usernameAttribute: provider.username_attribute,
        emailAttribute: provider.email_attribute,
        displayNameAttribute: provider.display_name_attribute,
        givenNameAttribute: provider.given_name_attribute,
        familyNameAttribute: provider.family_name_attribute,
        externalIdAttribute: provider.external_id_attribute,
        groupsAttribute: provider.groups_attribute,
        rolesAttribute: provider.roles_attribute,
        jitProvisioning: provider.jit_provisioning,
        connectTimeoutMs: provider.connect_timeout_ms,
        operationTimeoutMs: provider.operation_timeout_ms,
      };
    });
  }
  return freezeProviders(result);
}

// RFC 4515 escaping. Non-printable/non-ASCII bytes are escaped as well so the
// resulting filter remains unambiguous across directory server implementations.
export function escapeLdapFilterValue(input) {
  let result = '';
  for (const byte of Buffer.from(String(input), 'utf8')) {
    if (byte < 0x20 || byte > 0x7e || [0x2a, 0x28, 0x29, 0x5c].includes(byte)) {
      result += `\\${byte.toString(16).padStart(2, '0')}`;
    } else {
      result += String.fromCharCode(byte);
    }
  }
  return result;
}

function userFilter(provider, login) {
  const escaped = escapeLdapFilterValue(login);
  const alternatives = provider.loginAttributes.map((attribute) => `(${attribute}=${escaped})`).join('');
  return `(&(objectClass=${provider.userObjectClass})(|${alternatives}))`;
}

function entryValue(entry, name) {
  const key = Object.keys(entry).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
  return key ? entry[key] : undefined;
}

function strings(value) {
  return (Array.isArray(value) ? value : value === undefined || value === null ? [] : [value])
    .map((item) => Buffer.isBuffer(item) ? item.toString('utf8') : String(item))
    .map((item) => item.trim())
    .filter(Boolean);
}

function first(entry, attribute) {
  return strings(entryValue(entry, attribute))[0] ?? '';
}

function groupPath(value) {
  const match = /(?:^|,)\s*cn=([^,]+)/i.exec(value);
  const name = (match?.[1] ?? value).trim().replaceAll('/', '-');
  return name ? `/${name}` : null;
}

function externalSubject(entry, provider, dn) {
  const value = entryValue(entry, provider.externalIdAttribute);
  if (Buffer.isBuffer(value)) return value.toString('base64url');
  const item = Array.isArray(value) ? value[0] : value;
  return item === undefined || item === null || String(item).trim() === '' ? dn : String(item).trim();
}

function profileFor(entry, provider, login, dn) {
  const username = first(entry, provider.usernameAttribute) || login;
  const email = first(entry, provider.emailAttribute);
  const groupValues = strings(entryValue(entry, provider.groupsAttribute));
  return {
    externalSubject: externalSubject(entry, provider, dn),
    username,
    email,
    emailVerified: false,
    name: first(entry, provider.displayNameAttribute) || username,
    givenName: first(entry, provider.givenNameAttribute),
    familyName: first(entry, provider.familyNameAttribute),
    groups: [...new Set(groupValues.map(groupPath).filter(Boolean))],
    roles: provider.rolesAttribute ? [...new Set(strings(entryValue(entry, provider.rolesAttribute)))] : [],
  };
}

async function defaultClientFactory(options) {
  const { Client } = await import('ldapts');
  return new Client(options);
}

async function closeClient(client) {
  try { await client?.unbind?.(); } catch { /* The connection may already be closed. */ }
}

function clientOptions(provider) {
  return {
    url: provider.url,
    connectTimeout: provider.connectTimeoutMs,
    timeout: provider.operationTimeoutMs,
    strictDN: true,
    tlsOptions: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true,
      ...(provider.caCertificate ? { ca: [provider.caCertificate] } : {}),
    },
  };
}

async function secureClient(provider, clientFactory) {
  const client = await clientFactory(clientOptions(provider));
  try {
    if (provider.startTls) {
      await client.startTLS({
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true,
        ...(provider.caCertificate ? { ca: [provider.caCertificate] } : {}),
      });
    }
    return client;
  } catch (error) {
    await closeClient(client);
    throw error;
  }
}

function invalidCredentials(error) {
  return error?.code === 49 || error?.code === '49' || error?.name === 'InvalidCredentialsError';
}

function loggableError(error) {
  const result = {};
  if (typeof error?.name === 'string' && error.name.length <= 100) result.name = error.name;
  if ((typeof error?.code === 'string' || typeof error?.code === 'number') && String(error.code).length <= 100) {
    result.code = error.code;
  }
  return result;
}

export async function authenticateLdapProvider(provider, { login, secret }, { clientFactory = defaultClientFactory } = {}) {
  if (!String(login).trim() || !String(secret)) return { status: 'failure' };
  let searchClient;
  try {
    searchClient = await secureClient(provider, clientFactory);
    if (provider.bindDn) await searchClient.bind(provider.bindDn, provider.bindPassword);
    const attributes = [...new Set([
      provider.usernameAttribute, provider.emailAttribute, provider.displayNameAttribute,
      provider.givenNameAttribute, provider.familyNameAttribute, provider.externalIdAttribute,
      provider.groupsAttribute, provider.rolesAttribute,
    ].filter(Boolean))];
    const { searchEntries } = await searchClient.search(provider.userBaseDn, {
      scope: 'sub',
      filter: userFilter(provider, String(login).trim()),
      attributes,
      sizeLimit: 2,
      timeLimit: Math.max(1, Math.ceil(provider.operationTimeoutMs / 1000)),
    });
    if (searchEntries.length !== 1) return { status: 'failure' };
    const entry = searchEntries[0];
    const dn = String(entry.dn ?? '').trim();
    if (!dn) return { status: 'failure' };

    let authClient;
    try {
      authClient = await secureClient(provider, clientFactory);
      await authClient.bind(dn, String(secret));
    } catch (error) {
      if (invalidCredentials(error)) return { status: 'failure' };
      throw error;
    } finally {
      await closeClient(authClient);
    }

    return {
      status: 'success',
      protocol: 'ldap',
      providerId: provider.id,
      issuer: provider.url,
      allowCreate: provider.jitProvisioning,
      profile: profileFor(entry, provider, String(login).trim(), dn),
    };
  } catch (error) {
    if (invalidCredentials(error)) return { status: 'failure' };
    return { status: 'unavailable', providerId: provider.id, error };
  } finally {
    await closeClient(searchClient);
  }
}

export function createLdapExtension({ providersByRealm, clientFactory, logger }) {
  return {
    manifest: {
      apiVersion: AUTHME_EXTENSION_API_VERSION,
      id: 'builtin.ldap',
      kind: 'authenticator',
      displayName: 'LDAP and Active Directory',
      capabilities: ['active-directory', 'jit-provisioning', 'ldap'],
    },
    implementation: {
      enabledFor: (realm) => (providersByRealm[realm]?.length ?? 0) > 0,
      async authenticate({ realm, login, secret }) {
        let unavailable = false;
        for (const provider of providersByRealm[realm] ?? []) {
          const result = await authenticateLdapProvider(provider, { login, secret }, { clientFactory });
          if (result.status === 'success') return result;
          if (result.status === 'unavailable') {
            unavailable = true;
            logger?.warn?.({ realm, providerId: provider.id, error: loggableError(result.error) }, 'LDAP provider unavailable');
          }
        }
        return { status: unavailable ? 'unavailable' : 'failure' };
      },
    },
  };
}
