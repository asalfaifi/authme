import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';

import { AUTHME_EXTENSION_API_VERSION } from '../authentication/registry.js';

const attributeName = z.string().regex(/^[a-zA-Z][a-zA-Z0-9-]{0,63}$/);
const providerId = z.string().regex(/^[a-z][a-z0-9-]{1,31}$/);
const ldapFilter = z.string().trim().min(3).max(4096)
  .refine((value) => value.startsWith('(') && value.endsWith(')') && !/[\u0000-\u001f\u007f]/u.test(value), {
    message: 'must be a parenthesized LDAP filter without control characters',
  });
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
  binary_attributes: z.array(attributeName).max(20).optional().default([]),
  groups_attribute: attributeName.optional().default('memberOf'),
  roles_attribute: attributeName.optional(),
  jit_provisioning: z.boolean().optional().default(false),
  sync_enabled: z.boolean().optional().default(false),
  sync_filter: ldapFilter.optional(),
  sync_page_size: z.number().int().min(1).max(1000).optional().default(200),
  sync_deletion_policy: z.enum(['disable', 'delete']).optional().default('disable'),
  sync_max_deprovision_fraction: z.number().min(0.01).max(1).optional().default(0.2),
  sync_max_deprovision_count: z.number().int().min(1).max(1_000_000).optional().default(100),
  sync_groups: z.boolean().optional().default(true),
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
        binaryAttributes: [...new Map(provider.binary_attributes.map((name) => [name.toLowerCase(), name])).values()],
        groupsAttribute: provider.groups_attribute,
        rolesAttribute: provider.roles_attribute,
        jitProvisioning: provider.jit_provisioning,
        syncEnabled: provider.sync_enabled,
        syncFilter: provider.sync_filter,
        syncPageSize: provider.sync_page_size,
        syncDeletionPolicy: provider.sync_deletion_policy,
        syncMaxDeprovisionFraction: provider.sync_max_deprovision_fraction,
        syncMaxDeprovisionCount: provider.sync_max_deprovision_count,
        syncGroups: provider.sync_groups,
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

function binaryAttribute(provider, attribute) {
  return provider.binaryAttributes?.some((name) => name.toLowerCase() === attribute.toLowerCase()) ?? false;
}

function externalSubject(entry, provider, dn) {
  const value = entryValue(entry, provider.externalIdAttribute);
  const item = Array.isArray(value) ? value[0] : value;
  if (item === undefined || item === null || (Buffer.isBuffer(item) && item.length === 0)
    || (!Buffer.isBuffer(item) && String(item).trim() === '')) return dn;
  if (binaryAttribute(provider, provider.externalIdAttribute)) {
    if (!Buffer.isBuffer(item)) throw invalidSyncEntry(`${provider.externalIdAttribute} was not returned as binary`);
    return item.toString('base64url');
  }
  return (Buffer.isBuffer(item) ? item.toString('utf8') : String(item)).trim();
}

function explicitBufferAttributes(provider) {
  return binaryAttribute(provider, provider.externalIdAttribute) ? [provider.externalIdAttribute] : [];
}

function profileFor(entry, provider, login, dn, { includeGroups = true } = {}) {
  const username = first(entry, provider.usernameAttribute) || login;
  const email = first(entry, provider.emailAttribute);
  const groupValues = includeGroups ? strings(entryValue(entry, provider.groupsAttribute)) : [];
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

function syncFilter(provider) {
  const objectClass = `(objectClass=${provider.userObjectClass})`;
  return provider.syncFilter ? `(&${objectClass}${provider.syncFilter})` : objectClass;
}

function syncAttributes(provider) {
  return [...new Set([
    provider.usernameAttribute, provider.emailAttribute, provider.displayNameAttribute,
    provider.givenNameAttribute, provider.familyNameAttribute, provider.externalIdAttribute,
    provider.syncGroups ? provider.groupsAttribute : null, provider.rolesAttribute,
  ].filter(Boolean))];
}

function invalidSyncEntry(message) {
  return Object.assign(new Error(`Invalid LDAP sync entry: ${message}`), {
    code: 'AUTHME_LDAP_SYNC_ENTRY_INVALID',
  });
}

function syncProfile(entry, provider) {
  const dn = String(entry.dn ?? '').trim();
  const subject = externalSubject(entry, provider, '');
  if (!subject) throw invalidSyncEntry(`missing ${provider.externalIdAttribute}`);
  if (subject.length > 2048 || /[\u0000-\u001f\u007f]/u.test(subject)) {
    throw invalidSyncEntry(`${provider.externalIdAttribute} is invalid`);
  }
  const profile = profileFor(entry, provider, subject, dn, { includeGroups: provider.syncGroups });
  profile.groups.sort((left, right) => left.localeCompare(right));
  profile.roles.sort((left, right) => left.localeCompare(right));
  return { externalSubject: subject, profile };
}

function initialSyncResult(realm, provider) {
  return {
    realm,
    providerId: provider.id,
    pages: 0,
    scanned: 0,
    created: 0,
    updated: 0,
    unchanged: 0,
    conflicts: 0,
    disabled: 0,
    deleted: 0,
    deletionRefused: 0,
    reconciliation: null,
  };
}

async function syncFailure(status, result, error, logger) {
  const level = status === 'unavailable' ? 'warn' : 'error';
  logger?.[level]?.({
    realm: result.realm,
    providerId: result.providerId,
    error: loggableError(error),
  }, status === 'unavailable' ? 'LDAP sync provider unavailable' : 'LDAP sync failed');
  return { ...result, status, error };
}

/**
 * Streams one realm/provider directory into the canonical user store. Each
 * entry commits independently; missing-entry reconciliation begins only after
 * every LDAP page has been received successfully.
 */
export async function syncLdapProvider(provider, { realm, repository }, {
  clientFactory = defaultClientFactory,
  logger,
} = {}) {
  if (typeof realm !== 'string' || !realm) throw new TypeError('LDAP sync realm is required');
  if (!repository?.syncEntry || !repository?.reconcileMissing) {
    throw new TypeError('LDAP sync repository is required');
  }

  const result = initialSyncResult(realm, provider);
  const syncId = randomUUID();
  let startedAt;
  let releaseLock;
  let client;
  try {
    let protocol;
    try { protocol = new URL(provider.url).protocol; } catch { /* Report through the ordinary safe failure path. */ }
    if (protocol !== 'ldaps:' && !(protocol === 'ldap:' && provider.startTls)) {
      return syncFailure('failed', result, configurationError(`${realm}.${provider.id}.url must use LDAPS or StartTLS`), logger);
    }
    try {
      releaseLock = await repository.acquireSyncLock?.({
        realm, providerId: provider.id, issuer: provider.url,
      });
    } catch (error) {
      return syncFailure('failed', result, error, logger);
    }
    if (releaseLock === null) return { ...result, status: 'busy' };
    startedAt = releaseLock?.startedAt ?? new Date().toISOString();

    try {
      client = await secureClient(provider, clientFactory);
      if (provider.bindDn) await client.bind(provider.bindDn, provider.bindPassword);
    } catch (error) {
      return syncFailure('unavailable', result, error, logger);
    }

    const options = {
      scope: 'sub',
      filter: syncFilter(provider),
      attributes: syncAttributes(provider),
      explicitBufferAttributes: explicitBufferAttributes(provider),
      paged: { pageSize: provider.syncPageSize },
      sizeLimit: 0,
      timeLimit: Math.max(1, Math.ceil(provider.operationTimeoutMs / 1000)),
    };
    let pages;
    try {
      pages = client.searchPaginated
        ? client.searchPaginated(provider.userBaseDn, options)
        : (async function* singlePage() { yield await client.search(provider.userBaseDn, options); }());
    } catch (error) {
      return syncFailure('unavailable', result, error, logger);
    }

    const iterator = pages[Symbol.asyncIterator]();
    while (true) {
      let page;
      try {
        page = await iterator.next();
      } catch (error) {
        return syncFailure('unavailable', result, error, logger);
      }
      if (page.done) break;
      result.pages += 1;
      if ((page.value?.searchReferences?.length ?? 0) > 0) {
        return syncFailure('failed', result, new Error('LDAP sync does not follow search referrals'), logger);
      }
      for (const entry of page.value?.searchEntries ?? []) {
        result.scanned += 1;
        let mapped;
        try {
          mapped = syncProfile(entry, provider);
        } catch (error) {
          return syncFailure('failed', result, error, logger);
        }
        let outcome;
        try {
          outcome = await repository.syncEntry({
            realm,
            providerId: provider.id,
            issuer: provider.url,
            externalSubject: mapped.externalSubject,
            profile: mapped.profile,
            syncId,
            syncGroups: provider.syncGroups,
            syncRoles: Boolean(provider.rolesAttribute),
          });
        } catch (error) {
          return syncFailure('failed', result, error, logger);
        }
        if (outcome.status === 'created') result.created += 1;
        else if (outcome.status === 'updated') result.updated += 1;
        else if (outcome.status === 'unchanged') result.unchanged += 1;
        else if (outcome.status === 'conflict') result.conflicts += 1;
        else return syncFailure('failed', result, new Error('LDAP sync repository returned an invalid status'), logger);
      }
    }

    await closeClient(client);
    client = null;
    try {
      const reconciled = await repository.reconcileMissing({
        realm,
        providerId: provider.id,
        issuer: provider.url,
        syncId,
        startedAt,
        scanned: result.scanned,
        deletionPolicy: provider.syncDeletionPolicy,
        maxDeprovisionFraction: provider.syncMaxDeprovisionFraction,
        maxDeprovisionCount: provider.syncMaxDeprovisionCount,
        batchSize: provider.syncPageSize,
      });
      result.disabled = reconciled.disabled;
      result.deleted = reconciled.deleted;
      result.deletionRefused = reconciled.deletionRefused;
      result.reconciliation = {
        status: reconciled.status,
        reason: reconciled.reason ?? null,
        existing: reconciled.existing,
        candidates: reconciled.candidates,
      };
      if (reconciled.status === 'skipped') {
        logger?.warn?.({
          realm: result.realm,
          providerId: result.providerId,
          reconciliation: result.reconciliation,
        }, 'LDAP sync reconciliation needs confirmation');
        return { ...result, status: 'needs_confirmation' };
      }
    } catch (error) {
      return syncFailure('failed', result, error, logger);
    }
    return { ...result, status: 'success' };
  } finally {
    await closeClient(client);
    await releaseLock?.();
  }
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
      explicitBufferAttributes: explicitBufferAttributes(provider),
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
      capabilities: ['active-directory', 'directory-sync', 'jit-provisioning', 'ldap'],
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
