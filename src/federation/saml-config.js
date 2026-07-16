import { z } from 'zod';

const pem = z.string().min(64).max(64 * 1024);
const mappingValue = z.union([z.string().min(1).max(512), z.array(z.string().min(1).max(512)).min(1).max(16)]);
const providerSchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
  display_name: z.string().trim().min(1).max(100),
  idp_entity_id: z.string().url().max(2048),
  idp_sso_url: z.string().url().max(2048),
  idp_signing_certificates: z.array(pem).min(1).max(10),
  sp_signing_private_key: pem.optional(),
  sp_signing_certificates: z.array(pem).min(1).max(10).optional(),
  sp_sign_metadata: z.boolean().optional().default(true),
  name_id_format: z.string().min(1).max(512).optional(),
  disable_requested_authn_context: z.boolean().optional().default(false),
  attribute_mapping: z.object({
    username: mappingValue.optional(), email: mappingValue.optional(), name: mappingValue.optional(),
    givenName: mappingValue.optional(), familyName: mappingValue.optional(),
    groups: mappingValue.optional(), roles: mappingValue.optional(),
  }).strict().optional(),
  trust_email: z.boolean().optional().default(false),
  jit_provisioning: z.boolean().optional().default(false),
  request_ttl_ms: z.number().int().min(30_000).max(1_800_000).optional().default(300_000),
  clock_skew_ms: z.number().int().min(0).max(300_000).optional().default(60_000),
  max_assertion_age_ms: z.number().int().min(30_000).max(1_800_000).optional().default(300_000),
  replay_ttl_ms: z.number().int().min(30_000).max(3_600_000).optional().default(600_000),
  max_response_bytes: z.number().int().min(16_384).max(5 * 1024 * 1024).optional().default(1024 * 1024),
}).strict();

const idpAttributeSource = z.enum([
  'id', 'username', 'email', 'email_verified', 'name', 'given_name', 'family_name', 'groups', 'roles',
]);
const samlText = z.string().min(1).max(512).regex(/^[^\u0000-\u001f\u007f]+$/u);
const idpAttributeMapping = z.record(samlText, idpAttributeSource)
  .refine((value) => Object.keys(value).length <= 64, 'must contain no more than 64 attributes');
const idpAuthnContextMapping = z.object({
  password: samlText.optional(),
  passkey: samlText.optional(),
  mfa: samlText.optional(),
  federated: samlText.optional(),
  fallback: samlText.optional(),
}).strict();
const serviceProviderSchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
  entity_id: z.string().min(1).max(2048),
  acs_urls: z.array(z.string().min(1).max(2048)).min(1).max(20),
  slo_url: z.string().min(1).max(2048).optional(),
  signing_certificates: z.array(pem).min(1).max(10).optional(),
  require_signed_authn_requests: z.boolean().optional(),
  encryption_certificate: pem.optional(),
  encrypt_assertions: z.boolean().optional().default(false),
  allow_idp_initiated: z.boolean().optional().default(false),
  name_id_format: samlText.optional()
    .default('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'),
  name_id_source: z.enum(['persistent', 'email', 'username']).optional().default('persistent'),
  attribute_mapping: idpAttributeMapping.optional().default({}),
  authn_context_mapping: idpAuthnContextMapping.optional().default({}),
  authn_context_order: z.array(samlText).min(1).max(32)
    .refine((value) => new Set(value).size === value.length, 'must not contain duplicates').optional(),
}).strict();
const identityProviderSchema = z.object({
  entity_id: z.string().min(1).max(2048).optional(),
  signing_private_key: pem,
  signing_certificates: z.array(pem).min(1).max(10),
  service_providers: z.array(serviceProviderSchema).min(1).max(1000),
  request_ttl_ms: z.number().int().min(30_000).max(600_000).optional().default(300_000),
  clock_skew_ms: z.number().int().min(0).max(300_000).optional().default(60_000),
  assertion_ttl_ms: z.number().int().min(30_000).max(600_000).optional().default(300_000),
  max_request_bytes: z.number().int().min(4096).max(1024 * 1024).optional().default(256 * 1024),
}).strict();

function configurationError(message, cause) {
  return Object.assign(new Error(`Invalid SAML provider configuration: ${message}`, cause ? { cause } : undefined), {
    code: 'AUTHME_SAML_CONFIGURATION_INVALID',
  });
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function ssoEndpoint(value, name) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw configurationError(`${name} must be an exact HTTPS URL without credentials, query, or fragment`);
  }
  return url.toString();
}

function serviceOrigin(value) {
  let url;
  try { url = new URL(value); } catch (error) {
    throw configurationError('SAML federation requires an absolute HTTPS AUTHME_PUBLIC_URL origin', error);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw configurationError('SAML federation requires an HTTPS AUTHME_PUBLIC_URL origin');
  }
  return url.origin;
}

function absoluteEntityId(value, name) {
  let url;
  try { url = new URL(value); } catch (error) {
    throw configurationError(`${name} must be an absolute URI`, error);
  }
  if (value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)
    || url.username || url.password || url.hash) {
    throw configurationError(`${name} cannot contain credentials or a fragment`);
  }
  return value;
}

function serviceEndpoint(value, name) {
  let url;
  try { url = new URL(value); } catch (error) {
    throw configurationError(`${name} must be an absolute HTTPS URL`, error);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw configurationError(`${name} must be an exact HTTPS URL without credentials or a fragment`);
  }
  return url.href;
}

export function parseSamlProviders(value, { realms, publicUrl }) {
  if (!value) return deepFreeze(Object.fromEntries(realms.map((realm) => [realm, []])));
  const origin = serviceOrigin(publicUrl);
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) {
    throw configurationError('AUTHME_SAML_PROVIDERS_JSON must contain valid JSON', error);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw configurationError('AUTHME_SAML_PROVIDERS_JSON must be an object keyed by realm');
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
      const item = validation.data;
      if (ids.has(item.id)) throw configurationError(`${realm} contains duplicate provider id ${item.id}`);
      ids.add(item.id);
      if (Boolean(item.sp_signing_private_key) !== Boolean(item.sp_signing_certificates)) {
        throw configurationError(`${realm}.${item.id} must set both SP signing private key and certificates`);
      }
      if (item.replay_ttl_ms < item.max_assertion_age_ms + item.clock_skew_ms) {
        throw configurationError(`${realm}.${item.id}.replay_ttl_ms must cover assertion age plus clock skew`);
      }
      const path = `/realms/${encodeURIComponent(realm)}/federation/builtin.saml-federation/${encodeURIComponent(item.id)}`;
      return {
        id: item.id,
        displayName: item.display_name,
        sp: {
          entityId: `${origin}${path}/metadata`,
          assertionConsumerServiceUrl: `${origin}${path}/acs`,
          signingPrivateKey: item.sp_signing_private_key,
          signingCertificates: item.sp_signing_certificates,
          signMetadata: item.sp_sign_metadata,
          nameIdFormat: item.name_id_format,
          disableRequestedAuthnContext: item.disable_requested_authn_context,
        },
        idp: {
          entityId: item.idp_entity_id,
          ssoUrl: ssoEndpoint(item.idp_sso_url, `${realm}.${item.id}.idp_sso_url`),
          signingCertificates: item.idp_signing_certificates,
        },
        attributeMapping: item.attribute_mapping,
        trustEmail: item.trust_email,
        jitProvisioning: item.jit_provisioning,
        requestTtlMs: item.request_ttl_ms,
        clockSkewMs: item.clock_skew_ms,
        maxAssertionAgeMs: item.max_assertion_age_ms,
        replayTtlMs: item.replay_ttl_ms,
        maxResponseBytes: item.max_response_bytes,
      };
    });
  }
  return deepFreeze(result);
}

export function parseSamlIdentityProviders(value, { realms, publicUrl }) {
  const disabled = () => deepFreeze(Object.fromEntries(realms.map((realm) => [realm, null])));
  if (!value) return disabled();
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) {
    throw configurationError('AUTHME_SAML_IDP_JSON must contain valid JSON', error);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw configurationError('AUTHME_SAML_IDP_JSON must be an object keyed by realm');
  }
  const unknownRealms = Object.keys(parsed).filter((realm) => !realms.includes(realm));
  if (unknownRealms.length) throw configurationError(`unknown SAML IdP realms: ${unknownRealms.join(', ')}`);
  if (!realms.some((realm) => parsed[realm] !== undefined && parsed[realm] !== null)) return disabled();
  const origin = serviceOrigin(publicUrl);

  const result = {};
  for (const realm of realms) {
    const input = parsed[realm];
    if (input === undefined || input === null) {
      result[realm] = null;
      continue;
    }
    const validation = identityProviderSchema.safeParse(input);
    if (!validation.success) {
      const issue = validation.error.issues[0];
      throw configurationError(`AUTHME_SAML_IDP_JSON.${realm}.${issue.path.join('.') || 'identity_provider'}: ${issue.message}`);
    }
    const item = validation.data;
    const ids = new Set();
    const entities = new Set();
    const serviceProviders = item.service_providers.map((sp, index) => {
      const name = `AUTHME_SAML_IDP_JSON.${realm}.service_providers[${index}]`;
      if (ids.has(sp.id)) throw configurationError(`${name}.id duplicates ${sp.id}`);
      ids.add(sp.id);
      const entityId = absoluteEntityId(sp.entity_id, `${name}.entity_id`);
      if (entities.has(entityId)) throw configurationError(`${name}.entity_id is duplicated`);
      entities.add(entityId);
      const acsUrls = sp.acs_urls.map((url, acsIndex) => serviceEndpoint(url, `${name}.acs_urls[${acsIndex}]`));
      if (new Set(acsUrls).size !== acsUrls.length) throw configurationError(`${name}.acs_urls contains duplicates`);
      const signingCertificates = sp.signing_certificates ?? [];
      const requireSignedAuthnRequests = sp.require_signed_authn_requests ?? signingCertificates.length > 0;
      if (requireSignedAuthnRequests && signingCertificates.length === 0) {
        throw configurationError(`${name}.signing_certificates is required for signed AuthnRequests`);
      }
      if (sp.slo_url && signingCertificates.length === 0) {
        throw configurationError(`${name}.signing_certificates is required for single logout`);
      }
      if (sp.encrypt_assertions && !sp.encryption_certificate) {
        throw configurationError(`${name}.encryption_certificate is required when encrypt_assertions is enabled`);
      }
      return {
        id: sp.id,
        entityId,
        acsUrls,
        sloUrl: sp.slo_url ? serviceEndpoint(sp.slo_url, `${name}.slo_url`) : undefined,
        signingCertificates,
        requireSignedAuthnRequests,
        encryptionCertificate: sp.encryption_certificate,
        encryptAssertions: sp.encrypt_assertions,
        allowIdpInitiated: sp.allow_idp_initiated,
        nameIdFormat: sp.name_id_format,
        nameIdSource: sp.name_id_source,
        attributeMapping: sp.attribute_mapping,
        authnContextMapping: sp.authn_context_mapping,
        authnContextOrder: sp.authn_context_order,
      };
    });
    const base = `${origin}/realms/${encodeURIComponent(realm)}/protocol/saml`;
    result[realm] = {
      entityId: absoluteEntityId(item.entity_id ?? base, `AUTHME_SAML_IDP_JSON.${realm}.entity_id`),
      ssoUrl: base,
      metadataUrl: `${base}/descriptor`,
      continuationUrl: `${base}/continue`,
      logoutContinuationUrl: `${base}/logout/continue`,
      signingPrivateKey: item.signing_private_key,
      signingCertificates: item.signing_certificates,
      serviceProviders,
      requestTtlMs: item.request_ttl_ms,
      clockSkewMs: item.clock_skew_ms,
      assertionTtlMs: item.assertion_ttl_ms,
      maxRequestBytes: item.max_request_bytes,
    };
  }
  return deepFreeze(result);
}
