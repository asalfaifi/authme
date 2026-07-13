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
