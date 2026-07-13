import {
  createPrivateKey,
  createPublicKey,
  randomBytes as secureRandomBytes,
  timingSafeEqual,
  X509Certificate,
} from 'node:crypto';
import { promisify } from 'node:util';
import { inflateRaw } from 'node:zlib';
import { SAML } from '@node-saml/node-saml';
import { AUTHME_EXTENSION_API_VERSION } from '../authentication/registry.js';
import { assertSamlReplayCache, createNodeSamlCacheProvider } from './saml-replay-cache.js';

const inflateRawAsync = promisify(inflateRaw);
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const RESPONSE_SIGNATURE_ALGORITHMS = new Set([
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
]);
const DIGEST_ALGORITHMS = new Set([
  'http://www.w3.org/2001/04/xmlenc#sha256',
  'http://www.w3.org/2001/04/xmlenc#sha512',
]);
const DEFAULT_ATTRIBUTE_MAPPING = Object.freeze({
  username: ['uid', 'urn:oid:0.9.2342.19200300.100.1.1', 'email', 'mail'],
  email: ['email', 'mail', 'urn:oid:0.9.2342.19200300.100.1.3'],
  name: ['displayName', 'name', 'urn:oid:2.16.840.1.113730.3.1.241'],
  givenName: ['givenName', 'urn:oid:2.5.4.42'],
  familyName: ['sn', 'surname', 'urn:oid:2.5.4.4'],
  groups: ['groups', 'memberOf'],
  roles: ['roles', 'role'],
});
const MAPPING_FIELDS = new Set(Object.keys(DEFAULT_ATTRIBUTE_MAPPING));

export class SamlFederationError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'SamlFederationError';
    this.code = code;
    this.status = 400;
  }
}

function fail(code, message, cause) {
  throw new SamlFederationError(code, message, cause ? { cause } : undefined);
}

function nonEmpty(value, name, max = 4096) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new TypeError(`${name} must be a non-empty string no longer than ${max} characters`);
  }
  return value;
}

function endpoint(value, name) {
  nonEmpty(value, name);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${name} must be an absolute URL`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new TypeError(`${name} must be an exact HTTPS URL without credentials, query, or fragment`);
  }
  return url.href;
}

function entityId(value, name) {
  nonEmpty(value, name);
  try {
    new URL(value);
  } catch {
    throw new TypeError(`${name} must be an absolute URI`);
  }
  return value;
}

function strongRsaPublicKey(value, name) {
  nonEmpty(value, name, 64 * 1024);
  let key;
  try {
    key = createPublicKey(value);
  } catch (error) {
    throw new TypeError(`${name} must be a PEM X.509 certificate or public key`, { cause: error });
  }
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new TypeError(`${name} must contain an RSA key of at least 2048 bits`);
  }
  return key;
}

function strongRsaCertificate(value, name) {
  nonEmpty(value, name, 64 * 1024);
  let certificate;
  try {
    certificate = new X509Certificate(value);
  } catch (error) {
    throw new TypeError(`${name} must be a PEM X.509 certificate`, { cause: error });
  }
  const key = certificate.publicKey;
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new TypeError(`${name} must contain an RSA key of at least 2048 bits`);
  }
  return key;
}

function validateSpSigningKey(privateKey, certificates) {
  let key;
  try {
    key = createPrivateKey(privateKey);
  } catch (error) {
    throw new TypeError('sp.signingPrivateKey must be a PEM private key', { cause: error });
  }
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new TypeError('sp.signingPrivateKey must contain an RSA key of at least 2048 bits');
  }
  const derived = createPublicKey(key).export({ type: 'spki', format: 'der' });
  const current = strongRsaCertificate(certificates[0], 'sp.signingCertificates[0]')
    .export({ type: 'spki', format: 'der' });
  if (derived.length !== current.length || !timingSafeEqual(derived, current)) {
    throw new TypeError('sp.signingCertificates[0] does not match sp.signingPrivateKey');
  }
  certificates.slice(1).forEach((certificate, index) => {
    strongRsaCertificate(certificate, `sp.signingCertificates[${index + 1}]`);
  });
}

function integer(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function mapping(input = {}) {
  if (!input || Array.isArray(input) || typeof input !== 'object') {
    throw new TypeError('attributeMapping must be an object');
  }
  for (const name of Object.keys(input)) {
    if (!MAPPING_FIELDS.has(name)) throw new TypeError(`Unsupported SAML attribute mapping: ${name}`);
  }
  return Object.freeze(Object.fromEntries([...MAPPING_FIELDS].map((name) => {
    const configured = input[name] ?? DEFAULT_ATTRIBUTE_MAPPING[name];
    const aliases = typeof configured === 'string' ? [configured] : configured;
    if (!Array.isArray(aliases) || aliases.length === 0 || aliases.length > 16
      || aliases.some((alias) => typeof alias !== 'string' || alias.length === 0 || alias.length > 512)
      || new Set(aliases).size !== aliases.length) {
      throw new TypeError(`attributeMapping.${name} must contain 1 to 16 unique non-empty strings`);
    }
    return [name, Object.freeze([...aliases])];
  })));
}

function extractAttributes(attributeText, names) {
  const result = {};
  for (const name of names) {
    const pattern = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(["'])([^"']*)\\1`, 'g');
    const matches = [...attributeText.matchAll(pattern)];
    if (matches.length > 1) fail('malformed_saml_response', `SAML Response contains duplicate ${name} attributes`);
    result[name] = matches[0]?.[2];
  }
  return result;
}

function responseEnvelope(encoded, maxResponseBytes) {
  if (typeof encoded !== 'string' || encoded.length === 0 || encoded.length > Math.ceil(maxResponseBytes * 4 / 3) + 4
    || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    fail('malformed_saml_response', 'SAMLResponse must be one bounded base64 value');
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length === 0 || bytes.length > maxResponseBytes) {
    fail('malformed_saml_response', 'SAMLResponse exceeds the configured size limit');
  }
  const xml = bytes.toString('utf8');
  if (xml.includes('\uFFFD') || /<!DOCTYPE|<!ENTITY/i.test(xml)) {
    fail('malformed_saml_response', 'SAMLResponse contains prohibited XML constructs');
  }
  const root = /^\s*(?:<\?xml[^?]*\?>\s*)?<(?:(?:[A-Za-z_][\w.-]*):)?Response\b([^>]*)>/u.exec(xml);
  if (!root) fail('malformed_saml_response', 'SAMLResponse does not contain a root Response element');
  const attributes = extractAttributes(root[1], ['ID', 'Version', 'Destination', 'InResponseTo']);
  if (!attributes.ID || attributes.ID.length > 256 || !/^[_A-Za-z][\w.-]*$/u.test(attributes.ID)) {
    fail('malformed_saml_response', 'SAML Response ID is missing or invalid');
  }
  if (attributes.Version !== '2.0') fail('malformed_saml_response', 'SAML Response version must be 2.0');
  if (!attributes.Destination) fail('invalid_destination', 'SAML Response Destination is required');
  if (!attributes.InResponseTo) fail('invalid_in_response_to', 'SAML Response InResponseTo is required');

  const signatureAlgorithms = [...xml.matchAll(/<(?:[A-Za-z_][\w.-]*:)?SignatureMethod\b[^>]*\bAlgorithm\s*=\s*(["'])([^"']+)\1/gu)]
    .map((match) => match[2]);
  const digestAlgorithms = [...xml.matchAll(/<(?:[A-Za-z_][\w.-]*:)?DigestMethod\b[^>]*\bAlgorithm\s*=\s*(["'])([^"']+)\1/gu)]
    .map((match) => match[2]);
  if (signatureAlgorithms.length < 2 || signatureAlgorithms.some((algorithm) => !RESPONSE_SIGNATURE_ALGORITHMS.has(algorithm))) {
    fail('invalid_signature_algorithm', 'SAML Response and Assertion must use approved RSA-SHA256 or RSA-SHA512 signatures');
  }
  if (digestAlgorithms.length < 2 || digestAlgorithms.some((algorithm) => !DIGEST_ALGORITHMS.has(algorithm))) {
    fail('invalid_signature_algorithm', 'SAML Response and Assertion must use approved SHA-256 or SHA-512 digests');
  }
  return { xml, ...attributes };
}

function requestEnvelope(redirectUrl, relayState, entryPoint, callbackUrl) {
  const url = new URL(redirectUrl);
  const expected = new URL(entryPoint);
  if (url.origin !== expected.origin || url.pathname !== expected.pathname) {
    throw new Error('Node-SAML generated a request for an unexpected identity-provider endpoint');
  }
  if (url.searchParams.get('RelayState') !== relayState) throw new Error('Generated SAML request lost RelayState');
  const encoded = url.searchParams.get('SAMLRequest');
  if (!encoded) throw new Error('Generated SAML redirect has no SAMLRequest');
  return inflateRawAsync(Buffer.from(encoded, 'base64')).then((bytes) => {
    const xml = bytes.toString('utf8');
    const root = /^\s*(?:<\?xml[^?]*\?>\s*)?<(?:(?:[A-Za-z_][\w.-]*):)?AuthnRequest\b([^>]*)>/u.exec(xml);
    if (!root) throw new Error('Generated message is not an AuthnRequest');
    const attributes = extractAttributes(root[1], ['ID', 'Destination', 'AssertionConsumerServiceURL']);
    if (!attributes.ID || attributes.Destination !== entryPoint || attributes.AssertionConsumerServiceURL !== callbackUrl) {
      throw new Error('Generated AuthnRequest is not bound to the configured SAML endpoints');
    }
    return { requestId: attributes.ID, xml };
  });
}

function scalarValues(value) {
  const inputs = Array.isArray(value) ? value : [value];
  const values = [];
  for (const input of inputs) {
    if (!['string', 'number', 'boolean'].includes(typeof input)) continue;
    const text = String(input).trim();
    if (text && text.length <= 4096) values.push(text);
  }
  return [...new Set(values)].slice(0, 256);
}

function normalizedAttributes(profile) {
  const source = profile.attributes;
  if (!source || Array.isArray(source) || typeof source !== 'object') return Object.freeze({});
  const entries = [];
  for (const [name, value] of Object.entries(source).slice(0, 256)) {
    if (!name || name.length > 512) continue;
    const values = scalarValues(value);
    if (values.length) entries.push([name, Object.freeze(values)]);
  }
  return Object.freeze(Object.fromEntries(entries));
}

function firstMapped(attributes, aliases) {
  for (const alias of aliases) {
    if (attributes[alias]?.length) return attributes[alias][0];
  }
  return undefined;
}

function allMapped(attributes, aliases) {
  return [...new Set(aliases.flatMap((alias) => attributes[alias] ?? []))];
}

function assertionDetails(profile, callbackUrl, requestId, now, clockSkewMs) {
  const parsed = profile.getAssertion?.();
  const assertion = parsed?.Assertion;
  const assertionId = assertion?.$?.ID;
  if (typeof assertionId !== 'string' || assertionId.length > 256 || !/^[_A-Za-z][\w.-]*$/u.test(assertionId)) {
    fail('malformed_saml_assertion', 'Signed SAML Assertion ID is missing or invalid');
  }
  const confirmations = assertion?.Subject?.flatMap((subject) => subject.SubjectConfirmation ?? []) ?? [];
  const validBearer = confirmations.some((confirmation) => {
    if (confirmation?.$?.Method !== BEARER) return false;
    const data = confirmation.SubjectConfirmationData?.[0]?.$;
    if (!data || data.Recipient !== callbackUrl || data.InResponseTo !== requestId || !data.NotOnOrAfter) return false;
    const notBefore = data.NotBefore ? Date.parse(data.NotBefore) : undefined;
    const notOnOrAfter = Date.parse(data.NotOnOrAfter);
    if ((data.NotBefore && !Number.isFinite(notBefore)) || !Number.isFinite(notOnOrAfter)) return false;
    return (notBefore === undefined || now + clockSkewMs >= notBefore) && now - clockSkewMs < notOnOrAfter;
  });
  if (!validBearer) {
    fail('invalid_subject_confirmation', 'SAML Assertion has no valid bearer SubjectConfirmation for this request');
  }
  return { assertionId };
}

function identityFromProfile({ profile, realm, providerId, mapping: attributeMap, trustEmail }) {
  const issuer = nonEmpty(profile.issuer, 'SAML Assertion issuer', 2048);
  const externalSubject = nonEmpty(profile.nameID, 'SAML NameID', 2048);
  const attributes = normalizedAttributes(profile);
  const email = firstMapped(attributes, attributeMap.email);
  const suggested = Object.freeze({
    username: firstMapped(attributes, attributeMap.username) ?? email ?? externalSubject,
    email,
    emailVerified: Boolean(email && trustEmail),
    name: firstMapped(attributes, attributeMap.name),
    givenName: firstMapped(attributes, attributeMap.givenName),
    familyName: firstMapped(attributes, attributeMap.familyName),
    groups: Object.freeze(allMapped(attributes, attributeMap.groups)),
    roles: Object.freeze(allMapped(attributes, attributeMap.roles)),
  });
  return Object.freeze({
    protocol: 'saml',
    realm,
    providerId,
    issuer,
    externalSubject,
    nameIdFormat: typeof profile.nameIDFormat === 'string' ? profile.nameIDFormat : undefined,
    sessionIndex: typeof profile.sessionIndex === 'string' ? profile.sessionIndex : undefined,
    attributes,
    suggested,
  });
}

function stateMatches(left, right) {
  return left?.interactionUid === right?.interactionUid && left?.requestId === right?.requestId
    && left?.realm === right?.realm && left?.providerId === right?.providerId;
}

export function createSamlBroker({
  realm,
  providerId,
  sp,
  idp,
  replayCache,
  attributeMapping,
  trustEmail = false,
  requestTtlMs = 5 * 60 * 1000,
  clockSkewMs = 60 * 1000,
  maxAssertionAgeMs = 5 * 60 * 1000,
  replayTtlMs = 10 * 60 * 1000,
  maxResponseBytes = 1024 * 1024,
  now = Date.now,
  randomBytes = secureRandomBytes,
  samlFactory = (options) => new SAML(options),
}) {
  nonEmpty(realm, 'realm', 63);
  nonEmpty(providerId, 'providerId', 128);
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(providerId)) throw new TypeError('providerId contains unsupported characters');
  if (!sp || typeof sp !== 'object' || !idp || typeof idp !== 'object') throw new TypeError('sp and idp configuration are required');
  const issuer = entityId(sp.entityId, 'sp.entityId');
  const callbackUrl = endpoint(sp.assertionConsumerServiceUrl, 'sp.assertionConsumerServiceUrl');
  const entryPoint = endpoint(idp.ssoUrl, 'idp.ssoUrl');
  const expectedIssuer = entityId(idp.entityId, 'idp.entityId');
  const certificates = Array.isArray(idp.signingCertificates) ? idp.signingCertificates : [idp.signingCertificates];
  if (certificates.length === 0 || certificates.length > 10
    || certificates.some((certificate) => typeof certificate !== 'string' || certificate.length === 0)) {
    throw new TypeError('idp.signingCertificates must contain 1 to 10 PEM certificates or public keys');
  }
  certificates.forEach((certificate, index) => strongRsaPublicKey(certificate, `idp.signingCertificates[${index}]`));
  if ((sp.signingPrivateKey && !sp.signingCertificates) || (!sp.signingPrivateKey && sp.signingCertificates)) {
    throw new TypeError('sp.signingPrivateKey and sp.signingCertificates must be configured together');
  }
  const publicCertificates = sp.signingCertificates === undefined
    ? undefined
    : (Array.isArray(sp.signingCertificates) ? sp.signingCertificates : [sp.signingCertificates]);
  if (publicCertificates?.some((certificate) => typeof certificate !== 'string' || certificate.length === 0)) {
    throw new TypeError('sp.signingCertificates must contain PEM certificates');
  }
  if (publicCertificates && (publicCertificates.length === 0 || publicCertificates.length > 10)) {
    throw new TypeError('sp.signingCertificates must contain 1 to 10 PEM certificates');
  }
  if (sp.signingPrivateKey) validateSpSigningKey(sp.signingPrivateKey, publicCertificates);
  assertSamlReplayCache(replayCache);
  integer(requestTtlMs, 'requestTtlMs', 30_000, 30 * 60 * 1000);
  integer(clockSkewMs, 'clockSkewMs', 0, 5 * 60 * 1000);
  integer(maxAssertionAgeMs, 'maxAssertionAgeMs', 30_000, 30 * 60 * 1000);
  integer(replayTtlMs, 'replayTtlMs', maxAssertionAgeMs + clockSkewMs, 60 * 60 * 1000);
  integer(maxResponseBytes, 'maxResponseBytes', 16 * 1024, 5 * 1024 * 1024);
  if (typeof now !== 'function' || typeof randomBytes !== 'function' || typeof samlFactory !== 'function') {
    throw new TypeError('now, randomBytes, and samlFactory must be functions');
  }
  if (typeof trustEmail !== 'boolean') throw new TypeError('trustEmail must be a boolean');
  const resolvedMapping = mapping(attributeMapping);
  const prefix = `saml:${realm}:${providerId}`;
  const cacheProvider = createNodeSamlCacheProvider({ cache: replayCache, prefix, ttlMs: requestTtlMs, now });
  const saml = samlFactory({
    issuer,
    audience: issuer,
    callbackUrl,
    entryPoint,
    idpIssuer: expectedIssuer,
    idpCert: [...certificates],
    privateKey: sp.signingPrivateKey,
    publicCert: publicCertificates?.[0],
    signatureAlgorithm: 'sha256',
    digestAlgorithm: 'sha256',
    authnRequestBinding: 'HTTP-Redirect',
    wantAuthnResponseSigned: true,
    wantAssertionsSigned: true,
    validateInResponseTo: 'always',
    requestIdExpirationPeriodMs: requestTtlMs,
    acceptedClockSkewMs: clockSkewMs,
    maxAssertionAgeMs,
    cacheProvider,
    identifierFormat: sp.nameIdFormat ?? null,
    disableRequestedAuthnContext: sp.disableRequestedAuthnContext ?? false,
    signMetadata: Boolean(sp.signingPrivateKey && (sp.signMetadata ?? true)),
  });

  const stateKey = (relayState) => `${prefix}:state:${relayState}`;
  const responseKey = (responseId) => `${prefix}:response:${responseId}`;
  const assertionKey = (assertionId) => `${prefix}:assertion:${assertionId}`;

  return Object.freeze({
    realm,
    providerId,
    metadata() {
      return saml.generateServiceProviderMetadata(null, publicCertificates ?? null);
    },
    async start({ interactionUid }) {
      nonEmpty(interactionUid, 'interactionUid', 256);
      if (!/^[A-Za-z0-9_-]+$/.test(interactionUid)) throw new TypeError('interactionUid must be base64url-safe');
      const relayState = randomBytes(32).toString('base64url');
      if (relayState.length > 80) throw new Error('Generated RelayState exceeds the SAML binding limit');
      const redirectUrl = await saml.getAuthorizeUrlAsync(relayState, undefined, {});
      const { requestId } = await requestEnvelope(redirectUrl, relayState, entryPoint, callbackUrl);
      const state = Object.freeze({ realm, providerId, interactionUid, requestId });
      const saved = await replayCache.putIfAbsent(stateKey(relayState), state, requestTtlMs);
      if (!saved) {
        await cacheProvider.removeAsync(requestId);
        throw new Error('Unable to allocate unique SAML RelayState');
      }
      return Object.freeze({
        redirectUrl,
        relayState,
        requestId,
        expiresAt: new Date(now() + requestTtlMs).toISOString(),
      });
    },
    async consumePost({ SAMLResponse, RelayState }) {
      if (typeof RelayState !== 'string' || !/^[A-Za-z0-9_-]{32,80}$/.test(RelayState)) {
        fail('invalid_relay_state', 'SAML RelayState is missing or invalid');
      }
      const pending = await replayCache.get(stateKey(RelayState));
      if (!pending) fail('invalid_relay_state', 'SAML RelayState is unknown, expired, or already used');
      const envelope = responseEnvelope(SAMLResponse, maxResponseBytes);
      if (envelope.Destination !== callbackUrl) fail('invalid_destination', 'SAML Response was sent to a different destination');
      if (envelope.InResponseTo !== pending.requestId) {
        fail('invalid_in_response_to', 'SAML Response is not bound to this OIDC interaction');
      }

      let profile;
      try {
        const result = await saml.validatePostResponseAsync({ SAMLResponse });
        if (result.loggedOut || !result.profile) fail('invalid_saml_response', 'SAML login response did not contain an identity assertion');
        profile = result.profile;
      } catch (error) {
        if (error instanceof SamlFederationError) throw error;
        fail('invalid_saml_response', 'SAML response validation failed', error);
      }
      if (profile.inResponseTo !== pending.requestId) fail('invalid_in_response_to', 'Validated SAML response has the wrong request identifier');
      if (profile.issuer !== expectedIssuer) fail('invalid_issuer', 'SAML Assertion issuer is not the configured identity provider');
      const { assertionId } = assertionDetails(profile, callbackUrl, pending.requestId, now(), clockSkewMs);

      if (!await replayCache.putIfAbsent(responseKey(envelope.ID), true, replayTtlMs)) {
        fail('replayed_saml_response', 'SAML Response has already been used');
      }
      if (!await replayCache.putIfAbsent(assertionKey(assertionId), true, replayTtlMs)) {
        fail('replayed_saml_assertion', 'SAML Assertion has already been used');
      }
      const consumed = await replayCache.consume(stateKey(RelayState));
      if (!stateMatches(consumed, pending)) fail('invalid_relay_state', 'SAML RelayState was consumed concurrently');

      return Object.freeze({
        interactionUid: pending.interactionUid,
        requestId: pending.requestId,
        responseId: envelope.ID,
        assertionId,
        identity: identityFromProfile({
          profile,
          realm,
          providerId,
          mapping: resolvedMapping,
          trustEmail,
        }),
      });
    },
  });
}

export async function completeSamlJitHandoff(validation, handoff) {
  if (!validation?.identity || typeof validation.interactionUid !== 'string') {
    throw new TypeError('A validated SAML broker result is required');
  }
  if (typeof handoff !== 'function') throw new TypeError('SAML JIT identity handoff must be a function');
  const result = await handoff(validation.identity);
  if (!result || typeof result !== 'object' || typeof result.accountId !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(result.accountId)) {
    throw new TypeError('SAML JIT identity handoff must return an object containing a UUID accountId');
  }
  return Object.freeze({
    interactionUid: validation.interactionUid,
    created: result.created === true,
    login: Object.freeze({
      accountId: result.accountId,
      acr: 'urn:authme:loa:federated',
      amr: Object.freeze(['federated', 'saml']),
      remember: true,
    }),
  });
}

export function createSamlFederationExtension({ providersByRealm, replayCacheFor }) {
  if (!providersByRealm || typeof providersByRealm !== 'object') {
    throw new TypeError('SAML federation providersByRealm is required');
  }
  if (typeof replayCacheFor !== 'function') {
    throw new TypeError('SAML federation replayCacheFor must be a function');
  }
  const brokers = new Map();
  const providerFor = (realm, id) => providersByRealm[realm]?.find((provider) => provider.id === id);
  const brokerFor = (realm, id) => {
    const provider = providerFor(realm, id);
    if (!provider) fail('unknown_saml_provider', 'Unknown SAML identity provider');
    const key = `${realm}\u0000${id}`;
    if (!brokers.has(key)) {
      brokers.set(key, createSamlBroker({
        realm,
        providerId: provider.id,
        sp: provider.sp,
        idp: provider.idp,
        replayCache: replayCacheFor(realm, provider.id),
        attributeMapping: provider.attributeMapping,
        trustEmail: provider.trustEmail,
        requestTtlMs: provider.requestTtlMs,
        clockSkewMs: provider.clockSkewMs,
        maxAssertionAgeMs: provider.maxAssertionAgeMs,
        replayTtlMs: provider.replayTtlMs,
        maxResponseBytes: provider.maxResponseBytes,
      }));
    }
    return brokers.get(key);
  };

  return Object.freeze({
    manifest: Object.freeze({
      apiVersion: AUTHME_EXTENSION_API_VERSION,
      id: 'builtin.saml-federation',
      kind: 'federation',
      displayName: 'SAML 2.0 federation',
      capabilities: Object.freeze(['jit-provisioning', 'saml2', 'sp-initiated']),
    }),
    implementation: Object.freeze({
      enabledFor: (realm) => (providersByRealm[realm]?.length ?? 0) > 0,
      initiate: ({ realm, providerId, interactionUid }) => brokerFor(realm, providerId).start({ interactionUid }),
      async consume({ realm, providerId, params }) {
        const validation = await brokerFor(realm, providerId).consumePost(params ?? {});
        const configuredProvider = providerFor(realm, providerId);
        const { suggested } = validation.identity;
        return Object.freeze({
          interactionUid: validation.interactionUid,
          providerId,
          allowCreate: configuredProvider?.jitProvisioning === true,
          profile: Object.freeze({
            externalSubject: validation.identity.externalSubject,
            username: suggested.username,
            email: suggested.email ?? '',
            emailVerified: suggested.emailVerified,
            name: suggested.name ?? suggested.username,
            givenName: suggested.givenName ?? '',
            familyName: suggested.familyName ?? '',
            groups: suggested.groups,
            roles: suggested.roles,
          }),
          identity: validation.identity,
          amr: Object.freeze(['federated', 'saml']),
          acr: 'urn:authme:loa:federated',
        });
      },
      metadataFor: (realm, providerId) => brokerFor(realm, providerId).metadata(),
      providersFor: (realm) => (providersByRealm[realm] ?? [])
        .map(({ id, displayName }) => Object.freeze({ id, displayName })),
    }),
  });
}
