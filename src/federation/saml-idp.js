import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  createSign,
  randomBytes as secureRandomBytes,
  timingSafeEqual,
  X509Certificate,
} from 'node:crypto';
import { promisify } from 'node:util';
import { deflateRaw, inflateRaw } from 'node:zlib';
import { SAML } from '@node-saml/node-saml';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import xmlEncryption from 'xml-encryption';
import { assertSamlReplayCache } from './saml-replay-cache.js';

const inflateRawAsync = promisify(inflateRaw);
const deflateRawAsync = promisify(deflateRaw);
const encryptXmlAsync = promisify(xmlEncryption.encrypt).bind(xmlEncryption);
const ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const METADATA_NS = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const POST_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const REDIRECT_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const PASSWORD_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
const WEB_AUTHN_CONTEXT = 'urn:authme:ac:classes:WebAuthn';
const MFA_CONTEXT = 'https://refeds.org/profile/mfa';
const FEDERATED_CONTEXT = 'urn:authme:ac:classes:Federated';
const UNSPECIFIED_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';
const UNSPECIFIED_NAME_ID = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
const EXCLUSIVE_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const RSA_OAEP = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
const AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
const SIGNATURE_ALGORITHMS = new Set([RSA_SHA256, RSA_SHA512]);
const DIGEST_ALGORITHMS = new Set([SHA256, SHA512]);

export const SAML_IDP_BRIDGE_CLIENT_ID = 'authme-saml-idp';

export class SamlIdentityProviderError extends Error {
  constructor(code, message, status = 400, options) {
    super(message, options);
    this.name = 'SamlIdentityProviderError';
    this.code = code;
    this.status = status;
    this.safe = true;
  }
}

function fail(code, message, cause, status = 400) {
  throw new SamlIdentityProviderError(code, message, status, cause ? { cause } : undefined);
}

function nonEmpty(value, name, max = 4096) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new TypeError(`${name} must be a non-empty string no longer than ${max} characters`);
  }
  return value;
}

function integer(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function escapeXml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function escapeHtml(value) {
  return escapeXml(value);
}

function xmlText(value, name, max = 4096) {
  nonEmpty(value, name, max);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    fail('invalid_account', `${name} contains characters that cannot be represented in SAML`, null, 403);
  }
  return value;
}

function stripCertificate(certificate) {
  return certificate
    .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/gu, '');
}

function publicCertificate(value, name) {
  nonEmpty(value, name, 64 * 1024);
  let certificate;
  try { certificate = new X509Certificate(value); } catch (error) {
    throw new TypeError(`${name} must be a PEM X.509 certificate`, { cause: error });
  }
  const key = certificate.publicKey;
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new TypeError(`${name} must contain an RSA key of at least 2048 bits`);
  }
  return { certificate, key };
}

function signingMaterial(privateValue, certificates) {
  let privateKey;
  try { privateKey = createPrivateKey(privateValue); } catch (error) {
    throw new TypeError('SAML IdP signingPrivateKey must be a PEM private key', { cause: error });
  }
  if (privateKey.asymmetricKeyType !== 'rsa' || (privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new TypeError('SAML IdP signingPrivateKey must contain an RSA key of at least 2048 bits');
  }
  if (!Array.isArray(certificates) || certificates.length === 0 || certificates.length > 10) {
    throw new TypeError('SAML IdP signingCertificates must contain 1 to 10 certificates');
  }
  const parsed = certificates.map((certificate, index) => (
    publicCertificate(certificate, `signingCertificates[${index}]`)
  ));
  const derived = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const current = parsed[0].key.export({ type: 'spki', format: 'der' });
  if (derived.length !== current.length || !timingSafeEqual(derived, current)) {
    throw new TypeError('signingCertificates[0] does not match signingPrivateKey');
  }
  return { privateKey, parsed };
}

function directChildren(element, namespaceURI, localName) {
  const result = [];
  for (let child = element.firstChild; child; child = child.nextSibling) {
    if (child.nodeType === 1 && child.namespaceURI === namespaceURI && child.localName === localName) result.push(child);
  }
  return result;
}

function oneDirectChild(element, namespaceURI, localName, required = true) {
  const matches = directChildren(element, namespaceURI, localName);
  if (matches.length !== (required ? 1 : Math.min(matches.length, 1))) {
    fail('invalid_saml_request', `SAML request must contain ${required ? 'exactly one' : 'at most one'} ${localName}`);
  }
  return matches[0];
}

function boundedText(element, name, max = 2048) {
  const text = element?.textContent?.trim();
  if (!text || text.length > max || /[\u0000-\u001f\u007f]/u.test(text)) {
    fail('invalid_saml_request', `${name} is missing or invalid`);
  }
  return text;
}

function ensureUniqueIds(document) {
  const ids = new Set();
  const elements = document.getElementsByTagName('*');
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements.item(index);
    const present = ['ID', 'Id', 'id'].filter((name) => element.hasAttribute(name));
    if (present.length > 1) fail('invalid_saml_request', 'SAML XML contains ambiguous ID attributes');
    if (!present.length) continue;
    const id = element.getAttribute(present[0]);
    if (!/^[_A-Za-z][\w.-]{0,255}$/u.test(id) || ids.has(id)) {
      fail('invalid_saml_request', 'SAML XML contains an invalid or duplicate ID');
    }
    ids.add(id);
  }
}

function parseXml(xml, expectedLocalName) {
  if (xml.includes('\uFFFD') || /<!DOCTYPE|<!ENTITY/iu.test(xml)) {
    fail('invalid_saml_request', 'SAML XML contains prohibited constructs');
  }
  const errors = [];
  const document = new DOMParser({
    errorHandler: {
      warning(message) { errors.push(message); },
      error(message) { errors.push(message); },
      fatalError(message) { errors.push(message); },
    },
  }).parseFromString(xml, 'text/xml');
  const root = document?.documentElement;
  if (errors.length || !root || root.namespaceURI !== PROTOCOL_NS || root.localName !== expectedLocalName) {
    fail('invalid_saml_request', `SAML message must contain one root ${expectedLocalName}`);
  }
  ensureUniqueIds(document);
  return { document, root, xml };
}

function decodePost(value, maxRequestBytes, expectedLocalName) {
  if (typeof value !== 'string' || value.length === 0
    || value.length > Math.ceil(maxRequestBytes * 4 / 3) + 4
    || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    fail('invalid_saml_request', 'SAMLRequest must be one bounded base64 value');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.length > maxRequestBytes) fail('invalid_saml_request', 'SAMLRequest is too large');
  return parseXml(bytes.toString('utf8'), expectedLocalName);
}

async function decodeRedirect(value, maxRequestBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxRequestBytes * 2
    || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    fail('invalid_saml_request', 'Redirect SAMLRequest must be one bounded base64 value');
  }
  let bytes;
  try {
    bytes = await inflateRawAsync(Buffer.from(value, 'base64'), { maxOutputLength: maxRequestBytes });
  } catch (error) {
    fail('invalid_saml_request', 'Redirect SAMLRequest is not valid bounded DEFLATE data', error);
  }
  if (bytes.length === 0 || bytes.length > maxRequestBytes) fail('invalid_saml_request', 'SAMLRequest is too large');
  const xml = bytes.toString('utf8');
  const name = /^\s*(?:<\?xml[^?]*\?>\s*)?<(?:(?:[A-Za-z_][\w.-]*):)?(AuthnRequest|LogoutRequest)\b/u.exec(xml)?.[1];
  if (!['AuthnRequest', 'LogoutRequest'].includes(name)) fail('invalid_saml_request', 'Unsupported SAML request type');
  return parseXml(xml, name);
}

function parseRawQuery(rawQuery) {
  if (typeof rawQuery !== 'string' || rawQuery.length === 0 || rawQuery.length > 16_384) {
    fail('invalid_saml_request', 'SAML Redirect query is missing or too large');
  }
  const allowed = new Set(['SAMLRequest', 'RelayState', 'SigAlg', 'Signature']);
  const raw = new Map();
  const decoded = {};
  for (const token of rawQuery.split('&')) {
    const separator = token.indexOf('=');
    if (separator < 1) fail('invalid_saml_request', 'SAML Redirect query is malformed');
    let key;
    let value;
    try {
      key = decodeURIComponent(token.slice(0, separator).replaceAll('+', ' '));
      value = decodeURIComponent(token.slice(separator + 1).replaceAll('+', ' '));
    } catch (error) {
      fail('invalid_saml_request', 'SAML Redirect query contains invalid percent encoding', error);
    }
    if (!allowed.has(key) || raw.has(key)) fail('invalid_saml_request', 'SAML Redirect query has unsupported or duplicate parameters');
    raw.set(key, token);
    decoded[key] = value;
  }
  if (!raw.has('SAMLRequest')) fail('invalid_saml_request', 'SAMLRequest is required');
  if (raw.has('SigAlg') !== raw.has('Signature')) fail('invalid_saml_signature', 'SigAlg and Signature must be provided together');
  const relayState = decoded.RelayState;
  if (relayState !== undefined && (Buffer.byteLength(relayState) > 80 || /[\u0000-\u001f\u007f]/u.test(relayState))) {
    fail('invalid_relay_state', 'RelayState exceeds the SAML binding limit or contains controls');
  }
  return { decoded, raw };
}

function issueInstant(root, now, requestTtlMs, clockSkewMs) {
  if (root.getAttribute('Version') !== '2.0') fail('invalid_saml_request', 'SAML request Version must be 2.0');
  const value = Date.parse(root.getAttribute('IssueInstant'));
  if (!Number.isFinite(value) || value > now + clockSkewMs || value < now - requestTtlMs - clockSkewMs) {
    fail('invalid_saml_request', 'SAML request IssueInstant is outside the accepted time window');
  }
  return value;
}

function requestId(root) {
  const id = root.getAttribute('ID');
  if (!/^_[A-Za-z0-9_.-]{1,255}$/u.test(id)) fail('invalid_saml_request', 'SAML request ID is missing or invalid');
  return id;
}

function verifyXmlSignature({ document, root, xml }, certificates, required) {
  const allSignatures = Array.from(document.getElementsByTagNameNS(DSIG_NS, 'Signature'));
  const signatures = directChildren(root, DSIG_NS, 'Signature');
  if (allSignatures.length === 0) {
    if (required) fail('invalid_saml_signature', 'The service provider must sign this SAML request');
    return;
  }
  if (allSignatures.length !== 1 || signatures.length !== 1) {
    fail('invalid_saml_signature', 'SAML request contains an ambiguous signature');
  }
  if (!certificates.length) fail('invalid_saml_signature', 'No service-provider certificate is registered for this signature');
  const signatureElement = signatures[0];
  const signatureMethods = Array.from(signatureElement.getElementsByTagNameNS(DSIG_NS, 'SignatureMethod'));
  const digestMethods = Array.from(signatureElement.getElementsByTagNameNS(DSIG_NS, 'DigestMethod'));
  const canonicalizations = Array.from(signatureElement.getElementsByTagNameNS(DSIG_NS, 'CanonicalizationMethod'));
  const transforms = Array.from(signatureElement.getElementsByTagNameNS(DSIG_NS, 'Transform'))
    .map((element) => element.getAttribute('Algorithm'));
  if (signatureMethods.length !== 1 || !SIGNATURE_ALGORITHMS.has(signatureMethods[0].getAttribute('Algorithm'))
    || digestMethods.length !== 1 || !DIGEST_ALGORITHMS.has(digestMethods[0].getAttribute('Algorithm'))
    || canonicalizations.length !== 1 || canonicalizations[0].getAttribute('Algorithm') !== EXCLUSIVE_C14N
    || transforms.length !== 2 || transforms[0] !== ENVELOPED_SIGNATURE || transforms[1] !== EXCLUSIVE_C14N) {
    fail('invalid_saml_signature', 'SAML request uses an unsupported XML signature profile');
  }
  const expectedReference = `#${root.getAttribute('ID')}`;
  let verified = false;
  for (const certificate of certificates) {
    try {
      const signature = new SignedXml();
      signature.publicCert = certificate;
      signature.loadSignature(signatureElement);
      const references = signature.getReferences();
      if (references.length !== 1 || `#${references[0].uri.replace(/^#/u, '')}` !== expectedReference) continue;
      if (signature.checkSignature(xml) && signature.getSignedReferences().length === 1) {
        verified = true;
        break;
      }
    } catch {
      // Try the next explicitly configured rollover certificate.
    }
  }
  if (!verified) fail('invalid_saml_signature', 'SAML request XML signature validation failed');
}

async function verifyRedirectSignature(parsedQuery, rawQuery, sp, idpEntityId, ssoUrl, required) {
  const signed = parsedQuery.raw.has('Signature');
  if (!signed) {
    if (required) fail('invalid_saml_signature', 'The service provider must sign this SAML Redirect request');
    return;
  }
  if (!SIGNATURE_ALGORITHMS.has(parsedQuery.decoded.SigAlg) || sp.signingCertificates.length === 0) {
    fail('invalid_saml_signature', 'SAML Redirect request uses an unsupported or untrusted signature');
  }
  const validator = new SAML({
    issuer: idpEntityId,
    callbackUrl: ssoUrl,
    idpCert: [...sp.signingCertificates],
    signatureAlgorithm: 'sha256',
  });
  try {
    await validator.hasValidSignatureForRedirect(parsedQuery.decoded, rawQuery);
  } catch (error) {
    fail('invalid_saml_signature', 'SAML Redirect signature validation failed', error);
  }
}

function issuerFor(root) {
  return boundedText(oneDirectChild(root, ASSERTION_NS, 'Issuer'), 'SAML Issuer');
}

function requestedAuthnContext(root) {
  const requested = oneDirectChild(root, PROTOCOL_NS, 'RequestedAuthnContext', false);
  if (!requested) return null;
  const comparison = requested.getAttribute('Comparison') || 'exact';
  if (!['exact', 'minimum', 'better', 'maximum'].includes(comparison)) {
    fail('invalid_saml_request', 'RequestedAuthnContext Comparison is invalid');
  }
  const classRefs = [];
  let declarationRefCount = 0;
  for (let child = requested.firstChild; child; child = child.nextSibling) {
    if (child.nodeType !== 1) continue;
    if (child.namespaceURI !== ASSERTION_NS
      || !['AuthnContextClassRef', 'AuthnContextDeclRef'].includes(child.localName)) {
      fail('invalid_saml_request', 'RequestedAuthnContext contains an unsupported element');
    }
    if (child.localName === 'AuthnContextDeclRef') {
      boundedText(child, 'AuthnContextDeclRef', 512);
      declarationRefCount += 1;
    }
    else classRefs.push(boundedText(child, 'AuthnContextClassRef', 512));
  }
  if (classRefs.length + declarationRefCount === 0 || classRefs.length > 32
    || declarationRefCount > 32 || (declarationRefCount && classRefs.length)) {
    fail('invalid_saml_request', 'RequestedAuthnContext must contain one bounded reference type');
  }
  return Object.freeze({ classRefs: Object.freeze([...new Set(classRefs)]), comparison });
}

function authnRequest(parsed, sp, configuration, now) {
  const { root } = parsed;
  const id = requestId(root);
  issueInstant(root, now, configuration.requestTtlMs, configuration.clockSkewMs);
  if (root.getAttribute('Destination') !== configuration.ssoUrl) {
    fail('invalid_destination', 'SAML AuthnRequest Destination does not match this realm');
  }
  if (issuerFor(root) !== sp.entityId) fail('unknown_service_provider', 'SAML AuthnRequest Issuer is not registered in this realm', null, 403);
  const acsUrl = root.getAttribute('AssertionConsumerServiceURL');
  if (!acsUrl || !sp.acsUrls.includes(acsUrl)) {
    fail('unregistered_acs', 'SAML AuthnRequest ACS is not registered for this service provider', null, 403);
  }
  const binding = root.getAttribute('ProtocolBinding');
  if (binding && binding !== POST_BINDING) fail('unsupported_binding', 'AuthMe returns SAML Responses using HTTP-POST binding');
  if (root.hasAttribute('AssertionConsumerServiceIndex')) {
    fail('unsupported_binding', 'AssertionConsumerServiceIndex is not supported; send the exact registered ACS URL');
  }
  if (root.getAttribute('IsPassive') === 'true') fail('unsupported_authn_request', 'Passive SAML authentication is not supported');
  const nameIdPolicy = oneDirectChild(root, PROTOCOL_NS, 'NameIDPolicy', false);
  const requestedFormat = nameIdPolicy?.getAttribute('Format');
  if (requestedFormat && requestedFormat !== UNSPECIFIED_NAME_ID && requestedFormat !== sp.nameIdFormat) {
    fail('invalid_name_id_policy', 'Requested NameID format is not configured for this service provider');
  }
  return {
    acsUrl,
    forceAuthn: root.getAttribute('ForceAuthn') === 'true',
    requestId: id,
    requestedAuthnContext: requestedAuthnContext(root),
  };
}

function logoutRequest(parsed, sp, configuration, now) {
  const { root } = parsed;
  const id = requestId(root);
  issueInstant(root, now, configuration.requestTtlMs, configuration.clockSkewMs);
  if (root.getAttribute('Destination') !== configuration.ssoUrl) {
    fail('invalid_destination', 'SAML LogoutRequest Destination does not match this realm');
  }
  if (issuerFor(root) !== sp.entityId) fail('unknown_service_provider', 'SAML LogoutRequest Issuer is not registered in this realm', null, 403);
  if (!sp.sloUrl) fail('slo_not_configured', 'Single logout is not configured for this service provider', null, 403);
  const nameIdElement = oneDirectChild(root, ASSERTION_NS, 'NameID');
  const sessionIndexElement = oneDirectChild(root, PROTOCOL_NS, 'SessionIndex');
  return {
    nameId: boundedText(nameIdElement, 'LogoutRequest NameID'),
    requestId: id,
    sessionIndex: boundedText(sessionIndexElement, 'LogoutRequest SessionIndex', 256),
  };
}

function signElement(xml, xpath, location, privateKey, certificate) {
  const signature = new SignedXml();
  signature.signatureAlgorithm = RSA_SHA256;
  signature.canonicalizationAlgorithm = EXCLUSIVE_C14N;
  signature.addReference({
    xpath,
    transforms: [ENVELOPED_SIGNATURE, EXCLUSIVE_C14N],
    digestAlgorithm: SHA256,
  });
  signature.privateKey = privateKey;
  signature.publicCert = certificate;
  signature.computeSignature(xml, { location });
  return signature.getSignedXml();
}

function samlId(prefix, randomBytes) {
  return `_${prefix}${randomBytes(20).toString('hex')}`;
}

function attributeValues(user, source) {
  const value = {
    id: user.id,
    username: user.username,
    email: user.email,
    email_verified: user.emailVerified,
    name: user.name,
    given_name: user.givenName,
    family_name: user.familyName,
    groups: user.groups,
    roles: user.roles,
  }[source];
  const values = Array.isArray(value) ? value : [value];
  return [...new Set(values.filter((item) => ['string', 'number', 'boolean'].includes(typeof item))
    .map(String).filter((item) => item.length > 0 && item.length <= 4096))].slice(0, 256);
}

function attributesXml(user, mapping) {
  const attributes = [];
  let totalBytes = 0;
  for (const [name, source] of Object.entries(mapping)) {
    const values = attributeValues(user, source);
    if (!values.length) continue;
    const attribute = `<saml:Attribute Name="${escapeXml(name)}">${values.map((value) => (
      `<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema">${escapeXml(xmlText(value, `attribute ${name}`))}</saml:AttributeValue>`
    )).join('')}</saml:Attribute>`;
    totalBytes += Buffer.byteLength(attribute);
    if (totalBytes > 256 * 1024) fail('invalid_account', 'Mapped SAML attributes exceed the response size limit', null, 403);
    attributes.push(attribute);
  }
  return attributes.length ? `<saml:AttributeStatement>${attributes.join('')}</saml:AttributeStatement>` : '';
}

function nameIdFor(user, sp, realm, subjectSalt, randomBytes) {
  if (sp.nameIdSource === 'email') {
    if (!user.email) fail('invalid_account', 'The authenticated account has no email for the configured NameID', null, 403);
    return xmlText(user.email, 'user.email', 2048);
  }
  if (sp.nameIdSource === 'username') return xmlText(user.username, 'user.username', 2048);
  if (sp.nameIdFormat === 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
    return randomBytes(32).toString('base64url');
  }
  return createHmac('sha256', subjectSalt)
    .update(`saml-name-id-v1\u0000${realm}\u0000${sp.entityId}\u0000${user.id}`)
    .digest('base64url');
}

async function encryptedAssertion(assertion, sp) {
  if (!sp.encryptAssertions) return assertion;
  const key = createPublicKey(sp.encryptionCertificate).export({ type: 'spki', format: 'pem' });
  const encrypted = await encryptXmlAsync(assertion, {
    rsa_pub: key,
    pem: sp.encryptionCertificate,
    encryptionAlgorithm: AES256_GCM,
    keyEncryptionAlgorithm: RSA_OAEP,
    keyEncryptionDigest: 'sha256',
    disallowEncryptionWithInsecureAlgorithm: true,
    warnInsecureAlgorithm: true,
  });
  return `<saml:EncryptedAssertion xmlns:saml="${ASSERTION_NS}">${encrypted}</saml:EncryptedAssertion>`;
}

function authnContextFor(sp, authentication) {
  const mapping = sp.authnContextMapping ?? {};
  const methods = new Set(Array.isArray(authentication?.amr)
    ? authentication.amr.filter((method) => typeof method === 'string') : []);
  const hasPrimary = ['pwd', 'password', 'ldap', 'passkey', 'webauthn']
    .some((method) => methods.has(method));
  const hasSecondFactor = ['otp', 'totp', 'recovery'].some((method) => methods.has(method));
  if (methods.has('mfa') || (hasPrimary && hasSecondFactor)) {
    return mapping.mfa ?? MFA_CONTEXT;
  }
  if (methods.has('passkey') || methods.has('webauthn')) {
    return mapping.passkey ?? WEB_AUTHN_CONTEXT;
  }
  if (methods.has('pwd') || methods.has('password') || methods.has('ldap')) {
    return mapping.password ?? PASSWORD_CONTEXT;
  }
  const acr = authentication?.acr;
  if (methods.has('federated')) {
    return mapping.federated ?? (typeof acr === 'string' && acr.length <= 512 ? acr : FEDERATED_CONTEXT);
  }
  return typeof acr === 'string' && acr.length <= 512 ? acr : (mapping.fallback ?? UNSPECIFIED_CONTEXT);
}

function satisfiesRequestedAuthnContext(sp, actual, requested) {
  if (!requested) return true;
  if (requested.comparison === 'exact' || requested.comparison === 'maximum') {
    return requested.classRefs.includes(actual);
  }
  const mapping = sp.authnContextMapping ?? {};
  const order = sp.authnContextOrder ?? [
    mapping.password ?? PASSWORD_CONTEXT,
    mapping.passkey ?? WEB_AUTHN_CONTEXT,
    mapping.mfa ?? MFA_CONTEXT,
  ];
  const actualRank = order.indexOf(actual);
  if (actualRank < 0) return false;
  return requested.classRefs.some((context) => {
    const requestedRank = order.indexOf(context);
    return requestedRank >= 0 && (requested.comparison === 'minimum'
      ? actualRank >= requestedRank : actualRank > requestedRank);
  });
}

async function responseXml({
  configuration,
  privateKey,
  sp,
  user,
  requestId: inResponseTo,
  authentication,
  requestedAuthnContext: requested,
  subjectSalt,
  randomBytes,
  now,
}) {
  const issueTime = new Date(now).toISOString();
  const notBefore = new Date(now - configuration.clockSkewMs).toISOString();
  const notOnOrAfter = new Date(now + configuration.assertionTtlMs).toISOString();
  const assertionId = samlId('a', randomBytes);
  const responseId = samlId('r', randomBytes);
  const sessionIndex = samlId('s', randomBytes);
  const nameId = nameIdFor(user, sp, configuration.realm, subjectSalt, randomBytes);
  const responseBinding = inResponseTo ? ` InResponseTo="${escapeXml(inResponseTo)}"` : '';
  const subjectBinding = inResponseTo ? ` InResponseTo="${escapeXml(inResponseTo)}"` : '';
  const authTimeValue = Number(authentication?.authTime);
  const authTimeMs = Number.isFinite(authTimeValue)
    ? (authTimeValue < 10_000_000_000 ? authTimeValue * 1000 : authTimeValue)
    : now;
  const authnInstant = new Date(Math.min(now, authTimeMs)).toISOString();
  const authnContext = xmlText(authnContextFor(sp, authentication), 'AuthnContextClassRef', 512);
  if (!satisfiesRequestedAuthnContext(sp, authnContext, requested)) {
    fail('no_authn_context', 'The authentication result does not satisfy RequestedAuthnContext', null, 403);
  }
  let assertion = `<saml:Assertion xmlns:saml="${ASSERTION_NS}" ID="${assertionId}" Version="2.0" IssueInstant="${issueTime}">
  <saml:Issuer>${escapeXml(configuration.entityId)}</saml:Issuer>
  <saml:Subject><saml:NameID Format="${escapeXml(sp.nameIdFormat)}">${escapeXml(nameId)}</saml:NameID><saml:SubjectConfirmation Method="${BEARER}"><saml:SubjectConfirmationData${subjectBinding} Recipient="${escapeXml(authentication.acsUrl)}" NotOnOrAfter="${notOnOrAfter}"/></saml:SubjectConfirmation></saml:Subject>
  <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${escapeXml(sp.entityId)}</saml:Audience></saml:AudienceRestriction><saml:OneTimeUse/></saml:Conditions>
  <saml:AuthnStatement AuthnInstant="${authnInstant}" SessionIndex="${sessionIndex}"><saml:AuthnContext><saml:AuthnContextClassRef>${escapeXml(authnContext)}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
  ${attributesXml(user, sp.attributeMapping)}
</saml:Assertion>`;
  const assertionXpath = "//*[local-name(.)='Assertion' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']";
  assertion = signElement(assertion, assertionXpath, {
    reference: `${assertionXpath}/*[local-name(.)='Issuer']`, action: 'after',
  }, privateKey, configuration.signingCertificates[0]);
  const assertionPayload = await encryptedAssertion(assertion, sp);
  let response = `<samlp:Response xmlns:samlp="${PROTOCOL_NS}" xmlns:saml="${ASSERTION_NS}" ID="${responseId}" Version="2.0" IssueInstant="${issueTime}" Destination="${escapeXml(authentication.acsUrl)}"${responseBinding}>
  <saml:Issuer>${escapeXml(configuration.entityId)}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  ${assertionPayload}
</samlp:Response>`;
  const responseXpath = "//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']";
  response = signElement(response, responseXpath, {
    reference: `${responseXpath}/*[local-name(.)='Issuer']`, action: 'after',
  }, privateKey, configuration.signingCertificates[0]);
  return { assertionId, nameId, responseId, sessionIndex, xml: response };
}

function stateMatches(left, right) {
  return left?.kind === right?.kind && left?.realm === right?.realm && left?.spId === right?.spId
    && left?.requestId === right?.requestId && left?.issuedAt === right?.issuedAt;
}

function authenticationUrl(configuration, state, nonce, codeChallenge, forceAuthn) {
  const url = new URL(configuration.oidcAuthorizationUrl);
  url.searchParams.set('client_id', SAML_IDP_BRIDGE_CLIENT_ID);
  url.searchParams.set('redirect_uri', configuration.continuationUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (forceAuthn) url.searchParams.set('prompt', 'login');
  return url.href;
}

function logoutUrl(configuration, state) {
  const url = new URL(configuration.oidcLogoutUrl);
  url.searchParams.set('client_id', SAML_IDP_BRIDGE_CLIENT_ID);
  url.searchParams.set('post_logout_redirect_uri', configuration.logoutContinuationUrl);
  url.searchParams.set('state', state);
  return url.href;
}

function metadataXml(configuration) {
  const keys = configuration.signingCertificates.map((certificate) => (
    `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${stripCertificate(certificate)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
  )).join('');
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="${METADATA_NS}" xmlns:ds="${DSIG_NS}" entityID="${escapeXml(configuration.entityId)}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
    ${keys}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleLogoutService Binding="${REDIRECT_BINDING}" Location="${escapeXml(configuration.ssoUrl)}"/>
    <md:SingleSignOnService Binding="${REDIRECT_BINDING}" Location="${escapeXml(configuration.ssoUrl)}"/>
    <md:SingleSignOnService Binding="${POST_BINDING}" Location="${escapeXml(configuration.ssoUrl)}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

function logoutResponseXml(configuration, privateKey, pending, randomBytes, now) {
  const responseId = samlId('l', randomBytes);
  const issueInstantValue = new Date(now).toISOString();
  let xml = `<samlp:LogoutResponse xmlns:samlp="${PROTOCOL_NS}" xmlns:saml="${ASSERTION_NS}" ID="${responseId}" Version="2.0" IssueInstant="${issueInstantValue}" Destination="${escapeXml(pending.sloUrl)}" InResponseTo="${escapeXml(pending.requestId)}"><saml:Issuer>${escapeXml(configuration.entityId)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>`;
  const xpath = "//*[local-name(.)='LogoutResponse' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']";
  xml = signElement(xml, xpath, {
    reference: `${xpath}/*[local-name(.)='Issuer']`, action: 'after',
  }, privateKey, configuration.signingCertificates[0]);
  return xml;
}

async function signedRedirectResponse(destination, xml, relayState, privateKey) {
  const encoded = (await deflateRawAsync(Buffer.from(xml))).toString('base64');
  let signed = `SAMLResponse=${encodeURIComponent(encoded)}`;
  if (relayState !== undefined) signed += `&RelayState=${encodeURIComponent(relayState)}`;
  signed += `&SigAlg=${encodeURIComponent(RSA_SHA256)}`;
  const signature = createSign('RSA-SHA256').update(signed).sign(privateKey, 'base64');
  const separator = destination.includes('?') ? '&' : '?';
  return `${destination}${separator}${signed}&Signature=${encodeURIComponent(signature)}`;
}

export function renderSamlPostForm({ acsUrl, samlResponse, relayState, nonce }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Continue sign-in</title></head><body><form id="saml-response" method="post" action="${escapeHtml(acsUrl)}"><input type="hidden" name="SAMLResponse" value="${escapeHtml(samlResponse)}">${relayState === undefined ? '' : `<input type="hidden" name="RelayState" value="${escapeHtml(relayState)}">`}<noscript><button type="submit">Continue</button></noscript></form><script nonce="${escapeHtml(nonce)}">document.getElementById('saml-response').submit();</script></body></html>`;
}

export function createSamlIdentityProvider({
  realm,
  configuration: input,
  replayCache,
  subjectSalt,
  oidcAuthorizationUrl,
  oidcLogoutUrl,
  sessionTtlMs = 8 * 60 * 60 * 1000,
  now = Date.now,
  randomBytes = secureRandomBytes,
}) {
  nonEmpty(realm, 'realm', 63);
  if (!input || typeof input !== 'object') throw new TypeError('SAML IdP configuration is required');
  assertSamlReplayCache(replayCache);
  nonEmpty(subjectSalt, 'subjectSalt', 1024);
  nonEmpty(oidcAuthorizationUrl, 'oidcAuthorizationUrl', 4096);
  nonEmpty(oidcLogoutUrl, 'oidcLogoutUrl', 4096);
  if (typeof now !== 'function' || typeof randomBytes !== 'function') throw new TypeError('now and randomBytes must be functions');
  const { privateKey } = signingMaterial(input.signingPrivateKey, input.signingCertificates);
  integer(input.requestTtlMs, 'requestTtlMs', 30_000, 600_000);
  integer(input.clockSkewMs, 'clockSkewMs', 0, 300_000);
  integer(input.assertionTtlMs, 'assertionTtlMs', 30_000, 600_000);
  integer(input.maxRequestBytes, 'maxRequestBytes', 4096, 1024 * 1024);
  integer(sessionTtlMs, 'sessionTtlMs', 30_000, 24 * 60 * 60 * 1000);
  const serviceProviders = new Map();
  const serviceProviderIds = new Set();
  if (!Array.isArray(input.serviceProviders) || input.serviceProviders.length === 0 || input.serviceProviders.length > 1000) {
    throw new TypeError('SAML IdP serviceProviders must contain 1 to 1000 registrations');
  }
  for (const sp of input.serviceProviders) {
    if (serviceProviders.has(sp.entityId) || serviceProviderIds.has(sp.id)) {
      throw new TypeError('SAML IdP service-provider IDs and entity IDs must be unique');
    }
    serviceProviderIds.add(sp.id);
    for (const [index, certificate] of sp.signingCertificates.entries()) {
      publicCertificate(certificate, `${sp.id}.signingCertificates[${index}]`);
    }
    if (sp.encryptionCertificate) publicCertificate(sp.encryptionCertificate, `${sp.id}.encryptionCertificate`);
    serviceProviders.set(sp.entityId, sp);
  }
  const configuration = Object.freeze({
    ...input,
    realm,
    oidcAuthorizationUrl,
    oidcLogoutUrl,
  });
  const prefix = `saml-idp:${realm}`;
  const stateKey = (state) => `${prefix}:state:${state}`;
  const requestKey = (id) => `${prefix}:request:${id}`;
  const sessionKey = (id) => `${prefix}:session:${id}`;
  const stateTtl = input.requestTtlMs + input.clockSkewMs;
  const requestReplayTtl = input.requestTtlMs + (2 * input.clockSkewMs) + 1;

  async function authenticationContext(state) {
    if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(state)) fail('invalid_saml_state', 'SAML authentication state is invalid');
    const pending = await replayCache.get(stateKey(state));
    if (!pending || pending.kind !== 'authentication' || pending.realm !== realm) {
      fail('invalid_saml_state', 'SAML authentication state is unknown, expired, or already used');
    }
    return Object.freeze({ ...pending, continuationUrl: configuration.continuationUrl });
  }

  async function logoutContext(state) {
    if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(state)) fail('invalid_saml_state', 'SAML logout state is invalid');
    const pending = await replayCache.get(stateKey(state));
    if (!pending || pending.kind !== 'logout' || pending.realm !== realm) {
      fail('invalid_saml_state', 'SAML logout state is unknown, expired, or already used');
    }
    return Object.freeze({ ...pending });
  }

  async function saveState(pending) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const state = randomBytes(32).toString('base64url');
      if (await replayCache.putIfAbsent(stateKey(state), pending, stateTtl)) return state;
    }
    throw new Error('Unable to allocate unique SAML IdP state');
  }

  async function saveRequest(id) {
    if (!await replayCache.putIfAbsent(requestKey(id), true, requestReplayTtl)) {
      fail('replayed_saml_request', 'SAML request has already been used');
    }
  }

  async function startAuthentication(sp, details, relayState) {
    if (details.requestId) await saveRequest(details.requestId);
    const verifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(verifier).digest('base64url');
    const nonce = randomBytes(32).toString('base64url');
    const pending = Object.freeze({
      kind: 'authentication',
      realm,
      spId: sp.id,
      requestId: details.requestId ?? null,
      acsUrl: details.acsUrl,
      relayState,
      codeChallenge,
      nonce,
      requestedAuthnContext: details.requestedAuthnContext ?? null,
      issuedAt: now(),
    });
    const state = await saveState(pending);
    return Object.freeze({
      kind: 'authentication',
      authorizationUrl: authenticationUrl(configuration, state, nonce, codeChallenge, details.forceAuthn),
      state,
    });
  }

  return Object.freeze({
    realm,
    metadata: () => metadataXml(configuration),
    async receiveRedirect(rawQuery) {
      const query = parseRawQuery(rawQuery);
      const parsed = await decodeRedirect(query.decoded.SAMLRequest, configuration.maxRequestBytes);
      const sp = serviceProviders.get(issuerFor(parsed.root));
      if (!sp) fail('unknown_service_provider', 'SAML request Issuer is not registered in this realm', null, 403);
      if (parsed.root.localName === 'AuthnRequest') {
        await verifyRedirectSignature(query, rawQuery, sp, configuration.entityId, configuration.ssoUrl,
          sp.requireSignedAuthnRequests);
        const details = authnRequest(parsed, sp, configuration, now());
        return startAuthentication(sp, details, query.decoded.RelayState);
      }
      await verifyRedirectSignature(query, rawQuery, sp, configuration.entityId, configuration.ssoUrl, true);
      const details = logoutRequest(parsed, sp, configuration, now());
      await saveRequest(details.requestId);
      const session = await replayCache.get(sessionKey(details.sessionIndex));
      if (!session || session.spId !== sp.id || session.nameId !== details.nameId) {
        fail('invalid_saml_session', 'LogoutRequest does not identify an active SAML session', null, 403);
      }
      if (await replayCache.consume(sessionKey(details.sessionIndex)) === null) {
        fail('invalid_saml_session', 'The SAML session was consumed concurrently', null, 403);
      }
      const pending = Object.freeze({
        kind: 'logout',
        realm,
        spId: sp.id,
        requestId: details.requestId,
        accountId: session.accountId,
        sloUrl: sp.sloUrl,
        relayState: query.decoded.RelayState,
        issuedAt: now(),
      });
      const state = await saveState(pending);
      return Object.freeze({ kind: 'logout', logoutUrl: logoutUrl(configuration, state), state });
    },
    async receivePost({ SAMLRequest, RelayState }) {
      if (RelayState !== undefined && (typeof RelayState !== 'string' || Buffer.byteLength(RelayState) > 80
        || /[\u0000-\u001f\u007f]/u.test(RelayState))) {
        fail('invalid_relay_state', 'RelayState exceeds the SAML binding limit or contains controls');
      }
      const parsed = decodePost(SAMLRequest, configuration.maxRequestBytes, 'AuthnRequest');
      const sp = serviceProviders.get(issuerFor(parsed.root));
      if (!sp) fail('unknown_service_provider', 'SAML AuthnRequest Issuer is not registered in this realm', null, 403);
      verifyXmlSignature(parsed, sp.signingCertificates, sp.requireSignedAuthnRequests);
      const details = authnRequest(parsed, sp, configuration, now());
      return startAuthentication(sp, details, RelayState);
    },
    async initiate(spId) {
      const sp = [...serviceProviders.values()].find((candidate) => candidate.id === spId);
      if (!sp || !sp.allowIdpInitiated) fail('idp_initiated_disabled', 'IdP-initiated SSO is not enabled for this service provider', null, 404);
      return startAuthentication(sp, {
        acsUrl: sp.acsUrls[0], forceAuthn: false, requestId: null,
      });
    },
    authenticationContext,
    async complete({ state, user, authentication }) {
      const pending = await authenticationContext(state);
      if (!user?.enabled || typeof user.id !== 'string') fail('invalid_account', 'The authenticated account is unavailable', null, 403);
      const sp = [...serviceProviders.values()].find((candidate) => candidate.id === pending.spId);
      if (!sp || !sp.acsUrls.includes(pending.acsUrl)) fail('unregistered_acs', 'The pending SAML ACS is no longer registered', null, 403);
      const generated = await responseXml({
        configuration,
        privateKey,
        sp,
        user,
        requestId: pending.requestId,
        requestedAuthnContext: pending.requestedAuthnContext,
        authentication: { ...authentication, acsUrl: pending.acsUrl },
        subjectSalt,
        randomBytes,
        now: now(),
      });
      const consumed = await replayCache.consume(stateKey(state));
      if (!stateMatches(consumed, pending)) fail('invalid_saml_state', 'SAML authentication state was consumed concurrently');
      const sessionSaved = await replayCache.putIfAbsent(sessionKey(generated.sessionIndex), {
        accountId: user.id, nameId: generated.nameId, spId: sp.id,
      }, sessionTtlMs);
      if (!sessionSaved) throw new Error('Unable to allocate unique SAML session index');
      return Object.freeze({
        acsUrl: pending.acsUrl,
        assertionId: generated.assertionId,
        relayState: pending.relayState,
        requestId: pending.requestId,
        responseId: generated.responseId,
        samlResponse: Buffer.from(generated.xml).toString('base64'),
        sessionIndex: generated.sessionIndex,
        xml: generated.xml,
      });
    },
    logoutContext,
    async completeLogout(state) {
      const pending = await logoutContext(state);
      const xml = logoutResponseXml(configuration, privateKey, pending, randomBytes, now());
      const redirectUrl = await signedRedirectResponse(
        pending.sloUrl, xml, pending.relayState, privateKey,
      );
      const consumed = await replayCache.consume(stateKey(state));
      if (!stateMatches(consumed, pending)) fail('invalid_saml_state', 'SAML logout state was consumed concurrently');
      return Object.freeze({ redirectUrl, xml });
    },
  });
}
