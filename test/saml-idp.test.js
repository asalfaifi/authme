import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import express from 'express';
import { test } from 'node:test';
import { SAML } from '@node-saml/node-saml';
import { PemConverter, X509CertificateGenerator, cryptoProvider } from '@peculiar/x509';
import request from 'supertest';
import { SignedXml } from 'xml-crypto';
import {
  createSamlIdentityProvider,
  MemorySamlReplayCache,
  SamlIdentityProviderError,
} from '../src/federation/index.js';
import { parseSamlIdentityProviders } from '../src/federation/saml-config.js';
import { createSamlIdentityProviderRouter } from '../src/routes/saml-idp.js';
import { configuredClientsForRealm } from '../src/provider.js';

cryptoProvider.set(webcrypto);

const ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const POST_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const MASTER_IDP = 'https://login.example.test/realms/master/protocol/saml';
const STAFF_IDP = 'https://login.example.test/realms/staff/protocol/saml';
const SP_ENTITY_ID = 'https://sp.example.test/saml/metadata';
const ACS_URL = 'https://sp.example.test/saml/acs';
const SLO_URL = 'https://sp.example.test/saml/slo';
const PASSWORD_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
const WEB_AUTHN_CONTEXT = 'urn:authme:ac:classes:WebAuthn';
const MFA_CONTEXT = 'https://refeds.org/profile/mfa';

async function credentials(name) {
  const keys = await webcrypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  }, true, ['sign', 'verify']);
  const certificate = await X509CertificateGenerator.createSelfSigned({
    name: `CN=${name}`,
    keys,
    serialNumber: Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString(16),
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  });
  return {
    certificate: certificate.toString(),
    privateKey: PemConverter.encode(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY'),
  };
}

const idpCredentials = await credentials('AuthMe test IdP');
const spCredentials = await credentials('AuthMe test SP');

function rawConfiguration({ realm = 'master', encryptAssertions = false, serviceProvider = {} } = {}) {
  return {
    entity_id: realm === 'master' ? MASTER_IDP : STAFF_IDP,
    signing_private_key: idpCredentials.privateKey,
    signing_certificates: [idpCredentials.certificate],
    service_providers: [{
      id: 'analytics',
      entity_id: SP_ENTITY_ID,
      acs_urls: [ACS_URL],
      slo_url: SLO_URL,
      signing_certificates: [spCredentials.certificate],
      require_signed_authn_requests: true,
      encryption_certificate: encryptAssertions ? spCredentials.certificate : undefined,
      encrypt_assertions: encryptAssertions,
      allow_idp_initiated: true,
      name_id_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      attribute_mapping: {
        uid: 'username',
        mail: 'email',
        memberOf: 'groups',
        roles: 'roles',
      },
      ...serviceProvider,
    }],
  };
}

function configuration(options = {}) {
  const realm = options.realm ?? 'master';
  return parseSamlIdentityProviders(JSON.stringify({ [realm]: rawConfiguration(options) }), {
    realms: [realm], publicUrl: 'https://login.example.test',
  })[realm];
}

function identityProvider(options = {}) {
  const realm = options.realm ?? 'master';
  const now = options.now ?? Date.now;
  return createSamlIdentityProvider({
    realm,
    configuration: configuration(options),
    replayCache: options.replayCache ?? new MemorySamlReplayCache({ now }),
    subjectSalt: 'test-saml-idp-pairwise-subject-salt',
    oidcAuthorizationUrl: `https://login.example.test/realms/${realm}/protocol/openid-connect/auth`,
    oidcLogoutUrl: `https://login.example.test/realms/${realm}/protocol/openid-connect/logout`,
    now,
  });
}

function serviceProvider({ acsUrl = ACS_URL, destination = MASTER_IDP } = {}) {
  return new SAML({
    issuer: SP_ENTITY_ID,
    callbackUrl: acsUrl,
    entryPoint: destination,
    idpCert: idpCredentials.certificate,
    privateKey: spCredentials.privateKey,
    publicCert: spCredentials.certificate,
    signatureAlgorithm: 'sha256',
    digestAlgorithm: 'sha256',
    authnRequestBinding: 'HTTP-Redirect',
    wantAuthnResponseSigned: true,
    wantAssertionsSigned: true,
    validateInResponseTo: 'never',
    identifierFormat: null,
    disableRequestedAuthnContext: true,
    acceptedClockSkewMs: 60_000,
    maxAssertionAgeMs: 300_000,
    logoutUrl: destination,
  });
}

async function redirectRequest(options = {}) {
  const url = await serviceProvider(options).getAuthorizeUrlAsync('relay-state', undefined, {});
  return new URL(url).search.slice(1);
}

const user = Object.freeze({
  id: '4cd433eb-0f19-4e16-8749-60d80c04a5d4',
  enabled: true,
  username: 'alice',
  email: 'alice@example.test',
  emailVerified: true,
  name: 'Alice Example',
  givenName: 'Alice',
  familyName: 'Example',
  groups: ['/engineering', '/platform'],
  roles: ['developer'],
});

async function complete(target, rawQuery) {
  const started = await target.receiveRedirect(rawQuery ?? await redirectRequest());
  const result = await target.complete({
    state: started.state,
    user,
    authentication: { acr: 'urn:authme:loa:2', amr: ['pwd', 'otp'], authTime: Math.floor(Date.now() / 1000) },
  });
  return { result, started };
}

function signPostRequest(xml) {
  const signature = new SignedXml();
  signature.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  signature.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  signature.addReference({
    xpath: "//*[local-name(.)='AuthnRequest' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  signature.privateKey = spCredentials.privateKey;
  signature.publicCert = spCredentials.certificate;
  signature.computeSignature(xml, {
    location: {
      reference: "//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']",
      action: 'after',
    },
  });
  return signature.getSignedXml();
}

function postRequestXml({
  id = '_post-request',
  acsUrl = ACS_URL,
  destination = MASTER_IDP,
  issueInstant = new Date().toISOString(),
  requestedAuthnContext,
} = {}) {
  const requested = requestedAuthnContext
    ? `<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>${requestedAuthnContext}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`
    : '';
  return `<samlp:AuthnRequest xmlns:samlp="${PROTOCOL_NS}" xmlns:saml="${ASSERTION_NS}" ID="${id}" Version="2.0" IssueInstant="${issueInstant}" Destination="${destination}" AssertionConsumerServiceURL="${acsUrl}" ProtocolBinding="${POST_BINDING}"><saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>${requested}</samlp:AuthnRequest>`;
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error instanceof SamlIdentityProviderError, true);
    assert.equal(error.code, code);
    return true;
  });
}

test('SAML IdP metadata is published with realm entity, bindings, and signing certificate', async () => {
  const target = identityProvider();
  const app = express();
  app.use(createSamlIdentityProviderRouter({
    realm: 'master',
    identityProvider: target,
    provider: {
      AuthorizationCode: { find: async () => null },
      Session: { get: async () => ({}) },
    },
    store: { findUserById: async () => null },
    audit: async () => {},
  }));
  const response = await request(app).get('/realms/master/protocol/saml/descriptor').expect(200);
  assert.match(response.headers['content-type'], /^application\/samlmetadata\+xml/u);
  assert.match(response.text, new RegExp(`entityID="${MASTER_IDP}"`, 'u'));
  assert.match(response.text, /SingleSignOnService Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"/u);
  assert.match(response.text, /SingleSignOnService Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"/u);
  assert.match(response.text, /SingleLogoutService/u);
  assert.match(response.text, /X509Certificate/u);
});

test('reserved OIDC bridge client has only exact realm-local SAML continuation endpoints', () => {
  const config = {
    clientsByRealm: { master: [] },
    devMode: false,
    publicUrl: 'https://login.example.test',
    samlIdentityProvidersByRealm: { master: {} },
  };
  const clients = configuredClientsForRealm(config, 'master');
  const bridge = clients.find((client) => client.client_id === 'authme-saml-idp');
  assert.deepEqual(bridge.redirect_uris, ['https://login.example.test/realms/master/protocol/saml/continue']);
  assert.deepEqual(bridge.post_logout_redirect_uris, ['https://login.example.test/realms/master/protocol/saml/logout/continue']);
  assert.equal(bridge.token_endpoint_auth_method, 'none');
  assert.throws(() => configuredClientsForRealm({
    ...config,
    clientsByRealm: { master: [{ client_id: 'authme-saml-idp' }] },
  }, 'master'), /reserved/u);
});

test('SAML continuation consumes only the exact OIDC bridge code and returns a constrained POST form', async () => {
  const target = identityProvider();
  const started = await target.receiveRedirect(await redirectRequest());
  const context = await target.authenticationContext(started.state);
  let consumed = false;
  const app = express();
  app.use(createSamlIdentityProviderRouter({
    realm: 'master',
    identityProvider: target,
    provider: {
      issuer: 'https://login.example.test/realms/master',
      AuthorizationCode: {
        find: async () => ({
          isValid: true,
          clientId: 'authme-saml-idp',
          redirectUri: context.continuationUrl,
          nonce: context.nonce,
          codeChallenge: context.codeChallenge,
          codeChallengeMethod: 'S256',
          accountId: user.id,
          acr: 'urn:authme:loa:2',
          amr: ['passkey'],
          authTime: Math.floor(Date.now() / 1000),
          async consume() { consumed = true; },
        }),
      },
      Session: { get: async () => ({ accountId: user.id }) },
    },
    store: { findUserById: async () => user },
    audit: async () => {},
  }));
  const response = await request(app)
    .get(`/realms/master/protocol/saml/continue?${new URLSearchParams({
      code: 'authorization_code_value_1234567890',
      state: started.state,
      iss: 'https://login.example.test/realms/master',
    })}`)
    .expect(200);
  assert.equal(consumed, true);
  assert.match(response.text, new RegExp(`action="${ACS_URL}"`, 'u'));
  assert.match(response.text, /name="SAMLResponse"/u);
  assert.match(response.headers['content-security-policy'], /form-action https:\/\/sp\.example\.test/u);
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('SP-initiated SSO returns signed Response and Assertion with bounded audience and conditions', async () => {
  const target = identityProvider();
  const { result, started } = await complete(target);
  assert.equal(new URL(started.authorizationUrl).searchParams.get('client_id'), 'authme-saml-idp');
  assert.equal(result.acsUrl, ACS_URL);
  assert.equal(result.relayState, 'relay-state');
  assert.match(result.xml, /<saml:OneTimeUse\/>/u);
  assert.match(result.xml, new RegExp(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`, 'u'));
  assert.match(result.xml, new RegExp(`InResponseTo="${result.requestId}"`, 'u'));
  assert.equal((result.xml.match(/<Signature /gu) ?? []).length, 2);
  assert.match(result.xml, /<saml:Attribute Name="uid">/u);
  assert.match(result.xml, new RegExp(`<saml:AuthnContextClassRef>${MFA_CONTEXT}</saml:AuthnContextClassRef>`, 'u'));

  const validation = await serviceProvider().validatePostResponseAsync({ SAMLResponse: result.samlResponse });
  assert.equal(validation.loggedOut, false);
  assert.equal(validation.profile.issuer, MASTER_IDP);
  assert.equal(validation.profile.inResponseTo, result.requestId);
  assert.equal(validation.profile.attributes.uid, 'alice');
  assert.deepEqual(validation.profile.attributes.memberOf, ['/engineering', '/platform']);
  const assertion = validation.profile.getAssertion().Assertion;
  assert.equal(assertion.Conditions[0].AudienceRestriction[0].Audience[0]._, SP_ENTITY_ID);
  assert.ok(Date.parse(assertion.Conditions[0].$.NotOnOrAfter) > Date.now());
});

test('HTTP-POST AuthnRequest signatures are verified before starting the AuthMe interaction', async () => {
  const target = identityProvider();
  const signed = signPostRequest(postRequestXml());
  const started = await target.receivePost({
    SAMLRequest: Buffer.from(signed).toString('base64'), RelayState: 'post-relay',
  });
  assert.equal(started.kind, 'authentication');
  assert.equal(new URL(started.authorizationUrl).searchParams.get('state'), started.state);
});

test('unsatisfied RequestedAuthnContext is rejected instead of asserting a false method', async () => {
  const target = identityProvider();
  const signed = signPostRequest(postRequestXml({
    id: '_requested-password', requestedAuthnContext: PASSWORD_CONTEXT,
  }));
  const started = await target.receivePost({ SAMLRequest: Buffer.from(signed).toString('base64') });
  await rejectsCode(target.complete({
    state: started.state,
    user,
    authentication: {
      acr: 'urn:authme:loa:2', amr: ['passkey'], authTime: Math.floor(Date.now() / 1000),
    },
  }), 'no_authn_context');
});

test('unregistered ACS, bad signatures, replay, XSW, and XXE fail closed', async (t) => {
  await t.test('unregistered ACS', async () => {
    const target = identityProvider();
    await rejectsCode(target.receiveRedirect(await redirectRequest({ acsUrl: 'https://attacker.example.test/collect' })), 'unregistered_acs');
  });

  await t.test('redirect signature tampering', async () => {
    const target = identityProvider();
    const query = await redirectRequest();
    const tampered = query.replace('RelayState=relay-state', 'RelayState=attacker-state');
    await rejectsCode(target.receiveRedirect(tampered), 'invalid_saml_signature');
  });

  await t.test('request replay', async () => {
    const target = identityProvider();
    const query = await redirectRequest();
    await target.receiveRedirect(query);
    await rejectsCode(target.receiveRedirect(query), 'replayed_saml_request');
  });

  await t.test('future-dated request replay at the former retention boundary', async () => {
    const receivedAt = Date.parse('2026-07-16T10:00:00.000Z');
    let currentTime = receivedAt;
    const now = () => currentTime;
    const target = identityProvider({ now });
    const signed = signPostRequest(postRequestXml({
      id: '_future-replay-boundary',
      issueInstant: new Date(receivedAt + 60_000).toISOString(),
    }));
    const requestBody = { SAMLRequest: Buffer.from(signed).toString('base64') };
    await target.receivePost(requestBody);
    currentTime = receivedAt + 300_000 + 60_000;
    await rejectsCode(target.receivePost(requestBody), 'replayed_saml_request');
  });

  await t.test('signature wrapping duplicate ID', async () => {
    const target = identityProvider();
    const signed = signPostRequest(postRequestXml({ id: '_xsw-request' }));
    const wrapped = signed.replace('</samlp:AuthnRequest>', '<samlp:Extensions ID="_xsw-request"/></samlp:AuthnRequest>');
    await rejectsCode(target.receivePost({ SAMLRequest: Buffer.from(wrapped).toString('base64') }), 'invalid_saml_request');
  });

  await t.test('external entity declaration', async () => {
    const target = identityProvider();
    const xml = `<!DOCTYPE samlp:AuthnRequest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>${postRequestXml()}`;
    await rejectsCode(target.receivePost({ SAMLRequest: Buffer.from(xml).toString('base64') }), 'invalid_saml_request');
  });
});

test('encrypted signed assertion decrypts and validates through Node-SAML', async () => {
  const target = identityProvider({ encryptAssertions: true });
  const { result } = await complete(target);
  assert.match(result.xml, /<saml:EncryptedAssertion/u);
  assert.doesNotMatch(result.xml, /<saml:Assertion/u);
  const validator = new SAML({
    ...serviceProvider().options,
    decryptionPvk: spCredentials.privateKey,
  });
  const validation = await validator.validatePostResponseAsync({ SAMLResponse: result.samlResponse });
  assert.match(validation.profile.getAssertionXml(), /<saml:Attribute Name="mail">/u);
  assert.equal(validation.profile.attributes.mail, 'alice@example.test');
  assert.equal(validation.profile.issuer, MASTER_IDP);
});

test('SAML service-provider trust and pending state are isolated by realm', async () => {
  const master = identityProvider();
  const staff = identityProvider({ realm: 'staff' });
  const query = await redirectRequest();
  await master.receiveRedirect(query);
  await rejectsCode(staff.receiveRedirect(query), 'invalid_destination');

  const masterStarted = await master.initiate('analytics');
  await rejectsCode(staff.authenticationContext(masterStarted.state), 'invalid_saml_state');
});

test('IdP-initiated SSO is opt-in and omits request correlation only for the registered default ACS', async () => {
  const target = identityProvider();
  const started = await target.initiate('analytics');
  const result = await target.complete({
    state: started.state,
    user,
    authentication: { amr: ['passkey'], acr: 'urn:authme:loa:2', authTime: Math.floor(Date.now() / 1000) },
  });
  assert.equal(result.requestId, null);
  assert.equal(result.acsUrl, ACS_URL);
  assert.doesNotMatch(result.xml, /InResponseTo=/u);
  assert.match(result.xml, new RegExp(`<saml:AuthnContextClassRef>${WEB_AUTHN_CONTEXT}</saml:AuthnContextClassRef>`, 'u'));

  const disabled = identityProvider({ serviceProvider: { allow_idp_initiated: false } });
  await rejectsCode(disabled.initiate('analytics'), 'idp_initiated_disabled');
});

test('SP-initiated redirect logout consumes the issued SAML session and returns a signed LogoutResponse', async () => {
  const target = identityProvider();
  const { result } = await complete(target);
  const validation = await serviceProvider().validatePostResponseAsync({ SAMLResponse: result.samlResponse });
  const logout = await serviceProvider().getLogoutUrlAsync({
    nameID: validation.profile.nameID,
    nameIDFormat: validation.profile.nameIDFormat,
    sessionIndex: validation.profile.sessionIndex,
  }, 'logout-relay', {});
  const started = await target.receiveRedirect(new URL(logout).search.slice(1));
  assert.equal(started.kind, 'logout');
  assert.match(started.logoutUrl, /protocol\/openid-connect\/logout/u);
  const completed = await target.completeLogout(started.state);
  const redirect = new URL(completed.redirectUrl);
  assert.equal(`${redirect.origin}${redirect.pathname}`, SLO_URL);
  assert.equal(redirect.searchParams.get('RelayState'), 'logout-relay');
  const responseXml = inflateRawSync(Buffer.from(redirect.searchParams.get('SAMLResponse'), 'base64')).toString('utf8');
  assert.match(responseXml, /<samlp:LogoutResponse/u);
  assert.match(completed.xml, new RegExp(`InResponseTo="[^"]+"`, 'u'));
  assert.match(completed.xml, /<Signature /u);
  await rejectsCode(target.receiveRedirect(new URL(logout).search.slice(1)), 'replayed_saml_request');
});
