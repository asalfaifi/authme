import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { SignedXml } from 'xml-crypto';
import {
  completeSamlJitHandoff,
  createAdapterSamlReplayCache,
  createSamlBroker,
  createSamlFederationExtension,
  MemorySamlReplayCache,
  SamlFederationError,
} from '../src/federation/index.js';
import { createMemoryAdapter } from '../src/adapters/memory.js';

const SP_ENTITY_ID = 'https://auth.example.test/realms/master/saml/acme';
const ACS_URL = 'https://auth.example.test/realms/master/saml/acme/acs';
const IDP_ENTITY_ID = 'https://idp.example.test/metadata';
const IDP_SSO_URL = 'https://idp.example.test/sso';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const idpPrivateKey = privateKey.export({ type: 'pkcs8', format: 'pem' });
const idpPublicKey = publicKey.export({ type: 'spki', format: 'pem' });

function signElement(xml, xpath, location) {
  const signature = new SignedXml();
  signature.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  signature.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  signature.addReference({
    xpath,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  signature.privateKey = idpPrivateKey;
  signature.computeSignature(xml, { location });
  return signature.getSignedXml();
}

function signedResponse({
  requestId,
  responseId = `_${randomUUID()}`,
  assertionId = `_${randomUUID()}`,
  destination = ACS_URL,
  audience = SP_ENTITY_ID,
  issuer = IDP_ENTITY_ID,
  now = Date.now(),
  notBefore = new Date(now - 30_000).toISOString(),
  notOnOrAfter = new Date(now + 120_000).toISOString(),
  signAssertion = true,
  signResponse = true,
} = {}) {
  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${new Date(now).toISOString()}" Destination="${destination}" InResponseTo="${requestId}">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${new Date(now).toISOString()}">
    <saml:Issuer>${issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">alice-idp-subject</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="${requestId}" Recipient="${destination}" NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
      <saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${new Date(now - 1000).toISOString()}" SessionIndex="session-1">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid"><saml:AttributeValue>alice</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="mail"><saml:AttributeValue>alice@example.test</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="memberOf"><saml:AttributeValue>/engineering</saml:AttributeValue><saml:AttributeValue>/platform</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="roles"><saml:AttributeValue>developer</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;
  if (signAssertion) {
    const assertion = "//*[local-name(.)='Assertion' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']";
    const assertionIssuer = `${assertion}/*[local-name(.)='Issuer']`;
    xml = signElement(xml, assertion, { reference: assertionIssuer, action: 'after' });
  }
  if (signResponse) {
    const response = "//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']";
    const responseIssuer = `${response}/*[local-name(.)='Issuer']`;
    xml = signElement(xml, response, { reference: responseIssuer, action: 'after' });
  }
  return {
    assertionId,
    encoded: Buffer.from(xml).toString('base64'),
    responseId,
    xml,
  };
}

function broker(replayCache = new MemorySamlReplayCache(), overrides = {}) {
  return createSamlBroker({
    realm: 'master',
    providerId: 'acme',
    replayCache,
    sp: {
      entityId: SP_ENTITY_ID,
      assertionConsumerServiceUrl: ACS_URL,
    },
    idp: {
      entityId: IDP_ENTITY_ID,
      ssoUrl: IDP_SSO_URL,
      signingCertificates: [idpPublicKey],
    },
    trustEmail: true,
    ...overrides,
  });
}

async function initiated(target = broker(), interactionUid = `interaction_${randomUUID().replaceAll('-', '')}`) {
  const request = await target.start({ interactionUid });
  return { target, request };
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error instanceof SamlFederationError, true);
    assert.equal(error.code, code);
    return true;
  });
}

test('memory replay cache provides atomic insert, expiry, and consume semantics', async () => {
  let now = 1000;
  const cache = new MemorySamlReplayCache({ now: () => now });
  assert.equal(await cache.putIfAbsent('key', { value: 1 }, 100), true);
  assert.equal(await cache.putIfAbsent('key', { value: 2 }, 100), false);
  assert.deepEqual(await cache.get('key'), { value: 1 });
  assert.deepEqual(await cache.consume('key'), { value: 1 });
  assert.equal(await cache.consume('key'), null);
  assert.equal(await cache.putIfAbsent('expiring', true, 100), true);
  now = 1100;
  assert.equal(await cache.get('expiring'), null);
});

test('adapter replay cache reuses realm-scoped durable one-use records', async () => {
  const Adapter = createMemoryAdapter({ realm: `saml-cache-${randomUUID()}` });
  const cache = createAdapterSamlReplayCache(Adapter);
  assert.equal(await cache.putIfAbsent('shared-key', { request: 1 }, 60_000), true);
  assert.equal(await cache.putIfAbsent('shared-key', { request: 2 }, 60_000), false);
  assert.deepEqual(await cache.get('shared-key'), { request: 1 });
  assert.deepEqual(await cache.consume('shared-key'), { request: 1 });
  assert.equal(await cache.get('shared-key'), null);
  assert.equal(await cache.consume('shared-key'), null);
});

test('SAML trust configuration rejects weak signing keys and non-certificate SP credentials', () => {
  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const weakPublicKey = weak.publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => broker(new MemorySamlReplayCache(), {
    idp: { entityId: IDP_ENTITY_ID, ssoUrl: IDP_SSO_URL, signingCertificates: [weakPublicKey] },
  }), /at least 2048 bits/);
  assert.throws(() => broker(new MemorySamlReplayCache(), {
    sp: {
      entityId: SP_ENTITY_ID,
      assertionConsumerServiceUrl: ACS_URL,
      signingPrivateKey: idpPrivateKey,
      signingCertificates: [idpPublicKey],
    },
  }), /X\.509 certificate/);
});

test('SP metadata and AuthnRequest advertise exact endpoints and bind opaque RelayState', async () => {
  const { target, request } = await initiated();
  const metadata = target.metadata();
  assert.match(metadata, new RegExp(`entityID="${SP_ENTITY_ID}"`));
  assert.match(metadata, new RegExp(`Location="${ACS_URL}"`));
  assert.match(metadata, /WantAssertionsSigned="true"/);
  assert.match(metadata, /AuthnRequestsSigned="false"/);

  const redirect = new URL(request.redirectUrl);
  assert.equal(`${redirect.origin}${redirect.pathname}`, IDP_SSO_URL);
  assert.equal(redirect.searchParams.get('RelayState'), request.relayState);
  assert.ok(redirect.searchParams.get('SAMLRequest'));
  assert.equal(request.relayState.length, 43);
  assert.match(request.relayState, /^[A-Za-z0-9_-]+$/);
  assert.match(request.requestId, /^_/);
});

test('signed Response and Assertion produce a bounded JIT handoff and are one-use', async () => {
  const { target, request } = await initiated();
  const response = signedResponse({ requestId: request.requestId });
  const validation = await target.consumePost({
    SAMLResponse: response.encoded,
    RelayState: request.relayState,
  });

  assert.equal(validation.interactionUid.startsWith('interaction_'), true);
  assert.equal(validation.requestId, request.requestId);
  assert.equal(validation.responseId, response.responseId);
  assert.equal(validation.assertionId, response.assertionId);
  assert.deepEqual(validation.identity, {
    protocol: 'saml',
    realm: 'master',
    providerId: 'acme',
    issuer: IDP_ENTITY_ID,
    externalSubject: 'alice-idp-subject',
    nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    sessionIndex: 'session-1',
    attributes: {
      uid: ['alice'],
      mail: ['alice@example.test'],
      displayName: ['Alice Example'],
      memberOf: ['/engineering', '/platform'],
      roles: ['developer'],
    },
    suggested: {
      username: 'alice',
      email: 'alice@example.test',
      emailVerified: true,
      name: 'Alice Example',
      givenName: undefined,
      familyName: undefined,
      groups: ['/engineering', '/platform'],
      roles: ['developer'],
    },
  });

  const accountId = randomUUID();
  const completed = await completeSamlJitHandoff(validation, async (identity) => {
    assert.equal(identity.externalSubject, 'alice-idp-subject');
    return { accountId, created: true };
  });
  assert.deepEqual(completed.login, {
    accountId,
    acr: 'urn:authme:loa:federated',
    amr: ['federated', 'saml'],
    remember: true,
  });
  assert.equal(completed.created, true);
  await rejectsCode(target.consumePost({ SAMLResponse: response.encoded, RelayState: request.relayState }), 'invalid_relay_state');
});

test('SAML federation extension exposes the shared federation/JIT contract', async () => {
  const sharedCache = new MemorySamlReplayCache();
  const extension = createSamlFederationExtension({
    providersByRealm: {
      master: [{
        id: 'acme',
        displayName: 'Acme Workforce',
        sp: { entityId: SP_ENTITY_ID, assertionConsumerServiceUrl: ACS_URL },
        idp: { entityId: IDP_ENTITY_ID, ssoUrl: IDP_SSO_URL, signingCertificates: [idpPublicKey] },
        trustEmail: true,
        jitProvisioning: true,
      }],
    },
    replayCacheFor: () => sharedCache,
  });
  assert.equal(extension.manifest.id, 'builtin.saml-federation');
  assert.deepEqual(extension.implementation.providersFor('master'), [{ id: 'acme', displayName: 'Acme Workforce' }]);
  assert.match(extension.implementation.metadataFor('master', 'acme'), /WantAssertionsSigned="true"/);
  const request = await extension.implementation.initiate({
    realm: 'master', providerId: 'acme', interactionUid: 'interaction_extension',
  });
  const response = signedResponse({ requestId: request.requestId });
  const result = await extension.implementation.consume({
    realm: 'master', providerId: 'acme',
    params: { SAMLResponse: response.encoded, RelayState: request.relayState },
  });
  assert.deepEqual(result.profile, {
    externalSubject: 'alice-idp-subject',
    username: 'alice',
    email: 'alice@example.test',
    emailVerified: true,
    name: 'Alice Example',
    givenName: '',
    familyName: '',
    groups: ['/engineering', '/platform'],
    roles: ['developer'],
  });
  assert.deepEqual(result.amr, ['federated', 'saml']);
  assert.equal(result.allowCreate, true);
});

test('destination, request binding, signature, audience, time, issuer, and replay checks fail closed', async (t) => {
  await t.test('destination', async () => {
    const { target, request } = await initiated();
    const response = signedResponse({ requestId: request.requestId, destination: 'https://attacker.example.test/acs' });
    await rejectsCode(target.consumePost({ SAMLResponse: response.encoded, RelayState: request.relayState }), 'invalid_destination');
  });

  await t.test('RelayState cannot be swapped between OIDC interactions', async () => {
    const target = broker();
    const first = await target.start({ interactionUid: 'interaction_first' });
    const second = await target.start({ interactionUid: 'interaction_second' });
    const response = signedResponse({ requestId: first.requestId });
    await rejectsCode(target.consumePost({ SAMLResponse: response.encoded, RelayState: second.relayState }), 'invalid_in_response_to');
  });

  await t.test('both Response and Assertion signatures are required', async () => {
    const { target, request } = await initiated();
    const response = signedResponse({ requestId: request.requestId, signAssertion: false });
    await rejectsCode(target.consumePost({ SAMLResponse: response.encoded, RelayState: request.relayState }), 'invalid_signature_algorithm');
  });

  await t.test('signature tampering', async () => {
    const { target, request } = await initiated();
    const response = signedResponse({ requestId: request.requestId });
    const tampered = Buffer.from(response.xml.replace('alice@example.test', 'mallory@example.test')).toString('base64');
    await rejectsCode(target.consumePost({ SAMLResponse: tampered, RelayState: request.relayState }), 'invalid_saml_response');
  });

  await t.test('audience', async () => {
    const { target, request } = await initiated();
    const response = signedResponse({ requestId: request.requestId, audience: 'https://other-sp.example.test/' });
    await rejectsCode(target.consumePost({ SAMLResponse: response.encoded, RelayState: request.relayState }), 'invalid_saml_response');
  });

  await t.test('expired assertion', async () => {
    const { target, request } = await initiated();
    const expired = Date.now() - 60_000;
    const response = signedResponse({
      requestId: request.requestId,
      notBefore: new Date(expired - 60_000).toISOString(),
      notOnOrAfter: new Date(expired).toISOString(),
    });
    await rejectsCode(target.consumePost({ SAMLResponse: response.encoded, RelayState: request.relayState }), 'invalid_saml_response');
  });

  await t.test('assertion issuer', async () => {
    const { target, request } = await initiated();
    const response = signedResponse({ requestId: request.requestId, issuer: 'https://other-idp.example.test/' });
    await rejectsCode(target.consumePost({ SAMLResponse: response.encoded, RelayState: request.relayState }), 'invalid_issuer');
  });

  await t.test('response ID replay across requests', async () => {
    const target = broker();
    const first = await target.start({ interactionUid: 'interaction_replay_1' });
    const responseId = `_${randomUUID()}`;
    const firstResponse = signedResponse({ requestId: first.requestId, responseId });
    await target.consumePost({ SAMLResponse: firstResponse.encoded, RelayState: first.relayState });
    const second = await target.start({ interactionUid: 'interaction_replay_2' });
    const secondResponse = signedResponse({ requestId: second.requestId, responseId });
    await rejectsCode(target.consumePost({ SAMLResponse: secondResponse.encoded, RelayState: second.relayState }), 'replayed_saml_response');
  });

  await t.test('assertion ID replay across requests', async () => {
    const target = broker();
    const first = await target.start({ interactionUid: 'interaction_assertion_replay_1' });
    const assertionId = `_${randomUUID()}`;
    const firstResponse = signedResponse({ requestId: first.requestId, assertionId });
    await target.consumePost({ SAMLResponse: firstResponse.encoded, RelayState: first.relayState });
    const second = await target.start({ interactionUid: 'interaction_assertion_replay_2' });
    const secondResponse = signedResponse({ requestId: second.requestId, assertionId });
    await rejectsCode(target.consumePost({ SAMLResponse: secondResponse.encoded, RelayState: second.relayState }), 'replayed_saml_assertion');
  });
});
