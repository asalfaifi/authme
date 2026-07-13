import assert from 'node:assert/strict';
import { test } from 'node:test';
import express from 'express';
import request from 'supertest';

import {
  createFederationInitiationCsrfToken,
  createFederationRouter,
} from '../src/routes/federation.js';

const realm = 'master';
const uid = 'interaction-uid-one';
const csrfSecret = 'federation-route-csrf-secret-that-is-long-enough';
const accountId = '123e4567-e89b-42d3-a456-426614174000';
const oidcState = 'oidc_state_01234567890123456789012345678901';

function federationResult(providerId, overrides = {}) {
  return {
    interactionUid: uid,
    providerId,
    profile: {
      externalSubject: 'upstream-subject',
      username: 'alice',
      email: 'alice@example.test',
    },
    amr: ['federated'],
    acr: 'urn:authme:loa:federated',
    ...overrides,
  };
}

function stateStoreFixture() {
  const states = new Map();
  let counter = 1;
  return {
    states,
    async issue(stateRealm, payload, ttl) {
      const handle = Buffer.alloc(32, counter++).toString('base64url');
      states.set(`${stateRealm}:${handle}`, { payload, ttl });
      return handle;
    },
    async consume(stateRealm, handle) {
      const key = `${stateRealm}:${handle}`;
      const record = states.get(key);
      if (!record) {
        throw Object.assign(new Error('Federation state is missing, expired, or already used'), {
          code: 'AUTHME_FEDERATION_STATE_INVALID', status: 400, safe: true,
        });
      }
      states.delete(key);
      return record.payload;
    },
  };
}

function fixture(options = {}) {
  const calls = {
    initiated: [],
    consumed: [],
    resolved: [],
    audit: [],
    finished: [],
  };
  const interaction = {
    uid,
    prompt: 'login',
  };
  const stateStore = options.stateStore ?? stateStoreFixture();
  const saml = {
    manifest: {
      id: 'builtin.saml-federation',
      kind: 'federation',
      capabilities: ['jit-provisioning', 'saml2', 'sp-initiated'],
    },
    implementation: {
      enabledFor: () => true,
      providersFor: () => [{ id: 'corp', displayName: 'Corporate SSO' }],
      metadataFor: () => '<EntityDescriptor entityID="https://login.example.test/saml"/>',
      async initiate(input) {
        calls.initiated.push(input);
        return { redirectUrl: options.samlRedirect ?? 'https://idp.example.test/sso?SAMLRequest=opaque' };
      },
      async consume(input) {
        calls.consumed.push(input);
        return options.samlResult ?? federationResult('corp', {
          identity: { externalSubject: 'upstream-subject', issuer: 'https://idp.example.test' },
          amr: ['federated', 'saml'],
        });
      },
    },
  };
  const oidc = {
    manifest: {
      id: 'builtin.oidc-federation',
      kind: 'federation',
      capabilities: ['oauth2', 'oidc', 'pkce'],
    },
    implementation: {
      enabledFor: () => true,
      providersFor: () => [{ id: 'partner', displayName: 'Partner Login' }],
      async initiate(input) {
        calls.initiated.push(input);
        return { redirectUrl: options.oidcRedirect ?? 'https://accounts.example.test/authorize?state=opaque' };
      },
      async consume(input) {
        calls.consumed.push(input);
        return options.oidcResult ?? federationResult('partner', {
          amr: ['pwd'],
          acr: 'urn:partner:loa:2',
        });
      },
    },
  };
  const extensions = new Map([[saml.manifest.id, saml], [oidc.manifest.id, oidc]]);
  const registry = {
    get(id, kind) {
      const entry = extensions.get(id);
      return entry?.manifest.kind === kind ? entry : null;
    },
  };
  const provider = {
    async interactionDetails() {
      return {
        uid: interaction.uid,
        prompt: { name: interaction.prompt },
        params: { client_id: 'console' },
      };
    },
    async interactionFinished(_req, res, result, completionOptions) {
      calls.finished.push({ result, options: completionOptions });
      res.status(204).end();
    },
  };
  const accountResolver = options.accountResolver ?? (async (input) => {
    calls.resolved.push(input);
    return { accountId, created: true };
  });
  const app = express();
  app.set('query parser', 'simple');
  app.use(createFederationRouter({
    realm,
    provider,
    registry,
    stateStore,
    accountResolver,
    audit: async (event) => calls.audit.push(event),
    publicUrl: 'https://login.example.test',
    csrfSecret,
    maxSamlPostBytes: options.maxSamlPostBytes ?? 2_048,
  }));
  app.use((_req, res) => res.status(404).json({ code: 'NOT_FOUND' }));
  app.use((error, _req, res, _next) => res.status(error.status ?? 500).json({
    code: error.code,
    message: error.safe ? error.message : 'internal error',
  }));
  return { app, calls, interaction, stateStore };
}

function initiationCsrf(extensionId, providerId, interactionUid = uid) {
  return createFederationInitiationCsrfToken({
    realm,
    interactionUid,
    extensionId,
    providerId,
  }, csrfSecret);
}

function callbackHandle(response) {
  const location = new URL(response.headers.location, 'https://login.example.test');
  assert.equal(location.origin, 'https://login.example.test');
  assert.deepEqual([...location.searchParams.keys()], ['handle']);
  return { location, handle: location.searchParams.get('handle') };
}

test('publishes SAML metadata only for the exact SAML extension and provider', async () => {
  const { app } = fixture();
  const metadata = await request(app)
    .get('/realms/master/federation/builtin.saml-federation/corp/metadata');
  assert.equal(metadata.status, 200);
  assert.match(metadata.headers['content-type'], /^application\/samlmetadata\+xml/);
  assert.match(metadata.text, /EntityDescriptor/);

  const wrongProtocol = await request(app)
    .get('/realms/master/federation/builtin.oidc-federation/partner/metadata');
  assert.equal(wrongProtocol.status, 404);
  const wrongProvider = await request(app)
    .get('/realms/master/federation/builtin.saml-federation/partner/metadata');
  assert.equal(wrongProvider.status, 404);
});

test('initiation requires a matching login interaction, provider-bound CSRF, and exact body', async () => {
  const { app, calls, interaction } = fixture();
  const path = '/realms/master/interaction/interaction-uid-one/federation/builtin.oidc-federation/partner';
  const csrf = initiationCsrf('builtin.oidc-federation', 'partner');
  const started = await request(app).post(path).type('form').send({ csrf });
  assert.equal(started.status, 303);
  assert.equal(started.headers.location, 'https://accounts.example.test/authorize?state=opaque');
  assert.deepEqual(calls.initiated[0], {
    realm,
    providerId: 'partner',
    interactionUid: uid,
    callbackUrl: 'https://login.example.test/realms/master/federation/builtin.oidc-federation/partner/callback',
  });

  const badCsrf = await request(app).post(path).type('form')
    .send({ csrf: initiationCsrf('builtin.saml-federation', 'corp') });
  assert.equal(badCsrf.status, 403);
  const extraField = await request(app).post(path).type('form').send({ csrf, returnTo: 'https://evil.test' });
  assert.equal(extraField.status, 400);

  interaction.prompt = 'consent';
  const wrongPrompt = await request(app).post(path).type('form').send({ csrf });
  assert.equal(wrongPrompt.status, 400);
  interaction.prompt = 'login';
  interaction.uid = 'different-interaction';
  const wrongUid = await request(app).post(path).type('form').send({ csrf });
  assert.equal(wrongUid.status, 400);
});

test('initiation rejects provider/extension mismatch and unsafe extension redirects', async () => {
  let context = fixture();
  const mismatch = await request(context.app)
    .post('/realms/master/interaction/interaction-uid-one/federation/builtin.saml-federation/partner')
    .type('form')
    .send({ csrf: initiationCsrf('builtin.saml-federation', 'partner') });
  assert.equal(mismatch.status, 404);

  context = fixture({ samlRedirect: 'javascript:alert(1)' });
  const unsafe = await request(context.app)
    .post('/realms/master/interaction/interaction-uid-one/federation/builtin.saml-federation/corp')
    .type('form')
    .send({ csrf: initiationCsrf('builtin.saml-federation', 'corp') });
  assert.equal(unsafe.status, 502);
  assert.equal(unsafe.body.code, 'AUTHME_FEDERATION_REDIRECT_INVALID');
  assert.equal(unsafe.headers.location, undefined);
});

test('SAML ACS resolves identity into an opaque one-use same-site completion', async () => {
  const { app, calls } = fixture();
  const callback = await request(app)
    .post('/realms/master/federation/builtin.saml-federation/corp/acs')
    .type('form')
    .send({ SAMLResponse: 'signed-response', RelayState: 'opaque-relay-state' });
  assert.equal(callback.status, 303);
  assert.equal(callback.headers['referrer-policy'], 'no-referrer');
  const { location, handle } = callbackHandle(callback);
  assert.equal(location.pathname, '/realms/master/interaction/interaction-uid-one/federation/complete');
  assert.ok(handle);
  assert.doesNotMatch(callback.headers.location, /alice|example\.test|123e4567/i);
  assert.equal(calls.resolved.length, 1);
  assert.equal(calls.resolved[0].extensionId, 'builtin.saml-federation');
  assert.equal(calls.resolved[0].providerId, 'corp');
  assert.deepEqual(calls.resolved[0].identity, {
    externalSubject: 'upstream-subject', issuer: 'https://idp.example.test',
  });

  const completed = await request(app).get(`${location.pathname}${location.search}`);
  assert.equal(completed.status, 204);
  assert.deepEqual(calls.finished, [{
    result: {
      login: {
        accountId,
        acr: 'urn:authme:loa:federated',
        amr: ['federated', 'saml'],
        remember: true,
      },
    },
    options: { mergeWithLastSubmission: false },
  }]);
  const replay = await request(app).get(`${location.pathname}${location.search}`);
  assert.equal(replay.status, 400);

  const serializedAudit = JSON.stringify(calls.audit);
  assert.doesNotMatch(serializedAudit, /alice@example\.test|upstream-subject|signed-response/);
  assert.match(serializedAudit, /identity\.federation\.resolved/);
  assert.match(serializedAudit, /identity\.federation\.login_succeeded/);
});

test('completion revalidates the login prompt before consuming its handle', async () => {
  const { app, interaction, calls } = fixture();
  const callback = await request(app)
    .post('/realms/master/federation/builtin.saml-federation/corp/acs')
    .type('form')
    .send({ SAMLResponse: 'signed-response', RelayState: 'opaque-relay-state' });
  const { location } = callbackHandle(callback);

  interaction.prompt = 'consent';
  const rejected = await request(app).get(`${location.pathname}${location.search}`);
  assert.equal(rejected.status, 400);
  assert.equal(calls.finished.length, 0);

  interaction.prompt = 'login';
  const retried = await request(app).get(`${location.pathname}${location.search}`);
  assert.equal(retried.status, 204);
  assert.equal(calls.finished.length, 1);
});

test('completion rejects cross-UID, cross-realm, and modified-handle requests', async () => {
  let context = fixture();
  let callback = await request(context.app)
    .post('/realms/master/federation/builtin.saml-federation/corp/acs')
    .type('form')
    .send({ SAMLResponse: 'signed-response', RelayState: 'opaque-relay-state' });
  let { location, handle } = callbackHandle(callback);
  context.interaction.uid = 'other-interaction';
  const crossUid = await request(context.app)
    .get(`/realms/master/interaction/other-interaction/federation/complete?handle=${handle}`);
  assert.equal(crossUid.status, 400);
  assert.equal(context.calls.finished.length, 0);

  context = fixture();
  callback = await request(context.app)
    .post('/realms/master/federation/builtin.saml-federation/corp/acs')
    .type('form')
    .send({ SAMLResponse: 'signed-response', RelayState: 'opaque-relay-state' });
  ({ location, handle } = callbackHandle(callback));
  const crossRealm = await request(context.app)
    .get(`/realms/other/interaction/${uid}/federation/complete?handle=${handle}`);
  assert.equal(crossRealm.status, 404);
  const modified = await request(context.app)
    .get(`${location.pathname}?handle=${handle.slice(0, -1)}x&returnTo=https%3A%2F%2Fevil.test`);
  assert.equal(modified.status, 400);
  assert.equal(context.calls.finished.length, 0);
});

test('SAML ACS uses an exact bounded form body and rejects protocol confusion', async () => {
  const { app } = fixture({ maxSamlPostBytes: 1_024 });
  const path = '/realms/master/federation/builtin.saml-federation/corp/acs';
  const json = await request(app).post(path).send({ SAMLResponse: 'x', RelayState: 'y' });
  assert.equal(json.status, 400);
  const extra = await request(app).post(path).type('form')
    .send({ SAMLResponse: 'x', RelayState: 'y', returnTo: 'https://evil.test' });
  assert.equal(extra.status, 400);
  const duplicate = await request(app).post(path)
    .type('form').send('SAMLResponse=x&RelayState=one&RelayState=two');
  assert.equal(duplicate.status, 400);
  const oversized = await request(app).post(path).type('form')
    .send({ SAMLResponse: 'x'.repeat(2_000), RelayState: 'y' });
  assert.equal(oversized.status, 413);

  const oidcAtAcs = await request(app)
    .post('/realms/master/federation/builtin.oidc-federation/partner/acs')
    .type('form').send({ SAMLResponse: 'x', RelayState: 'y' });
  assert.equal(oidcAtAcs.status, 404);
  const samlAtOidc = await request(app)
    .get(`/realms/master/federation/builtin.saml-federation/corp/callback?state=${oidcState}&code=code`);
  assert.equal(samlAtOidc.status, 404);
});

test('OIDC callback is exact, fixed-origin, and completes with federated authentication context', async () => {
  const { app, calls } = fixture();
  const callbackPath = '/realms/master/federation/builtin.oidc-federation/partner/callback';
  const callback = await request(app).get(`${callbackPath}?state=${oidcState}&code=authorization-code`);
  assert.equal(callback.status, 303);
  assert.equal(calls.consumed.length, 1);
  assert.equal(calls.consumed[0].callbackUrl,
    'https://login.example.test/realms/master/federation/builtin.oidc-federation/partner/callback');
  assert.deepEqual(calls.consumed[0].params, { state: oidcState, code: 'authorization-code' });
  const { location } = callbackHandle(callback);
  const completed = await request(app).get(`${location.pathname}${location.search}`);
  assert.equal(completed.status, 204);
  assert.deepEqual(calls.finished[0].result.login, {
    accountId,
    acr: 'urn:partner:loa:2',
    amr: ['federated', 'pwd'],
    remember: true,
  });

  const duplicate = await request(app)
    .get(`${callbackPath}?state=${oidcState}&state=${oidcState}&code=code`);
  assert.equal(duplicate.status, 400);
  const openRedirect = await request(app)
    .get(`${callbackPath}?state=${oidcState}&code=code&returnTo=https%3A%2F%2Fevil.test`);
  assert.equal(openRedirect.status, 400);
});

test('callback rejects an extension result mismatch and an invalid resolver result', async () => {
  let context = fixture({
    oidcResult: federationResult('different-provider'),
  });
  let response = await request(context.app)
    .get(`/realms/master/federation/builtin.oidc-federation/partner/callback?state=${oidcState}&code=code`);
  assert.equal(response.status, 400);
  assert.equal(context.calls.resolved.length, 0);
  assert.equal(response.headers.location, undefined);

  context = fixture({ accountResolver: async () => ({ accountId: 'not-a-uuid' }) });
  response = await request(context.app)
    .get(`/realms/master/federation/builtin.oidc-federation/partner/callback?state=${oidcState}&code=code`);
  assert.equal(response.status, 500);
  assert.equal(response.headers.location, undefined);
  assert.doesNotMatch(JSON.stringify(response.body), /alice|example\.test|upstream-subject/);
});
