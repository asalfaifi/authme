import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34999';
const clientId = 'ciba-private-key-client';
const publicClientId = 'ciba-public-client';
const keyId = 'ciba-test-key';
const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const cibaGrant = 'urn:openid:params:grant-type:ciba';

let privateKey;
let runtime;
let triggeredRequest;

function issuer(realm) {
  return `${base}/realms/${realm}`;
}

function endpoint(realm, path) {
  return `${issuer(realm)}/protocol/openid-connect/${path}`;
}

async function clientAssertion(realm, audience) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: clientId,
    sub: clientId,
    aud: audience,
    iat: now,
    exp: now + 120,
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: 'RS256', kid: keyId })
    .sign(privateKey);
}

async function authenticatedPost(realm, path, body, expectedStatus, audience = endpoint(realm, path)) {
  return request(runtime.app)
    .post(`/realms/${realm}/protocol/openid-connect/${path}`)
    .set('host', new URL(base).host)
    .type('form')
    .send({
      ...body,
      client_assertion_type: assertionType,
      client_assertion: await clientAssertion(realm, audience),
    })
    .expect(expectedStatus);
}

async function initiate(realm = 'master', loginHint = 'admin', expectedStatus = 200) {
  return authenticatedPost(realm, 'ext/ciba/auth', {
    scope: 'openid profile email',
    login_hint: loginHint,
  }, expectedStatus);
}

async function poll(realm, authReqId, expectedStatus) {
  return authenticatedPost(realm, 'token', {
    grant_type: cibaGrant,
    auth_req_id: authReqId,
  }, expectedStatus);
}

before(async () => {
  const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  privateKey = pair.privateKey;
  const publicJwk = {
    ...await exportJWK(pair.publicKey),
    kid: keyId,
    alg: 'RS256',
    use: 'sig',
    key_ops: ['verify'],
  };
  const cibaClient = {
    client_id: clientId,
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'RS256',
    jwks: { keys: [publicJwk] },
    redirect_uris: [],
    response_types: [],
    grant_types: [cibaGrant],
    backchannel_token_delivery_mode: 'poll',
    scope: 'openid profile email',
  };
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34999',
    AUTHME_REALMS: 'master,staff',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [cibaClient, {
        client_id: publicClientId,
        application_type: 'native',
        token_endpoint_auth_method: 'none',
        redirect_uris: ['http://127.0.0.1:49160/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code'],
      }],
      staff: [cibaClient],
    }),
  }));
  runtime.providers.get('master').authmeCiba.setAuthenticationDeviceHandler((pending) => {
    triggeredRequest = pending;
  });
});

after(async () => {
  await runtime?.close();
});

test('discovery advertises the poll-only confidential CIBA profile', async () => {
  const response = await request(runtime.app)
    .get('/realms/master/.well-known/openid-configuration')
    .set('host', new URL(base).host)
    .expect(200);
  assert.equal(response.body.backchannel_authentication_endpoint, endpoint('master', 'ext/ciba/auth'));
  assert.deepEqual(response.body.backchannel_token_delivery_modes_supported, ['poll']);
  assert.equal(response.body.backchannel_user_code_parameter_supported, false);
  assert.ok(response.body.grant_types_supported.includes(cibaGrant));
});

test('CIBA returns an auth_req_id, remains pending, and issues tokens only after dev approval', async () => {
  const initiated = await initiate();
  assert.match(initiated.body.auth_req_id, /^[A-Za-z0-9._-]+$/);
  assert.equal(initiated.body.expires_in, 600);
  assert.equal(initiated.body.interval, 1);
  assert.equal(Number.isSafeInteger(triggeredRequest.expiresAt), true);
  assert.deepEqual(triggeredRequest, {
    realm: 'master',
    authReqId: initiated.body.auth_req_id,
    accountId: (await runtime.store.findUserByLogin('master', 'admin')).id,
    clientId,
    bindingMessage: undefined,
    expiresAt: triggeredRequest.expiresAt,
    scopes: ['openid', 'profile', 'email'],
  });

  const pending = await poll('master', initiated.body.auth_req_id, 400);
  assert.equal(pending.body.error, 'authorization_pending');

  await runtime.providers.get('master').authmeCiba.approveForDevelopment(initiated.body.auth_req_id);
  await delay(1_050);

  const tokens = await poll('master', initiated.body.auth_req_id, 200);
  assert.equal(tokens.body.token_type, 'Bearer');
  assert.equal(typeof tokens.body.access_token, 'string');
  assert.equal(typeof tokens.body.id_token, 'string');

  const replay = await poll('master', initiated.body.auth_req_id, 400);
  assert.equal(replay.body.error, 'invalid_grant');
});

test('CIBA polling faster than the advertised interval returns slow_down', async () => {
  const initiated = await initiate();
  const first = await poll('master', initiated.body.auth_req_id, 400);
  assert.equal(first.body.error, 'authorization_pending');

  const tooFast = await poll('master', initiated.body.auth_req_id, 400);
  assert.equal(tooFast.body.error, 'slow_down');
  assert.equal(tooFast.headers['retry-after'], '6');
});

test('unknown and unusable login hints fail closed with indistinguishable errors', async () => {
  await runtime.store.createUser({
    realm: 'master',
    username: 'disabled-ciba-user',
    email: 'disabled-ciba-user@example.test',
    name: 'Disabled CIBA User',
    enabled: false,
    passwordHash: 'disabled',
  });
  const unknown = await initiate('master', 'not-a-user@example.test', 400);
  const disabled = await initiate('master', 'disabled-ciba-user', 400);

  assert.deepEqual(unknown.body, disabled.body);
  assert.equal(unknown.body.error, 'unknown_user_id');
  assert.doesNotMatch(JSON.stringify(unknown.body), /not-a-user|disabled-ciba-user/);
});

test('public clients cannot initiate CIBA', async () => {
  const response = await request(runtime.app)
    .post('/realms/master/protocol/openid-connect/ext/ciba/auth')
    .set('host', new URL(base).host)
    .type('form')
    .send({
      client_id: publicClientId,
      scope: 'openid',
      login_hint: 'admin',
    })
    .expect(400);
  assert.equal(response.body.error, 'invalid_request');
  assert.match(response.body.error_description, /not allowed for this client/);
});

test('the CIBA endpoint audience is not accepted for token-endpoint client assertions', async () => {
  const response = await authenticatedPost('master', 'token', {
    grant_type: cibaGrant,
    auth_req_id: 'x'.repeat(43),
  }, 401, endpoint('master', 'ext/ciba/auth'));
  assert.equal(response.body.error, 'invalid_client');
});

test('CIBA requests and approvals cannot cross realm boundaries', async () => {
  const initiated = await initiate('master');

  const crossRealmPoll = await poll('staff', initiated.body.auth_req_id, 400);
  assert.equal(crossRealmPoll.body.error, 'invalid_grant');
  await assert.rejects(
    runtime.providers.get('staff').authmeCiba.approveForDevelopment(initiated.body.auth_req_id),
    /invalid_grant/,
  );

  assert.ok(await runtime.providers.get('master').BackchannelAuthenticationRequest.find(initiated.body.auth_req_id));
  assert.equal(
    await runtime.providers.get('staff').BackchannelAuthenticationRequest.find(initiated.body.auth_req_id),
    undefined,
  );
});

test('expired auth_req_id values return expired_token', async () => {
  const provider = runtime.providers.get('master');
  const user = await runtime.store.findUserByLogin('master', 'admin');
  const now = Math.floor(Date.now() / 1000);
  await provider.BackchannelAuthenticationRequest.adapter.upsert('expired-ciba-request', {
    kind: 'BackchannelAuthenticationRequest',
    jti: 'expired-ciba-request',
    iat: now - 2,
    exp: now - 1,
    accountId: user.id,
    clientId,
    scope: 'openid',
  }, 0);

  const response = await poll('master', 'expired-ciba-request', 400);
  assert.equal(response.body.error, 'expired_token');
});

test('signed CIBA Request Object jti values are one-use', async () => {
  const now = Math.floor(Date.now() / 1000);
  const requestObject = await new SignJWT({
    iss: clientId,
    aud: issuer('master'),
    iat: now,
    nbf: now,
    exp: now + 120,
    jti: randomUUID(),
    scope: 'openid profile',
    login_hint: 'admin',
  })
    .setProtectedHeader({ alg: 'RS256', kid: keyId })
    .sign(privateKey);

  await authenticatedPost('master', 'ext/ciba/auth', { request: requestObject }, 200);
  const replay = await authenticatedPost('master', 'ext/ciba/auth', { request: requestObject }, 400);
  assert.equal(replay.body.error, 'invalid_request');
});
