import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34994';
const host = new URL(base).host;
const realm = 'master';
const issuer = `${base}/realms/${realm}`;
const authorizationPath = `/realms/${realm}/protocol/openid-connect/auth`;
const tokenPath = `/realms/${realm}/protocol/openid-connect/token`;
const ordersResource = 'https://api.example.test/orders';
const billingResource = 'https://api.example.test/billing';
const clients = {
  single: {
    id: 'single-resource-client',
    redirectUri: 'http://127.0.0.1:49158/callback',
  },
  multiDenied: {
    id: 'multi-resource-denied-client',
    redirectUri: 'http://127.0.0.1:49159/callback',
  },
  multiAllowed: {
    id: 'multi-resource-allowed-client',
    redirectUri: 'http://127.0.0.1:49160/callback',
  },
};
let runtime;
let keySet;

function clientMetadata(client) {
  return {
    client_id: client.id,
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    redirect_uris: [client.redirectUri],
    response_types: ['code'],
    grant_types: ['authorization_code'],
  };
}

before(async () => {
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34994',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: Object.values(clients).map(clientMetadata),
    }),
    AUTHME_RESOURCE_SERVERS_JSON: JSON.stringify({
      master: [{
        audience: ordersResource,
        scopes: ['orders.read', 'shared', 'roles'],
        authorized_client_ids: Object.values(clients).map(({ id }) => id),
        multi_resource_client_ids: [clients.multiAllowed.id],
      }, {
        audience: billingResource,
        scopes: ['billing.read', 'shared'],
        authorized_client_ids: [clients.multiDenied.id, clients.multiAllowed.id],
        multi_resource_client_ids: [clients.multiAllowed.id],
      }],
    }),
  }));
  const jwks = await request(runtime.app)
    .get(`/realms/${realm}/protocol/openid-connect/certs`)
    .set('host', host)
    .expect(200);
  keySet = createLocalJWKSet(jwks.body);
});

after(async () => {
  await runtime?.close();
});

function csrf(html) {
  const match = html.match(/name="csrf" value="([^"]+)"/u);
  assert(match, 'Interaction form did not include a CSRF token');
  return match[1];
}

async function authorize(client, resources, scope) {
  const agent = request.agent(runtime.app);
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('base64url');
  let response = await agent
    .get(authorizationPath)
    .set('host', host)
    .query({
      client_id: client.id,
      redirect_uri: client.redirectUri,
      response_type: 'code',
      scope,
      resource: resources,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
      state,
    });

  for (let step = 0; step < 8; step += 1) {
    assert([302, 303].includes(response.status), `Unexpected authorization status ${response.status}`);
    const location = response.headers.location;
    assert(location, 'Authorization response did not include a Location header');
    const target = new URL(location, base);
    const callback = new URL(client.redirectUri);
    if (target.origin === callback.origin && target.pathname === callback.pathname) {
      return { callback: target, verifier };
    }

    assert.equal(target.origin, base, 'Authorization redirected to an unexpected origin');
    response = await agent
      .get(`${target.pathname}${target.search}`)
      .set('host', host);
    if (response.status !== 200) continue;

    if (response.text.includes('/login"')) {
      response = await agent
        .post(`${target.pathname}/login`)
        .set('host', host)
        .type('form')
        .send({
          csrf: csrf(response.text),
          login: 'admin',
          password: 'AuthMe-Change-Me-Now-2026!',
          otp: '',
        });
    } else if (response.text.includes('/confirm"')) {
      response = await agent
        .post(`${target.pathname}/confirm`)
        .set('host', host)
        .type('form')
        .send({ csrf: csrf(response.text) });
    } else {
      assert.fail('Authorization returned an unexpected interaction page');
    }
  }

  assert.fail('Authorization did not return to the client');
}

async function exchangeCode(client, authorization, resource) {
  const code = authorization.callback.searchParams.get('code');
  assert(code, 'Authorization response did not include a code');
  const body = {
    grant_type: 'authorization_code',
    client_id: client.id,
    code,
    code_verifier: authorization.verifier,
    redirect_uri: client.redirectUri,
  };
  if (resource) body.resource = resource;
  return request(runtime.app)
    .post(tokenPath)
    .set('host', host)
    .type('form')
    .send(body)
    .expect(200);
}

function scopes(value) {
  return new Set(String(value ?? '').split(' ').filter(Boolean));
}

async function verifyResourceToken(response, resource, expectedScopes) {
  const { payload, protectedHeader } = await jwtVerify(response.body.access_token, keySet, {
    algorithms: ['RS256'],
    issuer,
    audience: resource,
  });
  assert.equal(protectedHeader.typ, 'at+jwt');
  assert.equal(payload.aud, resource);
  assert.deepEqual(scopes(response.body.scope), new Set(expectedScopes));
  assert.deepEqual(scopes(payload.scope), new Set(expectedScopes));
  return payload;
}

test('an authorized single resource produces an audience-bound, resource-scoped token', async () => {
  const authorization = await authorize(
    clients.single,
    ordersResource,
    'openid orders.read shared roles',
  );
  assert.equal(authorization.callback.searchParams.get('error'), null);

  const token = await exchangeCode(clients.single, authorization);
  await verifyResourceToken(token, ordersResource, ['orders.read', 'shared', 'roles']);
});

test('a resource outside the client allowlist is rejected with invalid_target', async () => {
  const authorization = await authorize(
    clients.single,
    billingResource,
    'openid billing.read',
  );

  assert.equal(authorization.callback.searchParams.get('error'), 'invalid_target');
  assert.equal(authorization.callback.searchParams.get('code'), null);
});

test('multi-resource requests are denied by default and succeed only for an opted-in client', async () => {
  const denied = await authorize(
    clients.multiDenied,
    [ordersResource, billingResource],
    'openid orders.read billing.read shared',
  );
  assert.equal(denied.callback.searchParams.get('error'), 'invalid_target');
  assert.equal(denied.callback.searchParams.get('code'), null);

  const allowed = await authorize(
    clients.multiAllowed,
    [ordersResource, billingResource],
    'openid orders.read billing.read shared',
  );
  assert.equal(allowed.callback.searchParams.get('error'), null);
  const token = await exchangeCode(clients.multiAllowed, allowed, ordersResource);
  await verifyResourceToken(token, ordersResource, ['orders.read', 'shared']);
});

test('a multi-resource grant filters every issued token to the selected resource scopes', async () => {
  const requestedScope = 'openid orders.read billing.read shared roles';
  const ordersAuthorization = await authorize(
    clients.multiAllowed,
    [ordersResource, billingResource],
    requestedScope,
  );
  const ordersToken = await exchangeCode(clients.multiAllowed, ordersAuthorization, ordersResource);
  const ordersPayload = await verifyResourceToken(
    ordersToken,
    ordersResource,
    ['orders.read', 'shared', 'roles'],
  );
  assert.equal(scopes(ordersPayload.scope).has('billing.read'), false);

  const billingAuthorization = await authorize(
    clients.multiAllowed,
    [ordersResource, billingResource],
    requestedScope,
  );
  const billingToken = await exchangeCode(clients.multiAllowed, billingAuthorization, billingResource);
  const billingPayload = await verifyResourceToken(
    billingToken,
    billingResource,
    ['billing.read', 'shared'],
  );
  assert.equal(scopes(billingPayload.scope).has('orders.read'), false);
  assert.equal(scopes(billingPayload.scope).has('roles'), false);
});
