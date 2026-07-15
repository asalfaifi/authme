import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34993';
const realm = 'master';
const issuer = `${base}/realms/${realm}`;
const resourceAudience = 'https://api.example.test/orders';
const secrets = {
  introspectionJwt: 'jwt-introspection-secret-value-0001',
  introspectionJson: 'json-introspection-secret-value-001',
  introspectionUnauthorized: 'unauthorized-secret-value-00000001',
  tokenOwner: 'token-owner-secret-value-000000001',
  userinfoJwt: 'jwt-userinfo-secret-value-000000001',
  userinfoJson: 'json-userinfo-secret-value-00000001',
};
const clientIds = {
  introspectionJwt: 'jwt-introspection-client',
  introspectionJson: 'json-introspection-client',
  introspectionUnauthorized: 'unauthorized-introspection-client',
  tokenOwner: 'resource-token-owner',
  userinfoJwt: 'jwt-userinfo-client',
  userinfoJson: 'json-userinfo-client',
};

let introspectableToken;
let jwks;
let keySet;
let runtime;
let user;
let userinfoJwtToken;
let userinfoJsonToken;

function serviceClient(clientId, clientSecret, metadata = {}) {
  return {
    client_id: clientId,
    client_secret: clientSecret,
    token_endpoint_auth_method: 'client_secret_basic',
    redirect_uris: [],
    response_types: [],
    grant_types: ['client_credentials'],
    ...metadata,
  };
}

function authenticatedPost(clientId, clientSecret) {
  return request(runtime.app)
    .post(`/realms/${realm}/protocol/openid-connect/token/introspect`)
    .set('host', new URL(base).host)
    .auth(clientId, clientSecret);
}

async function issueUserinfoToken(provider, clientId) {
  const client = await provider.Client.find(clientId);
  const grant = new provider.Grant({ accountId: user.id, clientId });
  grant.addOIDCScope('openid profile');
  const grantId = await grant.save();
  return new provider.AccessToken({
    accountId: user.id,
    client,
    grantId,
    scope: 'openid profile',
  }).save();
}

before(async () => {
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34993',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [
        serviceClient(clientIds.userinfoJwt, secrets.userinfoJwt, {
          userinfo_signed_response_alg: 'RS256',
        }),
        serviceClient(clientIds.userinfoJson, secrets.userinfoJson),
        serviceClient(clientIds.introspectionJwt, secrets.introspectionJwt, {
          introspection_signed_response_alg: 'RS256',
        }),
        serviceClient(clientIds.introspectionJson, secrets.introspectionJson),
        serviceClient(clientIds.introspectionUnauthorized, secrets.introspectionUnauthorized, {
          introspection_signed_response_alg: 'RS256',
        }),
        serviceClient(clientIds.tokenOwner, secrets.tokenOwner),
      ],
    }),
    AUTHME_RESOURCE_SERVERS_JSON: JSON.stringify({
      master: [{
        audience: resourceAudience,
        scopes: ['orders.read'],
        authorized_client_ids: [clientIds.tokenOwner],
        introspection_client_ids: [clientIds.introspectionJwt, clientIds.introspectionJson],
        access_token_format: 'opaque',
      }],
    }),
  }));

  const provider = runtime.providers.get(realm);
  user = await runtime.store.findUserByLogin(realm, 'admin');
  userinfoJwtToken = await issueUserinfoToken(provider, clientIds.userinfoJwt);
  userinfoJsonToken = await issueUserinfoToken(provider, clientIds.userinfoJson);
  const tokenOwner = await provider.Client.find(clientIds.tokenOwner);
  introspectableToken = await new provider.AccessToken({
    aud: resourceAudience,
    client: tokenOwner,
    scope: 'orders.read',
  }).save();

  const response = await request(runtime.app)
    .get(`/realms/${realm}/protocol/openid-connect/certs`)
    .set('host', new URL(base).host)
    .expect(200);
  jwks = response.body;
  assert(jwks.keys.length > 0);
  assert(jwks.keys.every((key) => key.d === undefined), 'Published realm JWKS exposed private key material');
  keySet = createLocalJWKSet(jwks);
});

after(async () => {
  await runtime?.close();
});

test('userinfo_signed_response_alg returns realm-signed JWT UserInfo with sub', async () => {
  const discovery = await request(runtime.app)
    .get(`/realms/${realm}/.well-known/openid-configuration`)
    .set('host', new URL(base).host)
    .expect(200);
  assert.deepEqual(discovery.body.userinfo_signing_alg_values_supported, ['RS256']);

  const response = await request(runtime.app)
    .get(`/realms/${realm}/protocol/openid-connect/userinfo`)
    .set('host', new URL(base).host)
    .set('authorization', `Bearer ${userinfoJwtToken}`)
    .expect(200)
    .expect('content-type', /application\/jwt/u);
  const { payload, protectedHeader } = await jwtVerify(response.text, keySet, {
    algorithms: ['RS256'],
    audience: clientIds.userinfoJwt,
    issuer,
  });

  assert.equal(protectedHeader.alg, 'RS256');
  assert.notEqual(protectedHeader.alg, 'none');
  assert(jwks.keys.some((key) => key.kid === protectedHeader.kid));
  assert.equal(payload.sub, user.id);
});

test('introspection_signed_response_alg returns a signed token-introspection JWT', async () => {
  const discovery = await request(runtime.app)
    .get(`/realms/${realm}/.well-known/openid-configuration`)
    .set('host', new URL(base).host)
    .expect(200);
  assert.deepEqual(discovery.body.introspection_signing_alg_values_supported, ['RS256']);

  const response = await authenticatedPost(clientIds.introspectionJwt, secrets.introspectionJwt)
    .set('accept', 'application/token-introspection+jwt')
    .type('form')
    .send({ token: introspectableToken })
    .expect(200)
    .expect('content-type', /application\/token-introspection\+jwt/u);
  const { payload, protectedHeader } = await jwtVerify(response.text, keySet, {
    algorithms: ['RS256'],
    audience: clientIds.introspectionJwt,
    issuer,
  });

  assert.equal(protectedHeader.alg, 'RS256');
  assert.equal(protectedHeader.typ, 'token-introspection+jwt');
  assert.notEqual(protectedHeader.alg, 'none');
  assert(jwks.keys.some((key) => key.kid === protectedHeader.kid));
  assert.equal(payload.token_introspection.active, true);
  assert.equal(payload.token_introspection.client_id, clientIds.tokenOwner);
  assert.equal(payload.token_introspection.aud, resourceAudience);
  assert.equal(payload.token_introspection.scope, 'orders.read');
});

test('JWT response client metadata rejects alg none', () => {
  const provider = runtime.providers.get(realm);
  for (const field of ['userinfo_signed_response_alg', 'introspection_signed_response_alg']) {
    assert.throws(
      () => new provider.Client(serviceClient(`unsigned-${field}`, secrets.tokenOwner, { [field]: 'none' })),
      (error) => error.error === 'invalid_client_metadata'
        && new RegExp(field, 'u').test(error.error_description),
    );
  }
});

test('clients without JWT response opt-in continue to receive plain JSON', async () => {
  const userinfo = await request(runtime.app)
    .get(`/realms/${realm}/protocol/openid-connect/userinfo`)
    .set('host', new URL(base).host)
    .set('authorization', `Bearer ${userinfoJsonToken}`)
    .expect(200)
    .expect('content-type', /application\/json/u);
  assert.equal(userinfo.body.sub, user.id);

  const introspection = await authenticatedPost(clientIds.introspectionJson, secrets.introspectionJson)
    .set('accept', 'application/token-introspection+jwt')
    .type('form')
    .send({ token: introspectableToken })
    .expect(200)
    .expect('content-type', /application\/json/u);
  assert.doesNotMatch(introspection.text, /^[^.]+\.[^.]+\.[^.]+$/u);
  assert.equal(introspection.body.active, true);
  assert.equal(introspection.body.client_id, clientIds.tokenOwner);
});

test('JWT introspection remains subject to the resource-client authorization policy', async () => {
  const response = await authenticatedPost(
    clientIds.introspectionUnauthorized,
    secrets.introspectionUnauthorized,
  )
    .set('accept', 'application/token-introspection+jwt')
    .type('form')
    .send({ token: introspectableToken })
    .expect(200)
    .expect('content-type', /application\/token-introspection\+jwt/u);
  const { payload, protectedHeader } = await jwtVerify(response.text, keySet, {
    algorithms: ['RS256'],
    audience: clientIds.introspectionUnauthorized,
    issuer,
  });

  assert.equal(protectedHeader.typ, 'token-introspection+jwt');
  assert.deepEqual(payload.token_introspection, { active: false });
});
