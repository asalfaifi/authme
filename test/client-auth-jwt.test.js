import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34992';
const issuer = `${base}/realms/master`;
const tokenPath = '/realms/master/protocol/openid-connect/token';
const tokenEndpoint = `${issuer}/protocol/openid-connect/token`;
const introspectionPath = '/realms/master/protocol/openid-connect/token/introspect';
const revocationPath = '/realms/master/protocol/openid-connect/revoke';
const registrationPath = '/realms/master/clients-registrations/openid-connect';
const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const privateKeyClientId = 'private-key-jwt-client';
const remoteKeyClientId = 'private-key-jwt-uri-client';
const secretJwtClientId = 'client-secret-jwt-client';
const secretJwtClientSecret = 'client-secret-jwt-shared-secret-value-000000000001';
const basicClientId = 'client-secret-basic-client';
const basicClientSecret = 'client-secret-basic-shared-secret-value-000000001';
const publicClientId = 'public-none-client';
const privateKeyId = 'private-key-jwt-test-key';

let privateKey;
let runtime;

function claims(clientId, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    iat: now,
    exp: now + 120,
    jti: randomUUID(),
    ...overrides,
  };
}

async function privateKeyAssertion(overrides = {}) {
  return new SignJWT(claims(privateKeyClientId, overrides))
    .setProtectedHeader({ alg: 'RS256', kid: privateKeyId })
    .sign(privateKey);
}

async function clientSecretAssertion(overrides = {}) {
  return new SignJWT(claims(secretJwtClientId, overrides))
    .setProtectedHeader({ alg: 'HS256' })
    .sign(Buffer.from(secretJwtClientSecret));
}

function postAssertion(path, assertion, parameters) {
  return request(runtime.app)
    .post(path)
    .set('host', '127.0.0.1:34992')
    .type('form')
    .send({
      ...parameters,
      client_assertion_type: assertionType,
      client_assertion: assertion,
    });
}

function postRegistration(token, metadata) {
  return request(runtime.app)
    .post(registrationPath)
    .set('host', '127.0.0.1:34992')
    .set('authorization', `Bearer ${token}`)
    .send(metadata);
}

async function registrationToken() {
  const provider = runtime.providers.get('master');
  return new provider.InitialAccessToken({
    expiresIn: 60,
    policies: ['authme-secure-client'],
  }).save();
}

function tamper(assertion) {
  const parts = assertion.split('.');
  parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`;
  return parts.join('.');
}

function unsecuredAssertion(clientId) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode(claims(clientId))}.`;
}

before(async () => {
  const keyPair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  privateKey = keyPair.privateKey;
  const publicJwk = {
    ...await exportJWK(keyPair.publicKey),
    kid: privateKeyId,
    alg: 'RS256',
    use: 'sig',
    key_ops: ['verify'],
  };
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34992',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_ENABLE_DYNAMIC_REGISTRATION: 'true',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [{
        client_id: privateKeyClientId,
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'RS256',
        jwks: { keys: [publicJwk] },
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: remoteKeyClientId,
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'PS256',
        jwks_uri: 'https://keys.example.test/client.jwks',
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: secretJwtClientId,
        client_secret: secretJwtClientSecret,
        token_endpoint_auth_method: 'client_secret_jwt',
        token_endpoint_auth_signing_alg: 'HS256',
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: basicClientId,
        client_secret: basicClientSecret,
        token_endpoint_auth_method: 'client_secret_basic',
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: publicClientId,
        application_type: 'native',
        token_endpoint_auth_method: 'none',
        redirect_uris: ['http://127.0.0.1:49153/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code'],
      }],
    }),
  }));
});

after(async () => {
  await runtime?.close();
});

test('private_key_jwt authenticates endpoints and rejects cross-endpoint assertion replay', async () => {
  const assertion = await privateKeyAssertion();
  const tokenResponse = await postAssertion(tokenPath, assertion, {
    grant_type: 'client_credentials',
  }).expect(200);

  assert.equal(tokenResponse.body.token_type, 'Bearer');
  assert.equal(typeof tokenResponse.body.access_token, 'string');

  const replayResponse = await postAssertion(introspectionPath, assertion, {
    token: tokenResponse.body.access_token,
  }).expect(401);
  assert.equal(replayResponse.body.error, 'invalid_client');

  const introspectionResponse = await postAssertion(
    introspectionPath,
    await privateKeyAssertion({ aud: issuer }),
    { token: tokenResponse.body.access_token },
  ).expect(200);
  assert.equal(introspectionResponse.body.active, true);

  await postAssertion(
    revocationPath,
    await privateKeyAssertion(),
    { token: tokenResponse.body.access_token },
  ).expect(200);

  const revokedResponse = await postAssertion(
    introspectionPath,
    await privateKeyAssertion({ aud: issuer }),
    { token: tokenResponse.body.access_token },
  ).expect(200);
  assert.equal(revokedResponse.body.active, false);

  const remoteKeyClient = await runtime.providers.get('master').Client.find(remoteKeyClientId);
  assert.equal(remoteKeyClient.jwksUri, 'https://keys.example.test/client.jwks');
});

test('private_key_jwt rejects a tampered assertion', async () => {
  const response = await postAssertion(tokenPath, tamper(await privateKeyAssertion()), {
    grant_type: 'client_credentials',
  }).expect(401);
  assert.equal(response.body.error, 'invalid_client');
});

test('private_key_jwt rejects an expired assertion', async () => {
  const now = Math.floor(Date.now() / 1000);
  const response = await postAssertion(tokenPath, await privateKeyAssertion({
    iat: now - 600,
    exp: now - 300,
  }), {
    grant_type: 'client_credentials',
  }).expect(401);
  assert.equal(response.body.error, 'invalid_client');
});

test('private_key_jwt rejects an assertion whose lifetime exceeds 300 seconds', async () => {
  const now = Math.floor(Date.now() / 1000);
  const response = await postAssertion(tokenPath, await privateKeyAssertion({
    iat: now,
    exp: now + 301,
  }), {
    grant_type: 'client_credentials',
  }).expect(401);
  assert.equal(response.body.error, 'invalid_client');
});

test('private_key_jwt rejects an assertion with a non-exact audience', async () => {
  const response = await postAssertion(tokenPath, await privateKeyAssertion({
    aud: `${issuer}/protocol/openid-connect/token/extra`,
  }), {
    grant_type: 'client_credentials',
  }).expect(401);
  assert.equal(response.body.error, 'invalid_client');
});

test('client_secret_jwt authenticates with HS256 and the registered shared secret', async () => {
  const response = await postAssertion(tokenPath, await clientSecretAssertion(), {
    grant_type: 'client_credentials',
  }).expect(200);
  assert.equal(response.body.token_type, 'Bearer');
  assert.equal(typeof response.body.access_token, 'string');
});

test('JWT client authentication rejects alg none', async () => {
  const response = await postAssertion(tokenPath, unsecuredAssertion(privateKeyClientId), {
    grant_type: 'client_credentials',
  }).expect(401);
  assert.equal(response.body.error, 'invalid_client');
});

test('client registration rejects unsafe jwks_uri values as invalid client metadata', async () => {
  const token = await registrationToken();
  for (const [jwksUri, expected] of [
    ['http://keys.example.test/client.jwks', /must use HTTPS/],
    ['https://127.0.0.1/client.jwks', /loopback/],
    ['https://10.0.0.1/client.jwks', /private/],
  ]) {
    const response = await postRegistration(token, {
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'RS256',
      grant_types: ['client_credentials'],
      response_types: [],
      redirect_uris: [],
      jwks_uri: jwksUri,
    }).expect(400);
    assert.equal(response.body.error, 'invalid_client_metadata');
    assert.match(response.body.error_description, expected);
  }
});

test('client registration rejects every private inline JWK member as invalid client metadata', async () => {
  const token = await registrationToken();
  for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv']) {
    const response = await postRegistration(token, {
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'RS256',
      grant_types: ['client_credentials'],
      response_types: [],
      redirect_uris: [],
      jwks: { keys: [{ kty: 'RSA', [member]: 'private-value' }] },
    }).expect(400);
    assert.equal(response.body.error, 'invalid_client_metadata');
    assert.match(response.body.error_description, new RegExp(`private key material \\(${member}\\)`));
  }
});

test('client_secret_basic and none client authentication remain unchanged', async () => {
  const basicResponse = await request(runtime.app)
    .post(tokenPath)
    .set('host', '127.0.0.1:34992')
    .auth(basicClientId, basicClientSecret)
    .type('form')
    .send({ grant_type: 'client_credentials' })
    .expect(200);
  assert.equal(basicResponse.body.token_type, 'Bearer');

  const publicResponse = await request(runtime.app)
    .post(tokenPath)
    .set('host', '127.0.0.1:34992')
    .type('form')
    .send({
      grant_type: 'authorization_code',
      client_id: publicClientId,
      code: 'not-a-real-authorization-code',
      redirect_uri: 'http://127.0.0.1:49153/callback',
      code_verifier: 'v'.repeat(43),
    })
    .expect(400);
  assert.equal(publicResponse.body.error, 'invalid_grant');
});
