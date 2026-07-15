import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { validateClientSecurity } from '../src/provider.js';

const base = 'http://127.0.0.1:34993';
const issuer = `${base}/realms/master`;
const realm = 'master';
const jarClientId = 'jar-client';
const jarRedirectUri = 'http://127.0.0.1:49155/callback';
const plainClientId = 'plain-client';
const plainRedirectUri = 'http://127.0.0.1:49156/callback';
const authorizationPath = `/realms/${realm}/protocol/openid-connect/auth`;
let clientPrivateKey;
let clientPrivateJwk;
let wrongPrivateKey;
let runtime;

before(async () => {
  const clientKeys = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const wrongKeys = await generateKeyPair('RS256', { modulusLength: 2048 });
  clientPrivateKey = clientKeys.privateKey;
  clientPrivateJwk = await exportJWK(clientKeys.privateKey);
  wrongPrivateKey = wrongKeys.privateKey;
  const clientPublicJwk = {
    ...await exportJWK(clientKeys.publicKey),
    alg: 'RS256',
    kid: 'jar-signing-key',
    use: 'sig',
  };

  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34993',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [{
        client_id: jarClientId,
        application_type: 'native',
        token_endpoint_auth_method: 'none',
        redirect_uris: [jarRedirectUri],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        request_object_signing_alg: 'RS256',
        require_signed_request_object: true,
        jwks: { keys: [clientPublicJwk] },
      }, {
        client_id: plainClientId,
        application_type: 'native',
        token_endpoint_auth_method: 'none',
        redirect_uris: [plainRedirectUri],
        response_types: ['code'],
        grant_types: ['authorization_code'],
      }],
    }),
  }));
});

after(async () => {
  await runtime?.close();
});

function csrf(html) {
  const match = html.match(/name="csrf" value="([^"]+)"/u);
  assert(match, 'Interaction form did not include a CSRF token');
  return match[1];
}

function authorizationParameters({ clientId = jarClientId, redirectUri = jarRedirectUri, includePkce = true } = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const parameters = {
    aud: issuer,
    client_id: clientId,
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: Math.floor(Date.now() / 1000),
    iss: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile',
    state: randomBytes(16).toString('base64url'),
  };
  if (includePkce) {
    parameters.code_challenge = createHash('sha256').update(verifier).digest('base64url');
    parameters.code_challenge_method = 'S256';
  }
  return { parameters, verifier };
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

async function signedRequestObject(parameters, key = clientPrivateKey) {
  return new SignJWT(parameters)
    .setProtectedHeader({ alg: 'RS256', kid: 'jar-signing-key', typ: 'oauth-authz-req+jwt' })
    .sign(key);
}

function unsignedRequestObject(parameters) {
  return `${base64urlJson({ alg: 'none', typ: 'oauth-authz-req+jwt' })}.${base64urlJson(parameters)}.`;
}

async function finishAuthorization(agent, response, redirectUri) {
  let sawProfileScope = false;
  for (let step = 0; step < 8; step += 1) {
    assert([302, 303].includes(response.status), `Unexpected authorization status ${response.status}`);
    const location = response.headers.location;
    assert(location, 'Authorization response did not include a Location header');
    const target = new URL(location, base);
    const callback = new URL(redirectUri);
    if (target.origin === callback.origin && target.pathname === callback.pathname) {
      return { callback: target, sawProfileScope };
    }

    assert.equal(target.origin, base, 'Authorization redirected to an unexpected origin');
    response = await agent
      .get(`${target.pathname}${target.search}`)
      .set('host', new URL(base).host);
    if (response.status !== 200) continue;

    if (response.text.includes('/login"')) {
      response = await agent
        .post(`${target.pathname}/login`)
        .set('host', new URL(base).host)
        .type('form')
        .send({
          csrf: csrf(response.text),
          login: 'admin',
          password: 'AuthMe-Change-Me-Now-2026!',
          otp: '',
        });
    } else if (response.text.includes('/confirm"')) {
      sawProfileScope ||= response.text.includes('<strong>profile</strong>');
      response = await agent
        .post(`${target.pathname}/confirm`)
        .set('host', new URL(base).host)
        .type('form')
        .send({ csrf: csrf(response.text) });
    } else {
      assert.fail('Authorization returned an unexpected interaction page');
    }
  }

  assert.fail('Authorization did not return to the client');
}

test('discovery and client metadata expose the constrained JAR profile', async () => {
  const discovery = await request(runtime.app)
    .get(`/realms/${realm}/.well-known/openid-configuration`)
    .set('host', new URL(base).host)
    .expect(200);

  assert.equal(discovery.body.request_parameter_supported, true);
  assert.equal(discovery.body.request_uri_parameter_supported, false);
  assert.deepEqual(discovery.body.request_object_signing_alg_values_supported, ['RS256', 'PS256', 'ES256']);

  const client = await runtime.providers.get(realm).Client.find(jarClientId);
  assert.equal(client.requestObjectSigningAlg, 'RS256');
  assert.equal(client.requireSignedRequestObject, true);

  const externalRequestUri = await request(runtime.app)
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({ client_id: plainClientId, request_uri: 'https://client.example.test/request.jwt' });
  assert([302, 303].includes(externalRequestUri.status), `Unexpected request_uri error status ${externalRequestUri.status}`);
  const callback = new URL(externalRequestUri.headers.location, base);
  assert.equal(callback.origin, new URL(plainRedirectUri).origin);
  assert.equal(callback.pathname, new URL(plainRedirectUri).pathname);
  assert.equal(callback.searchParams.get('error'), 'request_uri_not_supported');
});

test('a valid signed request object succeeds and its redirect URI and scope are honored', async () => {
  const agent = request.agent(runtime.app);
  const { parameters } = authorizationParameters();
  const requestObject = await signedRequestObject(parameters);
  const response = await agent
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({ client_id: jarClientId, request: requestObject });
  const { callback, sawProfileScope } = await finishAuthorization(agent, response, jarRedirectUri);

  assert.equal(callback.searchParams.get('state'), parameters.state);
  assert.equal(typeof callback.searchParams.get('code'), 'string');
  assert.equal(callback.searchParams.get('error'), null);
  assert.equal(sawProfileScope, true);
});

test('an unsigned request object using alg none is rejected', async () => {
  const { parameters } = authorizationParameters();
  const response = await request(runtime.app)
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({ client_id: jarClientId, request: unsignedRequestObject(parameters) });

  assert([302, 303].includes(response.status), `Unexpected unsigned JAR error status ${response.status}`);
  const callback = new URL(response.headers.location, base);
  assert.equal(callback.origin, new URL(jarRedirectUri).origin);
  assert.equal(callback.pathname, new URL(jarRedirectUri).pathname);
  assert.equal(callback.searchParams.get('error'), 'invalid_request_object');
  assert.match(callback.searchParams.get('error_description') ?? '', /unsupported signed request alg/u);
});

test('a request object signed with a key not registered to the client is rejected', async () => {
  const { parameters } = authorizationParameters();
  const response = await request(runtime.app)
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({ client_id: jarClientId, request: await signedRequestObject(parameters, wrongPrivateKey) });

  assert([302, 303].includes(response.status), `Unexpected wrong-key JAR error status ${response.status}`);
  const callback = new URL(response.headers.location, base);
  assert.equal(callback.origin, new URL(jarRedirectUri).origin);
  assert.equal(callback.pathname, new URL(jarRedirectUri).pathname);
  assert.equal(callback.searchParams.get('error'), 'invalid_request_object');
  assert.match(callback.searchParams.get('error_description') ?? '', /could not validate Request Object/u);
});

test('signed request objects still enforce exact redirect URI registration and PKCE', async () => {
  const unregistered = authorizationParameters({ redirectUri: 'http://127.0.0.1:49157/other-callback' });
  const redirectResponse = await request(runtime.app)
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({ client_id: jarClientId, request: await signedRequestObject(unregistered.parameters) });
  assert.equal(redirectResponse.status, 400);
  assert.equal(redirectResponse.headers.location, undefined);
  assert.match(redirectResponse.text, /redirect_uri/u);

  const withoutPkce = authorizationParameters({ includePkce: false });
  const pkceResponse = await request(runtime.app)
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({ client_id: jarClientId, request: await signedRequestObject(withoutPkce.parameters) });
  assert([302, 303].includes(pkceResponse.status), `Unexpected PKCE error status ${pkceResponse.status}`);
  const callback = new URL(pkceResponse.headers.location, base);
  assert.equal(callback.origin, new URL(jarRedirectUri).origin);
  assert.equal(callback.pathname, new URL(jarRedirectUri).pathname);
  assert.equal(callback.searchParams.get('error'), 'invalid_request');
  assert.match(callback.searchParams.get('error_description') ?? '', /PKCE|code_challenge/iu);
});

test('normal authorization requests continue to work for clients that do not require JAR', async () => {
  const agent = request.agent(runtime.app);
  const { parameters } = authorizationParameters({ clientId: plainClientId, redirectUri: plainRedirectUri });
  const response = await agent
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query(parameters);
  const { callback } = await finishAuthorization(agent, response, plainRedirectUri);

  assert.equal(callback.searchParams.get('state'), parameters.state);
  assert.equal(typeof callback.searchParams.get('code'), 'string');
  assert.equal(callback.searchParams.get('error'), null);
});

test('inline client JWKS reject symmetric (oct) keys', () => {
  assert.throws(() => validateClientSecurity({
    token_endpoint_auth_method: 'none',
    request_object_signing_alg: 'RS256',
    jwks: { keys: [{ kty: 'oct', k: 'c2VjcmV0LWtleS1tYXRlcmlhbA', alg: 'HS256', kid: 'symmetric-key' }] },
  }, { development: true }), /inline jwks must contain public keys only/u);
});
