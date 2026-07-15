import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34992';
const clientId = 'jarm-client';
const redirectUri = 'http://127.0.0.1:49153/callback';
const realm = 'master';
let runtime;

before(async () => {
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34992',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [{
        client_id: clientId,
        application_type: 'native',
        token_endpoint_auth_method: 'none',
        redirect_uris: [redirectUri],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        authorization_signed_response_alg: 'RS256',
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

async function authorize(responseMode) {
  const agent = request.agent(runtime.app);
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('base64url');
  let response = await agent
    .get(`/realms/${realm}/protocol/openid-connect/auth`)
    .set('host', new URL(base).host)
    .query({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      response_mode: responseMode,
      scope: 'openid',
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
      state,
    });

  for (let step = 0; step < 8; step += 1) {
    assert([302, 303].includes(response.status), `Unexpected authorization status ${response.status}`);
    const location = response.headers.location;
    assert(location, 'Authorization response did not include a Location header');
    const target = new URL(location, base);
    if (target.origin === new URL(redirectUri).origin && target.pathname === new URL(redirectUri).pathname) {
      return { callback: target, state };
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

async function verifyJarm(responseJwt) {
  const jwks = await request(runtime.app)
    .get(`/realms/${realm}/protocol/openid-connect/certs`)
    .set('host', new URL(base).host)
    .expect(200);
  return jwtVerify(responseJwt, createLocalJWKSet(jwks.body), {
    algorithms: ['RS256'],
    issuer: `${base}/realms/${realm}`,
    audience: clientId,
  });
}

test('response_mode=jwt returns a verifiable realm-signed authorization response', async () => {
  const discovery = await request(runtime.app)
    .get(`/realms/${realm}/.well-known/openid-configuration`)
    .set('host', new URL(base).host)
    .expect(200);
  for (const mode of ['jwt', 'query.jwt', 'fragment.jwt', 'form_post.jwt']) {
    assert(discovery.body.response_modes_supported.includes(mode), `Discovery omitted ${mode}`);
  }
  assert.deepEqual(discovery.body.authorization_signing_alg_values_supported, ['RS256']);

  const client = await runtime.providers.get(realm).Client.find(clientId);
  assert.equal(client.authorizationSignedResponseAlg, 'RS256');

  const { callback, state } = await authorize('jwt');
  const responseJwt = callback.searchParams.get('response');
  assert(responseJwt, 'JARM authorization response did not include a response JWT');
  const { payload } = await verifyJarm(responseJwt);

  assert.equal(payload.iss, `${base}/realms/${realm}`);
  assert.equal(payload.aud, clientId);
  assert.equal(payload.state, state);
  assert.equal(typeof payload.exp, 'number');
  assert(payload.exp > Math.floor(Date.now() / 1000));
  assert.equal(typeof payload.code, 'string');
  assert(payload.code.length > 0);
});

test('JARM authorization responses are never unsigned', async () => {
  const { callback } = await authorize('query.jwt');
  const responseJwt = callback.searchParams.get('response');
  assert(responseJwt, 'JARM authorization response did not include a response JWT');
  const header = decodeProtectedHeader(responseJwt);
  const parts = responseJwt.split('.');

  assert.equal(header.alg, 'RS256');
  assert.notEqual(header.alg, 'none');
  assert.equal(parts.length, 3);
  assert(parts[2].length > 0, 'JARM JWT had an empty signature');
  await verifyJarm(responseJwt);
});

test('JARM client metadata rejects alg none', () => {
  const provider = runtime.providers.get(realm);
  assert.throws(
    () => new provider.Client({
      client_id: 'unsigned-jarm-client',
      application_type: 'native',
      token_endpoint_auth_method: 'none',
      redirect_uris: ['http://127.0.0.1:49154/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      authorization_signed_response_alg: 'none',
    }),
    (error) => error.error === 'invalid_client_metadata'
      && /authorization_signed_response_alg/u.test(error.error_description),
  );
});

test('non-JWT query authorization responses remain unchanged', async () => {
  const { callback, state } = await authorize('query');

  assert.equal(callback.searchParams.get('response'), null);
  assert.equal(callback.searchParams.get('state'), state);
  assert.equal(typeof callback.searchParams.get('code'), 'string');
  assert(callback.searchParams.get('code').length > 0);
});
