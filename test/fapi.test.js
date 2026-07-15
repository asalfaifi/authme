import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  jwtVerify,
  SignJWT,
} from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { validateClientSecurity } from '../src/provider.js';

const base = 'http://127.0.0.1:34997';
const realm = 'master';
const issuer = `${base}/realms/${realm}`;
const authorizationPath = `/realms/${realm}/protocol/openid-connect/auth`;
const parPath = `/realms/${realm}/protocol/openid-connect/ext/par/request`;
const parEndpoint = `${issuer}/protocol/openid-connect/ext/par/request`;
const registrationPath = `/realms/${realm}/clients-registrations/openid-connect`;
const tokenPath = `/realms/${realm}/protocol/openid-connect/token`;
const tokenEndpoint = `${issuer}/protocol/openid-connect/token`;
const introspectionPath = `/realms/${realm}/protocol/openid-connect/token/introspect`;
const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const fapiClientId = 'fapi-private-key-dpop-client';
const fapiRedirectUri = 'http://127.0.0.1:49160/callback';
const normalClientId = 'ordinary-native-client';
const normalRedirectUri = 'http://127.0.0.1:49161/callback';
const clientKeyId = 'fapi-client-signing-key';

let clientPrivateKey;
let clientPublicJwk;
let dpopPrivateKey;
let dpopPublicJwk;
let jwksDir;
let runtime;

function csrf(html) {
  const match = html.match(/name="csrf" value="([^"]+)"/u);
  assert(match, 'Interaction form did not include a CSRF token');
  return match[1];
}

async function finishAuthorization(agent, response, redirectUri) {
  for (let step = 0; step < 8; step += 1) {
    assert([302, 303].includes(response.status), `Unexpected authorization status ${response.status}`);
    const location = response.headers.location;
    assert(location, 'Authorization response did not include a Location header');
    const target = new URL(location, base);
    const callback = new URL(redirectUri);
    if (target.origin === callback.origin && target.pathname === callback.pathname) return target;

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

function fapiAuthorizationParameters({ includePkce = true, responseMode = 'jwt' } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const verifier = randomBytes(32).toString('base64url');
  const parameters = {
    aud: issuer,
    client_id: fapiClientId,
    exp: now + 55,
    iat: now,
    iss: fapiClientId,
    nbf: now - 1,
    redirect_uri: fapiRedirectUri,
    response_type: 'code',
    scope: 'openid profile',
    state: randomBytes(16).toString('base64url'),
  };
  if (responseMode !== undefined) parameters.response_mode = responseMode;
  if (includePkce) {
    parameters.code_challenge = createHash('sha256').update(verifier).digest('base64url');
    parameters.code_challenge_method = 'S256';
  }
  return { parameters, verifier };
}

async function requestObject(parameters) {
  return new SignJWT(parameters)
    .setProtectedHeader({ alg: 'PS256', kid: clientKeyId, typ: 'oauth-authz-req+jwt' })
    .sign(clientPrivateKey);
}

async function clientAssertion(audience = issuer) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    aud: audience,
    exp: now + 120,
    iat: now,
    iss: fapiClientId,
    jti: randomUUID(),
    sub: fapiClientId,
  })
    .setProtectedHeader({ alg: 'PS256', kid: clientKeyId })
    .sign(clientPrivateKey);
}

async function dpopProof(htu) {
  return new SignJWT({
    htm: 'POST',
    htu,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: 'ES256', jwk: dpopPublicJwk, typ: 'dpop+jwt' })
    .sign(dpopPrivateKey);
}

async function pushAuthorization(options = {}) {
  const { parameters, verifier } = fapiAuthorizationParameters(options);
  const response = await request(runtime.app)
    .post(parPath)
    .set('host', new URL(base).host)
    .set('DPoP', await dpopProof(parEndpoint))
    .type('form')
    .send({
      client_assertion: await clientAssertion(),
      client_assertion_type: assertionType,
      request: await requestObject(parameters),
    });
  return { parameters, response, verifier };
}

function dynamicFapiMetadata(overrides = {}) {
  return {
    fapi_profile: '2.0',
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'PS256',
    dpop_bound_access_tokens: true,
    redirect_uris: ['http://127.0.0.1:49162/callback'],
    response_types: ['code'],
    grant_types: ['authorization_code'],
    request_object_signing_alg: 'PS256',
    authorization_signed_response_alg: 'PS256',
    jwks: { keys: [clientPublicJwk] },
    ...overrides,
  };
}

async function registrationToken() {
  const provider = runtime.providers.get(realm);
  return new provider.InitialAccessToken({
    expiresIn: 60,
    policies: ['authme-secure-client'],
  }).save();
}

function postRegistration(token, metadata) {
  return request(runtime.app)
    .post(registrationPath)
    .set('host', new URL(base).host)
    .set('authorization', `Bearer ${token}`)
    .send(metadata);
}

before(async () => {
  const clientKeys = await generateKeyPair('PS256', { modulusLength: 2048, extractable: true });
  clientPrivateKey = clientKeys.privateKey;
  clientPublicJwk = {
    ...await exportJWK(clientKeys.publicKey),
    alg: 'PS256',
    key_ops: ['verify'],
    kid: clientKeyId,
    use: 'sig',
  };

  const dpopKeys = await generateKeyPair('ES256', { extractable: true });
  dpopPrivateKey = dpopKeys.privateKey;
  dpopPublicJwk = await exportJWK(dpopKeys.publicKey);

  const rsKeys = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const psKeys = await generateKeyPair('PS256', { modulusLength: 2048, extractable: true });
  const rsPrivateJwk = {
    ...await exportJWK(rsKeys.privateKey),
    alg: 'RS256',
    kid: 'realm-rs256-key',
    use: 'sig',
  };
  const psPrivateJwk = {
    ...await exportJWK(psKeys.privateKey),
    alg: 'PS256',
    kid: 'realm-ps256-key',
    use: 'sig',
  };
  jwksDir = await mkdtemp(join(tmpdir(), 'authme-fapi-'));
  await writeFile(join(jwksDir, `${realm}.json`), JSON.stringify({ keys: [rsPrivateJwk, psPrivateJwk] }));

  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34997',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_JWKS_DIR: jwksDir,
    AUTHME_ENABLE_DYNAMIC_REGISTRATION: 'true',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [{
        client_id: fapiClientId,
        fapi_profile: '2.0',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'PS256',
        dpop_bound_access_tokens: true,
        redirect_uris: [fapiRedirectUri],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        request_object_signing_alg: 'PS256',
        authorization_signed_response_alg: 'PS256',
        jwks: { keys: [clientPublicJwk] },
      }, {
        client_id: normalClientId,
        application_type: 'native',
        token_endpoint_auth_method: 'none',
        redirect_uris: [normalRedirectUri],
        response_types: ['code'],
        grant_types: ['authorization_code'],
      }],
    }),
  }));
});

after(async () => {
  await runtime?.close();
  if (jwksDir) await rm(jwksDir, { recursive: true, force: true });
});

test('discovery and client metadata expose the composed FAPI capabilities without a global mandate', async () => {
  const discovery = await request(runtime.app)
    .get(`/realms/${realm}/.well-known/openid-configuration`)
    .set('host', new URL(base).host)
    .expect(200);

  assert.equal(discovery.body.pushed_authorization_request_endpoint, parEndpoint);
  assert.equal(discovery.body.require_pushed_authorization_requests, undefined);
  assert.deepEqual(discovery.body.code_challenge_methods_supported, ['S256']);
  assert.equal(discovery.body.request_parameter_supported, true);
  assert(discovery.body.request_object_signing_alg_values_supported.includes('PS256'));
  assert(discovery.body.response_modes_supported.includes('jwt'));
  assert(discovery.body.authorization_signing_alg_values_supported.includes('PS256'));
  assert(discovery.body.id_token_signing_alg_values_supported.includes('PS256'));
  assert(discovery.body.dpop_signing_alg_values_supported.includes('ES256'));
  assert(discovery.body.token_endpoint_auth_methods_supported.includes('private_key_jwt'));

  const provider = runtime.providers.get(realm);
  const fapiClient = await provider.Client.find(fapiClientId);
  assert.equal(fapiClient.fapi_profile, '2.0');
  assert.equal(fapiClient.requirePushedAuthorizationRequests, true);
  assert.equal(fapiClient.requireSignedRequestObject, true);
  assert.deepEqual(fapiClient.responseModes, ['jwt']);
  assert.equal(fapiClient.idTokenSignedResponseAlg, 'PS256');
  assert.equal(fapiClient.dpopBoundAccessTokens, true);

  const normalClient = await provider.Client.find(normalClientId);
  assert.equal(normalClient.fapi_profile, undefined);
  assert.equal(normalClient.requirePushedAuthorizationRequests, false);
  assert.equal(normalClient.requireSignedRequestObject, false);
});

test('a FAPI client completes PAR, PKCE, JAR, JARM, private_key_jwt, and DPoP', async () => {
  const agent = request.agent(runtime.app);
  const { parameters, response: pushed, verifier } = await pushAuthorization();
  assert.equal(pushed.status, 201);
  assert.equal(typeof pushed.body.request_uri, 'string');

  const authorization = await agent
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({ client_id: fapiClientId, request_uri: pushed.body.request_uri });
  const callback = await finishAuthorization(agent, authorization, fapiRedirectUri);
  const responseJwt = callback.searchParams.get('response');
  assert(responseJwt, 'FAPI authorization response did not use JARM');

  const realmJwks = await request(runtime.app)
    .get(`/realms/${realm}/protocol/openid-connect/certs`)
    .set('host', new URL(base).host)
    .expect(200);
  const responseHeader = decodeProtectedHeader(responseJwt);
  assert(
    realmJwks.body.keys.some((key) => key.kid === responseHeader.kid && key.alg === responseHeader.alg),
    `JARM header ${JSON.stringify(responseHeader)} did not match ${JSON.stringify(realmJwks.body.keys)}`,
  );
  const { payload } = await jwtVerify(responseJwt, createLocalJWKSet(realmJwks.body), {
    algorithms: ['PS256'],
    audience: fapiClientId,
    issuer,
  });
  assert.equal(payload.state, parameters.state);
  assert.equal(typeof payload.code, 'string');
  const authorizationCode = await runtime.providers.get(realm).AuthorizationCode.find(payload.code);
  assert(authorizationCode.remainingTTL > 0 && authorizationCode.remainingTTL <= 60);

  const unconstrained = await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .type('form')
    .send({
      client_assertion: await clientAssertion(),
      client_assertion_type: assertionType,
      code: payload.code,
      code_verifier: verifier,
      grant_type: 'authorization_code',
      redirect_uri: fapiRedirectUri,
    })
    .expect(400);
  assert.equal(unconstrained.body.error, 'invalid_grant');

  const token = await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .set('DPoP', await dpopProof(tokenEndpoint))
    .type('form')
    .send({
      client_assertion: await clientAssertion(),
      client_assertion_type: assertionType,
      code: payload.code,
      code_verifier: verifier,
      grant_type: 'authorization_code',
      redirect_uri: fapiRedirectUri,
    })
    .expect(200);
  assert.equal(token.body.token_type, 'DPoP');
  assert.equal(typeof token.body.access_token, 'string');
  assert.equal(typeof token.body.id_token, 'string');
  const idTokenHeader = decodeProtectedHeader(token.body.id_token);
  assert(['PS256', 'ES256'].includes(idTokenHeader.alg));
  assert.notEqual(idTokenHeader.alg, 'RS256');
  const verifiedIdToken = await jwtVerify(token.body.id_token, createLocalJWKSet(realmJwks.body), {
    algorithms: ['PS256', 'ES256'],
    audience: fapiClientId,
    issuer,
  });
  assert.equal(typeof verifiedIdToken.payload.sub, 'string');

  const introspection = await request(runtime.app)
    .post(introspectionPath)
    .set('host', new URL(base).host)
    .type('form')
    .send({
      client_assertion: await clientAssertion(),
      client_assertion_type: assertionType,
      token: token.body.access_token,
    })
    .expect(200);
  assert.equal(introspection.body.active, true);
  assert.equal(introspection.body.cnf.jkt, await calculateJwkThumbprint(dpopPublicJwk));
});

test('FAPI downgrade attempts fail closed', async (t) => {
  await t.test('authorization errors use JARM when response_mode is missing or plain', async () => {
    const realmJwks = await request(runtime.app)
      .get(`/realms/${realm}/protocol/openid-connect/certs`)
      .set('host', new URL(base).host)
      .expect(200);

    for (const responseMode of [undefined, 'query', 'fragment']) {
      const { parameters } = fapiAuthorizationParameters({ responseMode });
      const response = await request(runtime.app)
        .get(authorizationPath)
        .set('host', new URL(base).host)
        .query(parameters);
      assert.equal(response.status, 303);
      const callback = new URL(response.headers.location, base);
      assert.equal(callback.origin, new URL(fapiRedirectUri).origin);
      assert.equal(callback.hash, '');
      assert.equal(callback.searchParams.get('error'), null);
      assert.equal(callback.searchParams.get('error_description'), null);
      const responseJwt = callback.searchParams.get('response');
      assert(responseJwt, `FAPI error response did not use JARM for ${responseMode ?? 'omitted'} response_mode`);
      const { payload } = await jwtVerify(responseJwt, createLocalJWKSet(realmJwks.body), {
        algorithms: ['PS256'],
        audience: fapiClientId,
        issuer,
      });
      assert.equal(payload.error, 'invalid_request');
      assert.match(payload.error_description, /Pushed Authorization Request must be used/u);
    }
  });

  await t.test('PAR without PKCE is rejected', async () => {
    const { response } = await pushAuthorization({ includePkce: false });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_request');
    assert.match(response.body.error_description, /PKCE|code_challenge/iu);
  });

  await t.test('a plain authorization response mode is rejected', async () => {
    const { response } = await pushAuthorization({ responseMode: 'query' });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_request');
    assert.match(response.body.error_description, /response_mode/u);
  });

  await t.test('weak client authentication is rejected', async () => {
    const { parameters } = fapiAuthorizationParameters();
    const response = await request(runtime.app)
      .post(parPath)
      .set('host', new URL(base).host)
      .auth(fapiClientId, 'not-a-valid-secret')
      .type('form')
      .send({ request: await requestObject(parameters) })
      .expect(401);
    assert.equal(response.body.error, 'invalid_client');
  });

  await t.test('a client assertion with the endpoint as audience is rejected', async () => {
    const { parameters } = fapiAuthorizationParameters();
    const response = await request(runtime.app)
      .post(parPath)
      .set('host', new URL(base).host)
      .set('DPoP', await dpopProof(parEndpoint))
      .type('form')
      .send({
        client_assertion: await clientAssertion(parEndpoint),
        client_assertion_type: assertionType,
        request: await requestObject(parameters),
      })
      .expect(401);
    assert.equal(response.body.error, 'invalid_client');
  });
});

test('a non-FAPI client remains on the ordinary authorization path', async () => {
  const agent = request.agent(runtime.app);
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('base64url');
  const response = await agent
    .get(authorizationPath)
    .set('host', new URL(base).host)
    .query({
      client_id: normalClientId,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
      redirect_uri: normalRedirectUri,
      response_type: 'code',
      scope: 'openid',
      state,
    });
  const callback = await finishAuthorization(agent, response, normalRedirectUri);

  assert.equal(callback.searchParams.get('response'), null);
  assert.equal(callback.searchParams.get('state'), state);
  assert.equal(typeof callback.searchParams.get('code'), 'string');
});

test('FAPI registration rejects weak ID-token algorithms and prevents profile removal', async () => {
  const token = await registrationToken();
  for (const algorithm of ['RS256', 'none']) {
    const rejected = await postRegistration(token, dynamicFapiMetadata({
      id_token_signed_response_alg: algorithm,
    })).expect(400);
    assert.equal(rejected.body.error, 'invalid_client_metadata');
    assert.match(rejected.body.error_description, /ID Tokens with PS256 or ES256/u);
  }

  const registered = await postRegistration(token, dynamicFapiMetadata()).expect(201);
  assert.equal(registered.body.fapi_profile, '2.0');
  assert.equal(registered.body.id_token_signed_response_alg, 'PS256');

  const update = structuredClone(registered.body);
  for (const property of [
    'client_id_issued_at',
    'client_secret_expires_at',
    'fapi_profile',
    'registration_access_token',
    'registration_client_uri',
  ]) delete update[property];

  const updatePath = new URL(registered.body.registration_client_uri).pathname;
  const rejectedUpdate = await request(runtime.app)
    .put(updatePath)
    .set('host', new URL(base).host)
    .set('authorization', `Bearer ${registered.body.registration_access_token}`)
    .send(update)
    .expect(400);
  assert.equal(rejectedUpdate.body.error, 'invalid_client_metadata');
  assert.match(rejectedUpdate.body.error_description, /cannot remove their fapi_profile/u);

  const stored = await runtime.providers.get(realm).Client.find(registered.body.client_id);
  assert.equal(stored.fapi_profile, '2.0');
});

test('FAPI client configuration rejects unknown profiles and unsafe combinations', () => {
  assert.throws(() => loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_CLIENTS_JSON: JSON.stringify({ master: [{ client_id: 'invalid', fapi_profile: '1.0' }] }),
  }), /fapi_profile must be 2\.0/u);

  assert.throws(() => validateClientSecurity({
    client_id: 'weak-fapi-client',
    fapi_profile: '2.0',
    token_endpoint_auth_method: 'client_secret_basic',
    dpop_bound_access_tokens: true,
  }, { development: true }), /private_key_jwt or mutual-TLS/u);

  assert.throws(() => validateClientSecurity({
    client_id: 'bearer-fapi-client',
    fapi_profile: '2.0',
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'PS256',
  }, { development: true }), /sender-constrained/u);
});
