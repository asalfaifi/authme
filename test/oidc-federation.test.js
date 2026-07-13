import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, importJWK, SignJWT } from 'jose';

import { createOidcBroker, parseOidcProviders } from '../src/federation/oidc.js';

function configuration(overrides = {}) {
  return JSON.stringify({ staff: [{
    id: 'workforce', display_name: 'Workforce', issuer: 'https://idp.example.test',
    authorization_endpoint: 'https://idp.example.test/authorize', token_endpoint: 'https://idp.example.test/token',
    jwks_uri: 'https://idp.example.test/jwks', client_id: 'authme', client_secret: 'upstream-secret',
    ...overrides,
  }] });
}

function stateStore() {
  const records = new Map();
  return {
    records,
    async issue(realm, payload) { const state = `state-${records.size}`; records.set(`${realm}:${state}`, payload); return state; },
    async consume(realm, state) {
      const key = `${realm}:${state}`;
      const record = records.get(key);
      if (!record) throw new Error('invalid state');
      records.delete(key);
      return record;
    },
  };
}

async function signer() {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const jwk = await exportJWK(publicKey);
  jwk.kid = 'test-key';
  return {
    jwks: async (header) => {
      assert.equal(header.kid, 'test-key');
      return importJWK(jwk, 'RS256');
    },
    sign: (claims) => new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer('https://idp.example.test').setAudience('authme').setIssuedAt().setExpirationTime('5m').sign(privateKey),
  };
}

test('upstream OIDC configuration requires HTTPS and the openid scope', () => {
  assert.throws(
    () => parseOidcProviders(configuration({ issuer: 'http://idp.example.test' }), { realms: ['staff'], devMode: false }),
    /must use HTTPS/,
  );
  assert.throws(
    () => parseOidcProviders(configuration({ scopes: ['profile'] }), { realms: ['staff'], devMode: false }),
    /uniquely include openid/,
  );
  const parsed = parseOidcProviders(configuration(), { realms: ['master', 'staff'], devMode: false });
  assert.equal(parsed.master.length, 0);
  assert.equal(parsed.staff[0].jitProvisioning, false);
  assert.equal(Object.isFrozen(parsed.staff[0]), true);
  assert.equal(parseOidcProviders(configuration({ issuer: 'https://idp.example.test/' }), {
    realms: ['staff'], devMode: false,
  }).staff[0].issuer, 'https://idp.example.test/');
});

test('OIDC broker binds state, nonce, issuer, PKCE, and the callback URI', async () => {
  const [provider] = parseOidcProviders(configuration({
    require_issuer_parameter: true, jit_provisioning: true,
  }), { realms: ['staff'], devMode: false }).staff;
  const states = stateStore();
  const keys = await signer();
  const requests = [];
  const broker = createOidcBroker(provider, {
    stateStore: states,
    jwks: keys.jwks,
    fetch: async (url, options) => {
      requests.push({ url, options });
      const transaction = states.lastTransaction;
      const accessToken = 'upstream-access-token';
      const atHash = createHash('sha256').update(accessToken, 'ascii').digest().subarray(0, 16).toString('base64url');
      return new Response(JSON.stringify({
        access_token: accessToken,
        token_type: 'Bearer',
        id_token: await keys.sign({
          sub: 'upstream-alice', nonce: transaction.nonce, email: 'Alice@Example.Test', email_verified: true,
          preferred_username: 'alice', name: 'Alice Example', groups: ['engineering'], roles: ['developer'], amr: ['pwd', 'mfa'],
          at_hash: atHash,
        }),
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const started = await broker.initiate({
    realm: 'staff', interactionUid: 'interaction-1', callbackUrl: 'https://login.example.test/realms/staff/broker/oidc/workforce/callback',
  });
  const authorization = new URL(started.redirectUrl);
  assert.equal(authorization.searchParams.get('response_type'), 'code');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorization.searchParams.get('state'), started.state);
  assert.ok(authorization.searchParams.get('nonce'));
  states.lastTransaction = states.records.get(`staff:${started.state}`);
  const result = await broker.consume({
    realm: 'staff', callbackUrl: 'https://login.example.test/realms/staff/broker/oidc/workforce/callback',
    params: { state: started.state, code: 'authorization-code', iss: provider.issuer },
  });
  assert.equal(result.protocol, 'oidc');
  assert.equal(result.issuer, provider.issuer);
  assert.equal(result.allowCreate, true);
  assert.deepEqual(result.profile, {
    externalSubject: 'upstream-alice', username: 'alice', email: 'alice@example.test', emailVerified: true,
    name: 'Alice Example', givenName: '', familyName: '', groups: ['engineering'], roles: ['developer'],
  });
  assert.deepEqual(result.amr, ['pwd', 'mfa']);
  const tokenBody = requests[0].options.body;
  assert.equal(tokenBody.get('code_verifier'), states.lastTransaction.codeVerifier);
  assert.match(requests[0].options.headers.authorization, /^Basic /);
  await assert.rejects(() => broker.consume({
    realm: 'staff', callbackUrl: 'https://login.example.test/realms/staff/broker/oidc/workforce/callback',
    params: { state: started.state, code: 'replayed', iss: provider.issuer },
  }), /invalid state/);
});

test('OIDC broker consumes state before rejecting mismatched issuer or nonce', async () => {
  const [provider] = parseOidcProviders(configuration({ require_issuer_parameter: true }), { realms: ['staff'], devMode: false }).staff;
  const states = stateStore();
  const keys = await signer();
  const broker = createOidcBroker(provider, { stateStore: states, jwks: keys.jwks, fetch: async () => { throw new Error('must not fetch'); } });
  const started = await broker.initiate({ realm: 'staff', interactionUid: 'i', callbackUrl: 'https://login.example.test/callback' });
  await assert.rejects(() => broker.consume({
    realm: 'staff', callbackUrl: 'https://login.example.test/callback',
    params: { state: started.state, code: 'code', iss: 'https://attacker.example.test' },
  }), /issuer is invalid/);
  assert.equal(states.records.has(`staff:${started.state}`), false);
});

test('OIDC broker rejects unsafe callbacks and substituted access tokens', async () => {
  const [provider] = parseOidcProviders(configuration(), { realms: ['staff'], devMode: false }).staff;
  const states = stateStore();
  const keys = await signer();
  const broker = createOidcBroker(provider, {
    stateStore: states,
    jwks: keys.jwks,
    fetch: async () => {
      const transaction = states.lastTransaction;
      return new Response(JSON.stringify({
        access_token: 'substituted-token',
        token_type: 'Bearer',
        id_token: await keys.sign({
          sub: 'upstream-alice', nonce: transaction.nonce, email: 'alice@example.test', at_hash: 'invalid-hash',
        }),
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  await assert.rejects(() => broker.initiate({
    realm: 'staff', interactionUid: 'i', callbackUrl: 'https://reader:secret@login.example.test/callback',
  }), /callback URI is invalid/);
  const started = await broker.initiate({ realm: 'staff', interactionUid: 'i', callbackUrl: 'https://login.example.test/callback' });
  states.lastTransaction = states.records.get(`staff:${started.state}`);
  await assert.rejects(() => broker.consume({
    realm: 'staff', callbackUrl: 'https://login.example.test/callback',
    params: { state: started.state, code: 'authorization-code' },
  }), /access token hash is invalid/);
});
