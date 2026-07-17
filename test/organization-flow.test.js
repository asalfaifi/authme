import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34998';
const host = new URL(base).host;
const issuer = `${base}/realms/master`;
const resource = 'https://api.example.test/organization';
const client = { id: 'organization-client', redirectUri: 'http://127.0.0.1:49170/callback' };
let runtime;
let keySet;

function csrf(html) {
  const match = /name="csrf" value="([^"]+)"/u.exec(html);
  assert(match, 'Interaction form did not include a CSRF token');
  return match[1];
}

async function authorize({ agent = request.agent(runtime.app), organization, scope = 'openid organization', acrValues, expectFailure = false } = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('base64url');
  let response = await agent.get('/realms/master/protocol/openid-connect/auth').set('host', host).query({
    client_id: client.id,
    redirect_uri: client.redirectUri,
    response_type: 'code',
    scope,
    organization,
    resource,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    acr_values: acrValues,
    state,
  });
  for (let step = 0; step < 8; step += 1) {
    if ([302, 303].includes(response.status)) {
      const target = new URL(response.headers.location, base);
      if (target.origin === new URL(client.redirectUri).origin) return { agent, callback: target, verifier };
      response = await agent.get(`${target.pathname}${target.search}`).set('host', host);
      continue;
    }
    if (response.status === 200 && response.text.includes('/login"')) {
      response = await agent.post(new URL(response.request.url).pathname.replace(/\/$/u, '') + '/login')
        .set('host', host).type('form').send({
          csrf: csrf(response.text), login: 'admin', password: 'AuthMe-Change-Me-Now-2026!', otp: '',
        });
      if (expectFailure) return { response, agent };
      continue;
    }
    if (response.status === 200 && response.text.includes('/confirm"')) {
      const path = new URL(response.request.url).pathname.replace(/\/$/u, '');
      response = await agent.post(`${path}/confirm`).set('host', host).type('form').send({ csrf: csrf(response.text) });
      continue;
    }
    break;
  }
  assert.fail(`Authorization did not complete; final status ${response.status}: ${String(response.text).slice(0, 2_000)}`);
}

async function exchange({ callback, verifier }) {
  const response = await request(runtime.app).post('/realms/master/protocol/openid-connect/token')
    .set('host', host).type('form').send({
      grant_type: 'authorization_code', client_id: client.id,
      redirect_uri: client.redirectUri, code: callback.searchParams.get('code'), code_verifier: verifier,
      resource,
    }).expect(200);
  return { ...await jwtVerify(response.body.access_token, keySet, { issuer, audience: resource }), accessToken: response.body.access_token };
}

before(async () => {
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true', AUTHME_PUBLIC_URL: base, AUTHME_PORT: '34998', AUTHME_LOG_LEVEL: 'silent',
    AUTHME_CLIENTS_JSON: JSON.stringify({ master: [{
      client_id: client.id, application_type: 'native', token_endpoint_auth_method: 'none',
      redirect_uris: [client.redirectUri], response_types: ['code'], grant_types: ['authorization_code'],
    }] }),
    AUTHME_RESOURCE_SERVERS_JSON: JSON.stringify({ master: [{
      audience: resource, scopes: ['organization', 'optional-context'], authorized_client_ids: [client.id],
    }] }),
  }));
  const jwks = await request(runtime.app).get('/realms/master/protocol/openid-connect/certs').set('host', host).expect(200);
  keySet = createLocalJWKSet(jwks.body);
});

after(async () => runtime?.close());

test('organization context, optional client scopes, and configured step-up flows are enforced end to end', async () => {
  const admin = await runtime.store.findUserByLogin('master', 'admin');
  const organization = await runtime.data.management.createOrganization('master', {
    name: 'Example', alias: 'example', enabled: true, domains: [{ domain: 'example.test', verified: true }],
    identityProviderIds: [], attributes: {},
  });
  await runtime.data.management.upsertOrganizationMembership('master', organization.id, admin.id, ['owner']);
  const optionalScope = await runtime.data.management.createClientScope('master', {
    name: 'optional-context', description: '', protocol: 'openid-connect', attributes: {},
  });
  await runtime.data.management.setClientScopeAssignment('master', client.id, optionalScope.id, 'optional');
  await runtime.data.management.createClaimMapper('master', {
    ownerType: 'client-scope', ownerId: optionalScope.id, name: 'optional-context', mapperType: 'hardcoded',
    config: { claim: 'optional_context', value: 'granted' },
  });

  const ordinary = await exchange(await authorize({ organization: organization.alias }));
  assert.deepEqual(ordinary.payload.organizations, [{ id: organization.id, alias: 'example', name: 'Example', roles: ['owner'] }]);
  assert.equal(ordinary.payload.optional_context, undefined);

  const optional = await exchange(await authorize({ organization: organization.id, scope: 'openid organization optional-context' }));
  assert.equal(optional.payload.optional_context, 'granted');

  await runtime.data.management.deleteOrganizationMembership('master', organization.id, admin.id);
  const revoked = await request(runtime.app).get('/realms/master/protocol/openid-connect/userinfo')
    .set('host', host).set('authorization', `Bearer ${ordinary.accessToken}`);
  assert.equal([401, 403].includes(revoked.status), true, `expected revoked organization context to fail, received ${revoked.status}`);
  await runtime.data.management.upsertOrganizationMembership('master', organization.id, admin.id, ['owner']);

  const unauthorized = await runtime.data.management.createOrganization('master', {
    name: 'Other', alias: 'other', enabled: true, domains: [], identityProviderIds: [], attributes: {},
  });
  const failure = await authorize({ organization: unauthorized.alias, expectFailure: true });
  assert.equal(failure.response.status, 401);

  const flow = await runtime.data.management.createAuthenticationFlow('master', {
    alias: 'dynamic-assurance', description: '', enabled: true, priority: 1, clientIds: [client.id],
    acr: 'urn:authme:dynamic', maxAgeSeconds: 300, steps: [{ type: 'password', requirement: 'required' }],
  });
  const sessionAgent = request.agent(runtime.app);
  await exchange(await authorize({ agent: sessionAgent, organization: organization.alias, acrValues: flow.acr }));
  await runtime.data.management.updateAuthenticationFlow('master', flow.id, {
    steps: [{ type: 'passkey', requirement: 'required' }],
  });
  const stepUp = await authorize({ agent: sessionAgent, organization: organization.alias, acrValues: flow.acr, expectFailure: true });
  assert.equal(stepUp.response.status, 401);
  assert.match(stepUp.response.text, /stronger authentication method/iu);
});
