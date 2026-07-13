import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34991';
let runtime;

before(async () => {
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34991',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [{
        client_id: 'pairwise-native',
        application_type: 'native',
        subject_type: 'pairwise',
        token_endpoint_auth_method: 'none',
        redirect_uris: ['http://127.0.0.1:49152/callback'],
        web_origins: ['http://127.0.0.1:49152'],
        response_types: ['code'],
        grant_types: ['authorization_code'],
      }],
    }),
  }));
});

after(async () => {
  await runtime?.close();
});

test('OIDC and RFC 8414 discovery agree on the issuer-mounted protocol endpoints', async () => {
  const oidc = await request(runtime.app)
    .get('/realms/master/.well-known/openid-configuration')
    .set('host', '127.0.0.1:34991')
    .expect(200);
  const oauth = await request(runtime.app)
    .get('/.well-known/oauth-authorization-server/realms/master')
    .set('host', '127.0.0.1:34991')
    .expect(200);

  assert.equal(oauth.body.issuer, `${base}/realms/master`);
  for (const property of [
    'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint',
    'introspection_endpoint', 'revocation_endpoint', 'end_session_endpoint',
  ]) {
    assert.equal(oauth.body[property], oidc.body[property], `${property} differs between metadata documents`);
    assert.match(oauth.body[property], new RegExp(`^${base}/realms/master/`));
    assert.doesNotMatch(oauth.body[property], /\.well-known\/oauth-authorization-server/);
  }
});

test('discovery advertises only supported client authentication and reachable subject types', async () => {
  const response = await request(runtime.app)
    .get('/realms/master/.well-known/openid-configuration')
    .set('host', '127.0.0.1:34991')
    .expect(200);

  assert.deepEqual(response.body.token_endpoint_auth_methods_supported, ['client_secret_basic', 'none']);
  assert.deepEqual(response.body.subject_types_supported, ['public', 'pairwise']);
  const client = await runtime.providers.get('master').Client.find('pairwise-native');
  assert.equal(client.subjectType, 'pairwise');
  assert.equal(client.clientAuthMethod, 'none');
  assert.equal(client.sectorIdentifier, '127.0.0.1:49152');
  assert.deepEqual(client.web_origins, ['http://127.0.0.1:49152']);
});
