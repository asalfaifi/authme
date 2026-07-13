import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  clientCanIntrospectToken,
  corsAllowed,
  findConfiguredResourceServer,
  pairwiseSubjectIdentifier,
  resourceTokenClaims,
  validateClientSecurity,
} from '../src/provider.js';

const secret = 's'.repeat(32);

test('client security policy rejects obsolete grants in every mode', () => {
  assert.throws(() => validateClientSecurity({ grant_types: ['password'] }, { development: true }), /not supported/);
  assert.throws(() => validateClientSecurity({ grant_types: ['implicit'] }), /not supported/);
});

test('client security policy exposes only the supported v0.2 authentication and subject methods', () => {
  assert.doesNotThrow(() => validateClientSecurity({ token_endpoint_auth_method: 'client_secret_basic' }, { development: true }));
  assert.doesNotThrow(() => validateClientSecurity({ token_endpoint_auth_method: 'none', subject_type: 'pairwise' }, { development: true }));
  assert.throws(
    () => validateClientSecurity({ token_endpoint_auth_method: 'private_key_jwt' }, { development: true }),
    /Unsupported token endpoint authentication method/,
  );
  assert.throws(
    () => validateClientSecurity({ subject_type: 'sector-specific' }, { development: true }),
    /Unsupported subject type/,
  );
});

test('pairwise subjects are stable within a sector and unlinkable across clients and realms', () => {
  const salt = 'pairwise-subject-test-salt-value-0001';
  const first = pairwiseSubjectIdentifier(salt, 'master', 'user-1', 'client-a');
  assert.equal(first, pairwiseSubjectIdentifier(salt, 'master', 'user-1', 'client-a'));
  assert.notEqual(first, pairwiseSubjectIdentifier(salt, 'master', 'user-1', 'client-b'));
  assert.notEqual(first, pairwiseSubjectIdentifier(salt, 'staff', 'user-1', 'client-a'));
});

test('production clients require secure redirects and strong shared secrets', () => {
  assert.throws(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['http://app.example.test/callback'],
  }), /must use HTTPS/);
  assert.throws(() => validateClientSecurity({
    client_secret: 'short',
    redirect_uris: ['https://app.example.test/callback'],
  }), /at least 32 bytes/);
  assert.throws(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['https://app.example.test/callback#fragment'],
  }), /fragments/);
  assert.throws(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['https://app.example.test/callback'],
    jwks_uri: 'http://keys.example.test/jwks.json',
  }), /jwks_uri must use HTTPS/);
  assert.throws(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['https://app.example.test/callback'],
    backchannel_logout_uri: 'https://user:pass@app.example.test/logout',
  }), /cannot contain credentials/);
});

test('production policy permits HTTPS web clients and native loopback clients', () => {
  assert.doesNotThrow(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['https://app.example.test/callback'],
    post_logout_redirect_uris: ['https://app.example.test/'],
    web_origins: ['https://app.example.test'],
  }));
  assert.doesNotThrow(() => validateClientSecurity({
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    redirect_uris: ['http://127.0.0.1:49321/callback'],
  }));
});

test('CORS uses only validated explicit web origins', () => {
  const client = {
    web_origins: ['https://browser.example.test'],
    redirectUris: ['https://redirect.example.test/callback'],
    postLogoutRedirectUris: ['https://logout.example.test/'],
  };
  assert.equal(corsAllowed('https://browser.example.test', client), true);
  assert.equal(corsAllowed('https://redirect.example.test', client), false);
  assert.equal(corsAllowed('https://logout.example.test', client), false);
  assert.equal(corsAllowed('https://sub.browser.example.test', client), false);
  assert.equal(corsAllowed('https://browser.example.test', { redirectUris: client.redirectUris }), false);

  assert.throws(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['https://app.example.test/callback'],
    web_origins: '*',
  }), /must be an array/);
  assert.throws(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['https://app.example.test/callback'],
    web_origins: ['https://app.example.test/path'],
  }), /exact HTTP\(S\) origins/);
  assert.throws(() => validateClientSecurity({
    client_secret: secret,
    redirect_uris: ['https://app.example.test/callback'],
    web_origins: ['http://app.example.test'],
  }), /must use HTTPS/);
  assert.doesNotThrow(() => validateClientSecurity({
    token_endpoint_auth_method: 'none',
    redirect_uris: ['http://127.0.0.1:3001/callback'],
    web_origins: ['http://127.0.0.1:3001'],
  }, { development: true }));
});

test('resource-server lookup normalizes audiences and token claims are audience and scope filtered', () => {
  const resourceServers = [{
    audience: 'https://api.example.test/orders',
    scopes: ['roles', 'groups'],
    roleClientIds: ['orders-api'],
    includeRealmRoles: true,
    includeGroups: true,
  }];
  const resourceServer = findConfiguredResourceServer(resourceServers, 'https://api.example.test/orders');
  assert.equal(resourceServer, resourceServers[0]);
  assert.equal(findConfiguredResourceServer(resourceServers, 'https://api.example.test/other'), undefined);

  const user = {
    roles: ['member'],
    groups: ['/engineering'],
    clientRoles: {
      'orders-api': ['orders.read'],
      'payroll-api': ['payroll.read'],
    },
  };
  assert.deepEqual(resourceTokenClaims(resourceServer, user, new Set(['roles', 'groups'])), {
    realm_access: { roles: ['member'] },
    resource_access: { 'orders-api': { roles: ['orders.read'] } },
    groups: ['/engineering'],
  });
  assert.deepEqual(resourceTokenClaims(resourceServer, user, new Set(['groups'])), {
    groups: ['/engineering'],
  });
  assert.equal(resourceTokenClaims(resourceServer, user, new Set(['openid'])), undefined);

  resourceServer.introspectionClientIds = ['orders-api'];
  assert.equal(clientCanIntrospectToken(resourceServers, 'browser-client', {
    clientId: 'browser-client', aud: resourceServer.audience,
  }), true);
  assert.equal(clientCanIntrospectToken(resourceServers, 'orders-api', {
    clientId: 'browser-client', aud: resourceServer.audience,
  }, 'client_secret_basic'), true);
  assert.equal(clientCanIntrospectToken(resourceServers, 'orders-api', {
    clientId: 'browser-client', aud: resourceServer.audience,
  }, 'none'), false);
  assert.equal(clientCanIntrospectToken(resourceServers, 'payroll-api', {
    clientId: 'browser-client', aud: resourceServer.audience,
  }), false);
});
