import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateClientSecurity } from '../src/provider.js';

const secret = 's'.repeat(32);

test('client security policy rejects obsolete grants in every mode', () => {
  assert.throws(() => validateClientSecurity({ grant_types: ['password'] }, { development: true }), /not supported/);
  assert.throws(() => validateClientSecurity({ grant_types: ['implicit'] }), /not supported/);
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
  }));
  assert.doesNotThrow(() => validateClientSecurity({
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    redirect_uris: ['http://127.0.0.1:49321/callback'],
  }));
});
