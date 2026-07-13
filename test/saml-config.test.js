import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseSamlProviders } from '../src/federation/saml-config.js';

const certificate = `-----BEGIN CERTIFICATE-----\n${'A'.repeat(128)}\n-----END CERTIFICATE-----`;

function input(overrides = {}) {
  return JSON.stringify({ staff: [{
    id: 'workforce', display_name: 'Workforce SAML',
    idp_entity_id: 'https://idp.example.test/metadata', idp_sso_url: 'https://idp.example.test/sso',
    idp_signing_certificates: [certificate], ...overrides,
  }] });
}

test('SAML provider configuration derives exact realm/provider SP endpoints', () => {
  const providers = parseSamlProviders(input(), {
    realms: ['master', 'staff'], publicUrl: 'https://login.example.test',
  });
  assert.deepEqual(providers.master, []);
  assert.equal(providers.staff[0].sp.entityId, 'https://login.example.test/realms/staff/federation/builtin.saml-federation/workforce/metadata');
  assert.equal(providers.staff[0].sp.assertionConsumerServiceUrl, 'https://login.example.test/realms/staff/federation/builtin.saml-federation/workforce/acs');
  assert.equal(providers.staff[0].trustEmail, false);
  assert.equal(providers.staff[0].jitProvisioning, false);
  assert.equal(Object.isFrozen(providers.staff[0].idp.signingCertificates), true);
});

test('SAML provider configuration fails closed for HTTP, partial signing keys, and short replay retention', () => {
  assert.throws(() => parseSamlProviders(input(), {
    realms: ['staff'], publicUrl: 'http://127.0.0.1:3000',
  }), /requires an HTTPS/);
  assert.throws(() => parseSamlProviders(input({
    sp_signing_private_key: `-----BEGIN PRIVATE KEY-----\n${'A'.repeat(128)}\n-----END PRIVATE KEY-----`,
  }), { realms: ['staff'], publicUrl: 'https://login.example.test' }), /both SP signing/);
  assert.throws(() => parseSamlProviders(input({
    max_assertion_age_ms: 300_000, clock_skew_ms: 60_000, replay_ttl_ms: 300_000,
  }), { realms: ['staff'], publicUrl: 'https://login.example.test' }), /must cover assertion age/);
  assert.throws(() => parseSamlProviders(input({ idp_sso_url: 'http://idp.example.test/sso' }), {
    realms: ['staff'], publicUrl: 'https://login.example.test',
  }), /must be an exact HTTPS URL/);
  assert.throws(() => parseSamlProviders(input({ idp_sso_url: 'https://reader:secret@idp.example.test/sso' }), {
    realms: ['staff'], publicUrl: 'https://login.example.test',
  }), /must be an exact HTTPS URL/);
  assert.throws(() => parseSamlProviders(input(), {
    realms: ['staff'], publicUrl: 'https://reader:secret@login.example.test',
  }), /HTTPS AUTHME_PUBLIC_URL origin/);
});
