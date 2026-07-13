import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  AUTHME_EXTENSION_API_VERSION,
  createIdentityExtensionRegistry,
} from '../src/authentication/registry.js';

function extension(overrides = {}) {
  return {
    manifest: {
      apiVersion: AUTHME_EXTENSION_API_VERSION,
      id: 'example.password',
      kind: 'authenticator',
      displayName: 'Example password',
      capabilities: ['password'],
      ...overrides.manifest,
    },
    implementation: { authenticate() {}, ...overrides.implementation },
  };
}

test('identity extensions expose only versioned, non-secret metadata', () => {
  const registry = createIdentityExtensionRegistry([extension({
    implementation: { enabledFor: (realm) => realm === 'staff', authenticate() {}, secret: 'not-described' },
  })]);

  assert.deepEqual(registry.describe('master'), []);
  assert.deepEqual(registry.describe('staff'), [{
    apiVersion: AUTHME_EXTENSION_API_VERSION,
    id: 'example.password',
    kind: 'authenticator',
    displayName: 'Example password',
    capabilities: ['password'],
  }]);
  assert.equal(Object.isFrozen(registry.describe('staff')[0]), true);
});

test('identity extension registry rejects incompatible and ambiguous providers', () => {
  assert.throws(
    () => createIdentityExtensionRegistry([extension({ manifest: { apiVersion: 'authme.identity/v2' } })]),
    /apiVersion/,
  );
  assert.throws(
    () => createIdentityExtensionRegistry([extension({ implementation: { authenticate: undefined } })]),
    /authenticate\(\) or begin\(\)\/complete\(\)/,
  );
  assert.throws(
    () => createIdentityExtensionRegistry([extension(), extension()]),
    /duplicate id/,
  );
  assert.throws(
    () => createIdentityExtensionRegistry([extension({ manifest: { capabilities: ['password', 'password'] } })]),
    /capabilities/,
  );
});

test('federation and provisioning extensions have explicit contracts', () => {
  assert.throws(() => createIdentityExtensionRegistry([extension({
    manifest: { id: 'example.saml', kind: 'federation', capabilities: ['saml2'] },
    implementation: { authenticate: undefined },
  })]), /initiate\(\) and consume\(\)/);
  assert.throws(() => createIdentityExtensionRegistry([extension({
    manifest: { id: 'example.scim', kind: 'provisioning', capabilities: ['scim2'] },
    implementation: { authenticate: undefined },
  })]), /createRouter\(\)/);
});
