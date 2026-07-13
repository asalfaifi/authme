import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createIdentityRuntime } from '../src/authentication/runtime.js';
import { clearMemoryAdapter, createMemoryAdapter } from '../src/adapters/memory.js';
import { MemoryIdentityStore } from '../src/repositories/identity-store.js';

function empty(realms) { return Object.fromEntries(realms.map((realm) => [realm, []])); }

test('identity runtime registers stable extension capabilities per realm', () => {
  clearMemoryAdapter();
  const realms = ['master'];
  const config = {
    realms,
    passwordPepper: 'p'.repeat(32),
    ldapProvidersByRealm: empty(realms),
    oidcProvidersByRealm: empty(realms),
    samlProvidersByRealm: empty(realms),
    scimTokensByRealm: empty(realms),
  };
  const runtime = createIdentityRuntime({
    config,
    data: { adapterFor: (realm) => createMemoryAdapter({ realm }) },
    store: new MemoryIdentityStore(),
    disabledPasswordHash: 'unusable',
  });
  assert.deepEqual(runtime.registry.describe('master').map(({ id }) => id), []);
  assert.equal(runtime.registry.get('builtin.ldap', 'authenticator').manifest.displayName, 'LDAP and Active Directory');
  assert.equal(runtime.registry.get('builtin.scim2', 'provisioning').manifest.displayName, 'SCIM 2.0 Provisioning');
});

test('SCIM refuses an isolated process-memory repository', () => {
  const realms = ['master'];
  assert.throws(() => createIdentityRuntime({
    config: {
      realms,
      passwordPepper: 'p'.repeat(32),
      ldapProvidersByRealm: empty(realms), oidcProvidersByRealm: empty(realms), samlProvidersByRealm: empty(realms),
      scimTokensByRealm: { master: [{ id: 'provisioner', token: 'x'.repeat(48) }] },
    },
    data: { adapterFor: (realm) => createMemoryAdapter({ realm }) },
    store: new MemoryIdentityStore(), disabledPasswordHash: 'unusable',
  }), /requires PostgreSQL/);
});
