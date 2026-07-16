import assert from 'node:assert/strict';
import { test } from 'node:test';

import { authenticateLdapProvider, parseLdapProviders, syncLdapProvider } from '../src/federation/ldap.js';
import { MemoryFederatedIdentityRepository } from '../src/repositories/federated-identity-repository.js';
import { MemoryIdentityStore } from '../src/repositories/identity-store.js';

function configuredProvider(overrides = {}) {
  const parsed = parseLdapProviders(JSON.stringify({
    staff: [{
      id: 'corp',
      display_name: 'Corporate directory',
      url: 'ldaps://directory.example.test:636',
      bind_dn: 'cn=reader,dc=example,dc=test',
      bind_password: 'reader-secret',
      user_base_dn: 'ou=people,dc=example,dc=test',
      sync_enabled: true,
      sync_filter: '(employeeType=staff)',
      sync_page_size: 2,
      sync_max_deprovision_fraction: 1,
      sync_max_deprovision_count: 100,
      ...overrides,
    }],
  }), { realms: ['staff'], devMode: false });
  return parsed.staff[0];
}

function entry(subject, username, overrides = {}) {
  return {
    dn: `uid=${username},ou=people,dc=example,dc=test`,
    entryUUID: subject,
    uid: username,
    mail: `${username}@example.test`,
    displayName: username,
    givenName: username,
    sn: 'Example',
    memberOf: ['CN=Engineering,OU=Groups,DC=example,DC=test'],
    ...overrides,
  };
}

function directory(runs, calls = []) {
  function entriesFor(entries, options) {
    const binary = new Set((options.explicitBufferAttributes ?? []).map((name) => name.toLowerCase()));
    return entries.map((source) => Object.fromEntries(Object.entries(source).map(([name, value]) => {
      if (!binary.has(name.toLowerCase())) return [name, value];
      const buffered = (item) => Buffer.isBuffer(item) ? Buffer.from(item) : Buffer.from(String(item), 'utf8');
      return [name, Array.isArray(value) ? value.map(buffered) : buffered(value)];
    })));
  }
  return {
    calls,
    async factory(options) {
      calls.push(['client', options]);
      const pages = runs.shift();
      if (!pages) throw new Error('unexpected LDAP connection');
      return {
        async bind(dn, password) { calls.push(['bind', dn, password]); },
        async *searchPaginated(base, optionsForSearch) {
          calls.push(['searchPaginated', base, optionsForSearch]);
          for (const page of pages) {
            if (page instanceof Error) throw page;
            yield { searchEntries: entriesFor(page, optionsForSearch) };
          }
        },
        async unbind() { calls.push(['unbind']); },
      };
    },
  };
}

function fixture() {
  const store = new MemoryIdentityStore();
  const repository = new MemoryFederatedIdentityRepository(store, {
    disabledPasswordHash: 'unusable-directory-password',
  });
  return { store, repository };
}

async function run(provider, repository, realm, pages, calls = []) {
  const ldap = directory([pages], calls);
  return syncLdapProvider(provider, { realm, repository }, { clientFactory: ldap.factory.bind(ldap) });
}

test('LDAP sync imports mapped users and group memberships through bounded pages', async () => {
  const provider = configuredProvider();
  const { store, repository } = fixture();
  const calls = [];
  const result = await run(provider, repository, 'staff', [
    [entry('uuid-alice', 'alice')],
    [entry('uuid-bob', 'bob')],
  ], calls);

  assert.deepEqual({
    status: result.status,
    pages: result.pages,
    scanned: result.scanned,
    created: result.created,
  }, { status: 'success', pages: 2, scanned: 2, created: 2 });
  const users = await store.listUsers('staff');
  assert.deepEqual(users.map((user) => user.username), ['alice', 'bob']);
  assert.deepEqual(users[0].groups, ['/Engineering']);
  assert.equal(users[0].passwordHash, 'unusable-directory-password');
  const search = calls.find(([kind]) => kind === 'searchPaginated');
  assert.equal(search[1], provider.userBaseDn);
  assert.equal(search[2].paged.pageSize, 2);
  assert.equal(search[2].sizeLimit, 0);
  assert.equal(search[2].filter, '(&(objectClass=person)(employeeType=staff))');
  assert.deepEqual(search[2].explicitBufferAttributes, []);
});

test('LDAP sync and authentication use the identical canonical textual and binary external keys', async () => {
  for (const testCase of [
    {
      provider: configuredProvider({ id: 'text-corp' }),
      directoryEntry: entry('uuid-alice', 'alice'),
      expected: 'uuid-alice',
      explicit: [],
    },
    {
      provider: configuredProvider({
        id: 'binary-corp', external_id_attribute: 'objectGUID', binary_attributes: ['objectGUID'],
      }),
      directoryEntry: entry('unused', 'alice', { objectGUID: Buffer.from('00112233445566778899aabbccddeeff', 'hex') }),
      expected: Buffer.from('00112233445566778899aabbccddeeff', 'hex').toString('base64url'),
      explicit: ['objectGUID'],
    },
  ]) {
    const { repository } = fixture();
    const syncCalls = [];
    assert.equal((await run(testCase.provider, repository, 'staff', [[testCase.directoryEntry]], syncCalls)).status, 'success');

    const authCalls = [];
    const clients = [{
      async bind() {},
      async search(base, options) {
        authCalls.push(['search', base, options]);
        return { searchEntries: (() => {
          const binary = new Set((options.explicitBufferAttributes ?? []).map((name) => name.toLowerCase()));
          return [Object.fromEntries(Object.entries(testCase.directoryEntry).map(([name, value]) => [
            name,
            binary.has(name.toLowerCase()) && !Buffer.isBuffer(value) ? Buffer.from(String(value), 'utf8') : value,
          ]))];
        })() };
      },
      async unbind() {},
    }, {
      async bind() {},
      async unbind() {},
    }];
    const authenticated = await authenticateLdapProvider(testCase.provider, {
      login: 'alice', secret: 'directory-password',
    }, { clientFactory: async () => clients.shift() });
    assert.equal(authenticated.status, 'success');
    assert.equal(authenticated.profile.externalSubject, testCase.expected);
    assert.deepEqual(syncCalls.find(([kind]) => kind === 'searchPaginated')[2].explicitBufferAttributes, testCase.explicit);
    assert.deepEqual(authCalls.find(([kind]) => kind === 'search')[2].explicitBufferAttributes, testCase.explicit);
    assert.equal((await repository.resolve({
      realm: 'staff',
      providerId: testCase.provider.id,
      issuer: testCase.provider.url,
      externalSubject: authenticated.profile.externalSubject,
      profile: authenticated.profile,
      allowCreate: false,
    })).status, 'resolved');
  }
});

test('LDAP sync reconciles updates and renames by immutable external key without duplication', async () => {
  const provider = configuredProvider();
  const { store, repository } = fixture();
  await run(provider, repository, 'staff', [[entry('uuid-alice', 'alice')]]);
  const original = await store.findUserByLogin('staff', 'alice');

  const result = await run(provider, repository, 'staff', [[entry('uuid-alice', 'alicia', {
    displayName: 'Alicia Updated',
    memberOf: ['CN=Platform,OU=Groups,DC=example,DC=test'],
  })]]);
  const renamed = await store.findUserByLogin('staff', 'alicia');
  assert.equal(result.updated, 1);
  assert.equal(renamed.id, original.id);
  assert.equal(renamed.name, 'Alicia Updated');
  assert.deepEqual(renamed.groups, ['/Platform']);
  assert.equal(await store.findUserByLogin('staff', 'alice'), null);
  assert.equal((await store.listUsers('staff')).length, 1);
});

test('LDAP sync only re-enables accounts previously disabled by the same provider sync', async () => {
  const disablingProvider = configuredProvider();
  const disabledFixture = fixture();
  await run(disablingProvider, disabledFixture.repository, 'staff', [[
    entry('uuid-alice', 'alice'), entry('uuid-bob', 'bob'),
  ]]);
  const disabled = await run(disablingProvider, disabledFixture.repository, 'staff', [[entry('uuid-alice', 'alice')]]);
  assert.equal(disabled.disabled, 1);
  assert.equal((await disabledFixture.store.findUserByLogin('staff', 'bob')).enabled, false);

  const restored = await run(disablingProvider, disabledFixture.repository, 'staff', [[
    entry('uuid-alice', 'alice'), entry('uuid-bob', 'bob'),
  ]]);
  assert.equal(restored.updated, 1);
  assert.equal((await disabledFixture.store.findUserByLogin('staff', 'bob')).enabled, true);

  const alice = await disabledFixture.store.findUserByLogin('staff', 'alice');
  await disabledFixture.store.updateUser('staff', alice.id, { enabled: false });
  const observedAfterAdminDisable = await run(disablingProvider, disabledFixture.repository, 'staff', [[
    entry('uuid-alice', 'alice'), entry('uuid-bob', 'bob'),
  ]]);
  assert.equal(observedAfterAdminDisable.status, 'success');
  assert.equal((await disabledFixture.store.findUserByLogin('staff', 'alice')).enabled, false);
});

test('LDAP sync hard-deletes only exclusively sync-managed accounts', async () => {
  const deletingProvider = configuredProvider({ id: 'delete-corp', sync_deletion_policy: 'delete' });
  const deletedFixture = fixture();
  await run(deletingProvider, deletedFixture.repository, 'staff', [[
    entry('uuid-carol', 'carol'), entry('uuid-keeper', 'keeper'),
  ]]);
  const deleted = await run(deletingProvider, deletedFixture.repository, 'staff', [[entry('uuid-keeper', 'keeper')]]);
  assert.equal(deleted.deleted, 1);
  assert.equal(await deletedFixture.store.findUserByLogin('staff', 'carol'), null);
});

test('LDAP sync refuses deletion when local credentials, admin grants, or other links exist', async () => {
  const provider = configuredProvider({ id: 'delete-corp', sync_deletion_policy: 'delete' });
  const { store, repository } = fixture();
  await run(provider, repository, 'staff', [[
    entry('uuid-local', 'local'), entry('uuid-linked', 'linked'), entry('uuid-keeper', 'keeper'),
  ]]);
  const local = await store.findUserByLogin('staff', 'local');
  const linked = await store.findUserByLogin('staff', 'linked');
  await store.updateUser('staff', local.id, { passwordHash: 'administrator-set-password-hash' });
  await store.upsertAdminGrant('staff', local.id, ['users.read']);
  await repository.link({
    realm: 'staff', providerId: 'other-idp', issuer: 'https://idp.example.test',
    externalSubject: 'other-linked-subject', userId: linked.id,
  });

  const result = await run(provider, repository, 'staff', [[entry('uuid-keeper', 'keeper')]]);
  assert.equal(result.status, 'success');
  assert.equal(result.deleted, 0);
  assert.equal(result.deletionRefused, 2);
  assert.equal(result.disabled, 2);
  assert.equal((await store.findUserById('staff', local.id)).enabled, false);
  assert.equal((await store.findUserById('staff', linked.id)).enabled, false);
  assert.ok(await store.findAdminGrant('staff', local.id));
  assert.equal((await repository.list('staff', linked.id)).length, 2);
});

test('LDAP sync aborts reconciliation for empty and over-threshold directory views', async () => {
  const provider = configuredProvider({ sync_max_deprovision_fraction: 0.5, sync_max_deprovision_count: 100 });
  const { store, repository } = fixture();
  await run(provider, repository, 'staff', [[
    entry('uuid-alice', 'alice'), entry('uuid-bob', 'bob'), entry('uuid-carol', 'carol'),
  ]]);

  const empty = await run(provider, repository, 'staff', [[]]);
  assert.equal(empty.status, 'needs_confirmation');
  assert.deepEqual(empty.reconciliation, {
    status: 'skipped', reason: 'empty_directory_view', existing: 3, candidates: 3,
  });
  assert.equal((await store.listUsers('staff')).every((user) => user.enabled), true);

  const changedView = await run(provider, repository, 'staff', [[entry('uuid-alice', 'alice')]]);
  assert.equal(changedView.status, 'needs_confirmation');
  assert.deepEqual(changedView.reconciliation, {
    status: 'skipped', reason: 'deprovision_threshold_exceeded', existing: 3, candidates: 2,
  });
  assert.equal((await store.listUsers('staff')).every((user) => user.enabled), true);

  const absoluteProvider = configuredProvider({ sync_max_deprovision_fraction: 1, sync_max_deprovision_count: 1 });
  const absolute = await run(absoluteProvider, repository, 'staff', [[entry('uuid-alice', 'alice')]]);
  assert.equal(absolute.status, 'needs_confirmation');
  assert.equal(absolute.reconciliation.reason, 'deprovision_threshold_exceeded');
});

test('LDAP sync does not reconcile deletions after a paginated directory outage and safely resumes', async () => {
  const provider = configuredProvider();
  const { store, repository } = fixture();
  const ldap = directory([
    [[entry('uuid-alice', 'alice'), entry('uuid-bob', 'bob')]],
    [[entry('uuid-alice', 'alice', { displayName: 'Updated before outage' })], new Error('directory offline')],
    [[entry('uuid-alice', 'alice'), entry('uuid-bob', 'bob')]],
  ]);
  assert.equal((await syncLdapProvider(provider, { realm: 'staff', repository }, {
    clientFactory: ldap.factory.bind(ldap),
  })).status, 'success');
  const outage = await syncLdapProvider(provider, { realm: 'staff', repository }, {
    clientFactory: ldap.factory.bind(ldap),
  });
  assert.equal(outage.status, 'unavailable');
  assert.equal((await store.findUserByLogin('staff', 'alice')).name, 'Updated before outage');
  assert.equal((await store.findUserByLogin('staff', 'bob')).enabled, true);
  assert.equal((await syncLdapProvider(provider, { realm: 'staff', repository }, {
    clientFactory: ldap.factory.bind(ldap),
  })).status, 'success');
  assert.equal((await store.listUsers('staff')).length, 2);
});

test('LDAP sync reconciliation is isolated to the selected realm', async () => {
  const provider = configuredProvider();
  const { store, repository } = fixture();
  await run(provider, repository, 'staff', [[entry('shared-subject', 'alice'), entry('staff-keeper', 'staff-keeper')]]);
  await run(provider, repository, 'contractors', [[entry('shared-subject', 'alice')]]);
  const staff = await store.findUserByLogin('staff', 'alice');
  const contractor = await store.findUserByLogin('contractors', 'alice');
  assert.notEqual(staff.id, contractor.id);

  await run(provider, repository, 'staff', [[entry('staff-keeper', 'staff-keeper')]]);
  assert.equal((await store.findUserByLogin('staff', 'alice')).enabled, false);
  assert.equal((await store.findUserByLogin('contractors', 'alice')).enabled, true);
});

test('LDAP sync refuses to auto-link colliding local accounts', async () => {
  const provider = configuredProvider();
  const { store, repository } = fixture();
  const local = await store.createUser({
    realm: 'staff', username: 'alice', email: 'alice@example.test', passwordHash: 'local-password-hash',
  });
  const result = await run(provider, repository, 'staff', [[entry('directory-alice', 'alice')]]);
  assert.equal(result.conflicts, 1);
  assert.equal((await store.listUsers('staff')).length, 1);
  assert.deepEqual(await repository.list('staff', local.id), []);
});

test('LDAP sync rejects plaintext transport even when configuration parsing is bypassed', async () => {
  const provider = { ...configuredProvider(), url: 'ldap://directory.example.test:389', startTls: false };
  const { repository } = fixture();
  let connected = false;
  const result = await syncLdapProvider(provider, { realm: 'staff', repository }, {
    clientFactory: async () => { connected = true; },
  });
  assert.equal(result.status, 'failed');
  assert.equal(result.error.code, 'AUTHME_LDAP_CONFIGURATION_INVALID');
  assert.equal(connected, false);
});
