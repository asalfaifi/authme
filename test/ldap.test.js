import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  authenticateLdapProvider,
  createLdapExtension,
  escapeLdapFilterValue,
  parseLdapProviders,
} from '../src/federation/ldap.js';

function configuration(overrides = {}) {
  return JSON.stringify({
    staff: [{
      id: 'corp',
      display_name: 'Corporate directory',
      url: 'ldaps://directory.example.test:636',
      bind_dn: 'cn=reader,dc=example,dc=test',
      bind_password: 'reader-secret',
      user_base_dn: 'ou=people,dc=example,dc=test',
      ...overrides,
    }],
  });
}

test('LDAP provider configuration requires authenticated transport and complete service credentials', () => {
  assert.throws(
    () => parseLdapProviders(configuration({ url: 'ldap://directory.example.test:389' }), { realms: ['staff'], devMode: false }),
    /must use ldaps:\/\/ or StartTLS/,
  );
  assert.throws(
    () => parseLdapProviders(configuration({ bind_password: undefined }), { realms: ['staff'], devMode: false }),
    /both bind_dn and bind_password/,
  );
  assert.throws(
    () => parseLdapProviders(configuration({ allow_insecure_development: true }), { realms: ['staff'], devMode: false }),
    /limited to development loopback/,
  );
  const parsed = parseLdapProviders(configuration({
    url: 'ldap://directory.example.test:389', start_tls: true,
  }), { realms: ['staff'], devMode: false });
  assert.equal(parsed.staff[0].startTls, true);
  assert.equal(parsed.staff[0].jitProvisioning, false);
  assert.equal(Object.isFrozen(parsed.staff[0]), true);
});

test('LDAP filter values are escaped against wildcard and parenthesis injection', () => {
  assert.equal(escapeLdapFilterValue('a*)(uid=*)'), 'a\\2a\\29\\28uid=\\2a\\29');
  assert.equal(escapeLdapFilterValue('ümlaut'), '\\c3\\bcmlaut');
});

test('LDAP authentication searches narrowly, binds as the user, and maps AD groups', async () => {
  const [provider] = parseLdapProviders(configuration({ jit_provisioning: true }), { realms: ['staff'], devMode: false }).staff;
  const calls = [];
  const clients = [
    {
      async bind(dn, password) { calls.push(['service-bind', dn, password]); },
      async search(base, options) {
        calls.push(['search', base, options]);
        return { searchEntries: [{
          dn: 'uid=alice,ou=people,dc=example,dc=test',
          uid: 'alice', mail: 'alice@example.test', displayName: 'Alice Example',
          entryUUID: 'directory-alice', memberOf: ['CN=Engineering,OU=Groups,DC=example,DC=test'],
        }] };
      },
      async unbind() { calls.push(['service-unbind']); },
    },
    {
      async bind(dn, password) { calls.push(['user-bind', dn, password]); },
      async unbind() { calls.push(['user-unbind']); },
    },
  ];
  const result = await authenticateLdapProvider(provider, {
    login: 'alice*)(uid=*)', secret: 'correct horse battery staple',
  }, { clientFactory: async (options) => { calls.push(['client', options]); return clients.shift(); } });

  assert.equal(result.status, 'success');
  assert.equal(result.providerId, 'corp');
  assert.equal(result.protocol, 'ldap');
  assert.equal(result.issuer, 'ldaps://directory.example.test:636');
  assert.equal(result.allowCreate, true);
  assert.deepEqual(result.profile, {
    externalSubject: 'directory-alice', username: 'alice', email: 'alice@example.test', emailVerified: false,
    name: 'Alice Example', givenName: '', familyName: '', groups: ['/Engineering'], roles: [],
  });
  const search = calls.find(([kind]) => kind === 'search');
  assert.match(search[2].filter, /alice\\2a\\29\\28uid=\\2a\\29/);
  assert.equal(search[2].sizeLimit, 2);
  assert.deepEqual(calls.find(([kind]) => kind === 'user-bind').slice(1), [
    'uid=alice,ou=people,dc=example,dc=test', 'correct horse battery staple',
  ]);
  assert.equal(calls.filter(([kind]) => kind.endsWith('unbind')).length, 2);
  assert.equal(calls[0][1].tlsOptions.rejectUnauthorized, true);
});

test('LDAP authentication fails closed on ambiguous results and directory outages', async () => {
  const [provider] = parseLdapProviders(configuration({ bind_dn: undefined, bind_password: undefined }), { realms: ['staff'], devMode: false }).staff;
  let unbound = false;
  assert.deepEqual(await authenticateLdapProvider(provider, { login: 'alice', secret: 'secret' }, {
    clientFactory: async () => ({
      async search() { return { searchEntries: [{ dn: 'uid=one' }, { dn: 'uid=two' }] }; },
      async unbind() { unbound = true; },
    }),
  }), { status: 'failure' });
  assert.equal(unbound, true);

  const outage = new Error('connection refused');
  const result = await authenticateLdapProvider(provider, { login: 'alice', secret: 'secret' }, {
    clientFactory: async () => { throw outage; },
  });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.error, outage);
});

test('LDAP is a realm-scoped credential extension', async () => {
  const providersByRealm = parseLdapProviders(configuration(), { realms: ['master', 'staff'], devMode: false });
  const extension = createLdapExtension({ providersByRealm, clientFactory: async () => { throw new Error('offline'); } });
  assert.equal(extension.implementation.enabledFor('master'), false);
  assert.equal(extension.implementation.enabledFor('staff'), true);
  assert.equal((await extension.implementation.authenticate({ realm: 'master', login: 'a', secret: 'b' })).status, 'failure');
});

test('StartTLS failures close clients and LDAP logs omit upstream error details', async () => {
  const [provider] = parseLdapProviders(configuration({
    url: 'ldap://directory.example.test:389', start_tls: true,
  }), { realms: ['staff'], devMode: false }).staff;
  const upstream = Object.assign(new Error('reader-secret was rejected'), {
    code: 'ECONNRESET', bindPassword: 'reader-secret',
  });
  let unbound = 0;
  const warnings = [];
  const extension = createLdapExtension({
    providersByRealm: { staff: [provider] },
    clientFactory: async () => ({
      async startTLS() { throw upstream; },
      async unbind() { unbound += 1; },
    }),
    logger: { warn: (...values) => warnings.push(values) },
  });
  assert.equal((await extension.implementation.authenticate({ realm: 'staff', login: 'alice', secret: 'secret' })).status, 'unavailable');
  assert.equal(unbound, 1);
  assert.deepEqual(warnings[0][0].error, { name: 'Error', code: 'ECONNRESET' });
  assert.doesNotMatch(JSON.stringify(warnings), /reader-secret|bindPassword/);
});
