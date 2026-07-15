import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { parseLdapProviders } from '../src/federation/ldap.js';
import { parseOidcProviders } from '../src/federation/oidc.js';
import { parseSamlProviders } from '../src/federation/saml-config.js';
import {
  KeycloakImportError,
  formatCompatibilityReport,
  stableJsonStringify,
  transformKeycloakRealm,
} from '../src/migration/keycloak-import.js';
import { validateClientSecurity } from '../src/provider.js';

const sourceSecrets = {
  client: 'keycloak-client-secret-do-not-copy',
  password: 'keycloak-password-hash-do-not-copy',
  idp: 'keycloak-idp-secret-do-not-copy',
  ldap: 'keycloak-bind-secret-do-not-copy',
  key: 'keycloak-private-key-do-not-copy',
};

function realmExport(overrides = {}) {
  return {
    realm: 'acme',
    displayName: 'Acme',
    enabled: true,
    accessTokenLifespan: 600,
    accessCodeLifespan: 90,
    ssoSessionIdleTimeout: 7200,
    ssoSessionMaxLifespan: 36_000,
    defaultDefaultClientScopes: ['profile', 'email', 'roles'],
    defaultOptionalClientScopes: ['offline_access'],
    clientScopes: [{
      name: 'roles',
      protocol: 'openid-connect',
      protocolMappers: [{
        name: 'realm roles',
        protocol: 'openid-connect',
        protocolMapper: 'oidc-usermodel-realm-role-mapper',
        config: { 'claim.name': 'realm_access.roles' },
      }],
    }],
    clients: [{
      clientId: 'orders-web',
      name: 'Orders web application',
      enabled: true,
      protocol: 'openid-connect',
      publicClient: false,
      clientAuthenticatorType: 'client-secret',
      secret: sourceSecrets.client,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: true,
      serviceAccountsEnabled: true,
      redirectUris: ['https://orders.example.test/callback', 'https://orders.example.test/*'],
      webOrigins: ['https://orders.example.test', '*'],
      defaultClientScopes: ['profile', 'email', 'roles'],
      optionalClientScopes: ['offline_access'],
      attributes: {
        'pkce.code.challenge.method': 'plain',
        'post.logout.redirect.uris': 'https://orders.example.test/signed-out##+',
      },
      protocolMappers: [{
        name: 'groups',
        protocol: 'openid-connect',
        protocolMapper: 'oidc-group-membership-mapper',
        config: { 'full.path': 'true' },
      }, {
        name: 'custom script',
        protocol: 'openid-connect',
        protocolMapper: 'oidc-script-based-protocol-mapper',
        config: { script: 'doSomething()' },
      }],
    }],
    roles: {
      realm: [{ name: 'member' }, {
        name: 'employee',
        composite: true,
        composites: { realm: ['member'] },
      }],
      client: {
        'orders-api': [{ name: 'orders.read' }, { name: 'orders.refund' }],
      },
    },
    groups: [{
      id: '10000000-0000-4000-8000-000000000001',
      name: 'engineering',
      attributes: { costCenter: ['42'] },
      realmRoles: ['member'],
      subGroups: [{
        id: '10000000-0000-4000-8000-000000000002',
        name: 'platform',
        clientRoles: { 'orders-api': ['orders.read'] },
      }],
    }],
    identityProviders: [{
      alias: 'corporate-oidc',
      displayName: 'Corporate login',
      providerId: 'oidc',
      enabled: true,
      config: {
        issuer: 'https://idp.example.test',
        authorizationUrl: 'https://idp.example.test/authorize',
        tokenUrl: 'https://idp.example.test/token',
        jwksUrl: 'https://idp.example.test/jwks',
        userInfoUrl: 'https://idp.example.test/userinfo',
        clientId: 'authme-broker',
        clientSecret: sourceSecrets.idp,
        clientAuthMethod: 'client_secret_basic',
        defaultScope: 'openid profile email',
      },
    }, {
      alias: 'github',
      providerId: 'github',
      enabled: true,
      config: { clientSecret: 'another-secret-not-to-report' },
    }],
    identityProviderMappers: [{
      name: 'groups claim',
      identityProviderAlias: 'corporate-oidc',
      identityProviderMapper: 'oidc-user-attribute-idp-mapper',
      config: { claim: 'member_of', 'user.attribute': 'groups' },
    }],
    components: {
      'org.keycloak.keys.KeyProvider': [{
        id: 'realm-key',
        name: 'rsa-generated',
        providerId: 'rsa-generated',
        config: { privateKey: [sourceSecrets.key] },
      }],
      'org.keycloak.storage.UserStorageProvider': [{
        id: 'ldap-component',
        name: 'corporate-directory',
        providerId: 'ldap',
        config: {
          enabled: ['true'],
          connectionUrl: ['ldaps://directory.example.test:636'],
          usersDn: ['ou=people,dc=example,dc=test'],
          bindDn: ['cn=reader,dc=example,dc=test'],
          bindCredential: [sourceSecrets.ldap],
          usernameLDAPAttribute: ['uid'],
          uuidLDAPAttribute: ['entryUUID'],
          userObjectClasses: ['inetOrgPerson, organizationalPerson'],
          importEnabled: ['true'],
        },
      }],
      'org.keycloak.storage.ldap.mappers.LDAPStorageMapper': [{
        id: 'ldap-email-mapper',
        parentId: 'ldap-component',
        name: 'email',
        providerId: 'user-attribute-ldap-mapper',
        config: {
          'user.model.attribute': ['email'],
          'ldap.attribute': ['mail'],
        },
      }],
    },
    users: [{
      id: '9af751a0-5842-4c56-8f21-6aa4319a3a25',
      username: 'sam',
      email: 'Sam@Example.Test',
      emailVerified: true,
      firstName: 'Sam',
      lastName: 'Example',
      enabled: true,
      attributes: {
        department: ['engineering'],
        apiToken: ['must-not-be-copied'],
      },
      realmRoles: ['employee'],
      clientRoles: { 'orders-api': ['orders.refund'] },
      groups: ['/engineering/platform'],
      requiredActions: ['UPDATE_PASSWORD'],
      credentials: [{
        id: 'credential-id',
        type: 'password',
        credentialData: '{"algorithm":"pbkdf2-sha256"}',
        secretData: sourceSecrets.password,
      }, { type: 'otp', secretData: 'otp-seed-do-not-copy' }],
      federatedIdentities: [{
        identityProvider: 'corporate-oidc',
        userId: 'upstream-subject-123',
        userName: 'sam@example.test',
      }],
    }],
    authenticationFlows: [{ alias: 'browser', providerId: 'basic-flow' }],
    passwordPolicy: 'length(14)',
    smtpServer: { host: 'smtp.example.test', password: 'smtp-secret-do-not-report' },
    ...overrides,
  };
}

test('maps realm, client, roles, nested groups, users, and group-derived assignments', () => {
  const { config, report } = transformKeycloakRealm(realmExport(), {
    publicUrl: 'https://login.example.test',
  });

  assert.deepEqual(config.realm, {
    name: 'acme',
    displayName: 'Acme',
    enabled: true,
    issuer: 'https://login.example.test/realms/acme',
    tokenLifetimes: { accessToken: 600, authorizationCode: 90, session: 7200 },
  });
  assert.equal(config.environment.AUTHME_REALMS, 'acme');
  assert.deepEqual(config.environment.AUTHME_CLIENTS_JSON.acme, config.clients);
  assert.deepEqual(config.clients, [{
    client_id: 'orders-web',
    client_name: 'Orders web application',
    token_endpoint_auth_method: 'client_secret_basic',
    client_secret: '__ROTATE__',
    redirect_uris: ['https://orders.example.test/callback'],
    post_logout_redirect_uris: ['https://orders.example.test/signed-out'],
    web_origins: ['https://orders.example.test'],
    response_types: ['code'],
    grant_types: ['authorization_code', 'client_credentials', 'refresh_token'],
    application_type: 'web',
    scope: 'email groups offline_access openid profile roles',
  }]);
  assert.deepEqual(config.roles.realm.map(({ name }) => name), ['employee', 'member']);
  assert.deepEqual(config.roles.clients['orders-api'].map(({ name }) => name), ['orders.read', 'orders.refund']);
  assert.deepEqual(config.groups.map(({ path }) => path), ['/engineering', '/engineering/platform']);
  assert.equal(config.groups[1].parentPath, '/engineering');

  assert.equal(config.users.length, 1);
  assert.deepEqual(config.users[0], {
    id: '9af751a0-5842-4c56-8f21-6aa4319a3a25',
    realm: 'acme',
    username: 'sam',
    email: 'sam@example.test',
    emailVerified: true,
    name: 'Sam Example',
    givenName: 'Sam',
    familyName: 'Example',
    enabled: true,
    attributes: { department: ['engineering'] },
    roles: ['employee', 'member'],
    groups: ['/engineering/platform'],
    clientRoles: { 'orders-api': ['orders.read', 'orders.refund'] },
    credentialMigration: { password: 'reset-required', mfa: 'reenrollment-required' },
  });
  assert.ok(report.summary.mapped > 0);
  assert.ok(report.summary.transformedWithWarnings > 0);
  assert.ok(report.summary.unsupportedOrSkipped > 0);
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(report), true);
});

test('maps OIDC and LDAP federation without copying source secrets', () => {
  const { config, report } = transformKeycloakRealm(realmExport(), {
    publicUrl: 'https://login.example.test',
  });

  assert.deepEqual(config.federation.oidc, [{
    id: 'corporate-oidc',
    display_name: 'Corporate login',
    issuer: 'https://idp.example.test',
    authorization_endpoint: 'https://idp.example.test/authorize',
    token_endpoint: 'https://idp.example.test/token',
    jwks_uri: 'https://idp.example.test/jwks',
    userinfo_endpoint: 'https://idp.example.test/userinfo',
    client_id: 'authme-broker',
    client_secret: '__ROTATE__',
    token_endpoint_auth_method: 'client_secret_basic',
    scopes: ['email', 'openid', 'profile'],
    groups_claim: 'member_of',
    require_email: true,
    jit_provisioning: true,
  }]);
  assert.deepEqual(config.federation.ldap, [{
    id: 'corporate-directory',
    display_name: 'corporate-directory',
    url: 'ldaps://directory.example.test:636',
    start_tls: false,
    bind_dn: 'cn=reader,dc=example,dc=test',
    bind_password: '__ROTATE__',
    user_base_dn: 'ou=people,dc=example,dc=test',
    user_object_class: 'inetOrgPerson',
    login_attributes: ['mail', 'sAMAccountName', 'uid', 'userPrincipalName'],
    username_attribute: 'uid',
    email_attribute: 'mail',
    display_name_attribute: 'displayName',
    given_name_attribute: 'givenName',
    family_name_attribute: 'sn',
    external_id_attribute: 'entryUUID',
    groups_attribute: 'memberOf',
    jit_provisioning: true,
  }]);
  assert.deepEqual(config.federation.federatedIdentities, [{
    realm: 'acme',
    userId: '9af751a0-5842-4c56-8f21-6aa4319a3a25',
    providerId: 'corporate-oidc',
    issuer: 'https://idp.example.test',
    externalSubject: 'upstream-subject-123',
  }]);

  const configJson = JSON.stringify(config);
  const reportJson = JSON.stringify(report);
  for (const secret of Object.values(sourceSecrets)) {
    assert.equal(configJson.includes(secret), false);
    assert.equal(reportJson.includes(secret), false);
  }
  assert.equal(configJson.includes('must-not-be-copied'), false);
  assert.equal(reportJson.includes('smtp-secret-do-not-report'), false);
});

test('emits client and federation fragments accepted by AuthMe parsers after secret injection', () => {
  const { config } = transformKeycloakRealm(realmExport(), {
    publicUrl: 'https://login.example.test',
  });
  const client = { ...config.clients[0], client_secret: 's'.repeat(32) };
  assert.doesNotThrow(() => validateClientSecurity(client));
  assert.throws(() => validateClientSecurity(config.clients[0]), /at least 32 bytes/u);

  const oidc = parseOidcProviders(JSON.stringify(config.environment.AUTHME_OIDC_PROVIDERS_JSON), {
    realms: ['acme'], devMode: false,
  });
  const ldap = parseLdapProviders(JSON.stringify(config.environment.AUTHME_LDAP_PROVIDERS_JSON), {
    realms: ['acme'], devMode: false,
  });
  const saml = parseSamlProviders(JSON.stringify(config.environment.AUTHME_SAML_PROVIDERS_JSON), {
    realms: ['acme'], publicUrl: 'https://login.example.test',
  });
  assert.equal(oidc.acme[0].issuer, 'https://idp.example.test');
  assert.equal(ldap.acme[0].url, 'ldaps://directory.example.test:636');
  assert.deepEqual(saml.acme, []);
});

test('skips public service-account clients and keeps client_credentials confidential', () => {
  const source = realmExport({
    clients: [{
      clientId: 'public-service',
      protocol: 'openid-connect',
      publicClient: true,
      clientAuthenticatorType: 'client-secret',
      standardFlowEnabled: true,
      serviceAccountsEnabled: true,
      redirectUris: ['https://public.example.test/callback'],
    }, {
      clientId: 'public-browser',
      protocol: 'openid-connect',
      publicClient: true,
      clientAuthenticatorType: 'client-secret',
      standardFlowEnabled: true,
      serviceAccountsEnabled: false,
      redirectUris: ['https://public.example.test/callback'],
    }, {
      clientId: 'confidential-service',
      protocol: 'openid-connect',
      publicClient: false,
      clientAuthenticatorType: 'client-secret',
      standardFlowEnabled: false,
      serviceAccountsEnabled: true,
    }],
  });

  const { config, report } = transformKeycloakRealm(source, {
    publicUrl: 'https://login.example.test',
  });
  assert.deepEqual(config.clients.map(({ client_id }) => client_id), ['confidential-service', 'public-browser']);
  assert.equal(config.clients.find(({ client_id }) => client_id === 'public-browser').token_endpoint_auth_method, 'none');
  const serviceClients = config.clients.filter(({ grant_types }) => grant_types.includes('client_credentials'));
  assert.equal(serviceClients.length, 1);
  for (const client of serviceClients) {
    assert.notEqual(client.token_endpoint_auth_method, 'none');
    assert.ok(['client_secret_basic', 'client_secret_jwt', 'private_key_jwt', 'tls_client_auth']
      .includes(client.token_endpoint_auth_method));
  }
  assert.ok(report.unsupportedOrSkipped.some(({ item, reason }) =>
    item === 'public-service'
      && /skipped.*service account.*confidential client authentication.*never receive client_credentials/iu.test(reason)));
});

test('reports unsupported features and renders a deterministic human summary', () => {
  const { report } = transformKeycloakRealm(realmExport(), { publicUrl: 'https://login.example.test' });
  const reasons = report.unsupportedOrSkipped.map(({ reason }) => reason).join('\n');
  assert.match(reasons, /password\/direct-access grant/u);
  assert.match(reasons, /Implicit|Custom, scripted|claim transforms/u);
  assert.match(reasons, /Custom authentication flows/u);
  assert.match(reasons, /password-policy expressions/u);
  assert.match(reasons, /Provider type github/u);
  assert.match(reasons, /password hash records are not portable/u);

  const human = formatCompatibilityReport(report);
  assert.match(human, /^Keycloak compatibility report\nRealm: acme\nSummary:/u);
  assert.match(human, /Mapped \(\d+\)/u);
  assert.match(human, /Transformed with warnings \(\d+\)/u);
  assert.match(human, /Unsupported or skipped \(\d+\)/u);
  for (const secret of Object.values(sourceSecrets)) assert.equal(human.includes(secret), false);
  assert.equal(human, formatCompatibilityReport(report));
});

test('supports partial exports while retaining undefined group paths with a warning', () => {
  const partial = realmExport({
    clients: undefined,
    clientScopes: undefined,
    roles: undefined,
    groups: undefined,
    identityProviders: undefined,
    identityProviderMappers: undefined,
    components: undefined,
    users: [{
      username: 'partial-user',
      email: 'partial@example.test',
      groups: ['/external/group'],
    }],
  });
  const { config, report } = transformKeycloakRealm(partial);
  assert.equal(config.realm.issuer, null);
  assert.equal(config.environment.AUTHME_PUBLIC_URL, undefined);
  assert.equal(config.users[0].id, 'c0726883-6668-56a1-b3c8-789b205cee29');
  assert.deepEqual(config.users[0].groups, ['/external/group']);
  assert.ok(report.transformedWithWarnings.some(({ category, reason }) =>
    category === 'group-membership' && /partial-export compatibility/u.test(reason)));
});

test('fails closed on malformed realm exports with precise paths', () => {
  assert.throws(() => transformKeycloakRealm(null), (error) => {
    assert.equal(error instanceof KeycloakImportError, true);
    assert.equal(error.code, 'KEYCLOAK_IMPORT_INVALID');
    assert.equal(error.path, '$');
    return true;
  });
  assert.throws(() => transformKeycloakRealm({}), /at realm: must be a non-empty string/u);
  assert.throws(() => transformKeycloakRealm({ realm: 'Acme' }), /lowercase letter/u);
  assert.throws(() => transformKeycloakRealm({ realm: 'acme', clients: {} }), /at clients: must be an array/u);
  assert.throws(() => transformKeycloakRealm({
    realm: 'acme',
    clients: [{ clientId: 'one' }, { clientId: 'one' }],
  }), /duplicates client one/u);
  assert.throws(() => transformKeycloakRealm({
    realm: 'acme',
    users: [{ username: 'sam', email: 'sam@example.test', enabled: 'true' }],
  }), /users\[0\]\.enabled: must be a boolean/u);
});

test('rejects prototype-shaped role namespaces without prototype pollution', () => {
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
  assert.equal({}.polluted, undefined);

  const cases = [{
    key: '__proto__',
    path: 'users[0].clientRoles.__proto__',
    insert(source, record) { source.users[0].clientRoles = record; },
  }, {
    key: 'constructor',
    path: 'users[0].clientRoles.constructor',
    insert(source, record) { source.users[0].clientRoles = record; },
  }, {
    key: '__proto__',
    path: 'groups[0].clientRoles.__proto__',
    insert(source, record) { source.groups[0].clientRoles = record; },
  }, {
    key: 'constructor',
    path: 'roles.client.constructor',
    insert(source, record) { source.roles.client = record; },
  }];
  for (const { key, path, insert } of cases) {
    const source = realmExport();
    insert(source, JSON.parse(`{${JSON.stringify(key)}:["polluted"]}`));
    assert.throws(() => transformKeycloakRealm(source), (error) => {
      assert.equal(error instanceof KeycloakImportError, true);
      assert.equal(error.name, 'KeycloakImportError');
      assert.match(error.message, /prototype-shaped record namespace key/u);
      assert.equal(error.path, path);
      return true;
    });
    assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
    assert.equal({}.polluted, undefined);
  }
});

test('transformation and JSON serialization are deterministic and do not mutate input', () => {
  const input = realmExport();
  const snapshot = structuredClone(input);
  const first = transformKeycloakRealm(input, { publicUrl: 'https://login.example.test' });
  const second = transformKeycloakRealm(input, { publicUrl: 'https://login.example.test' });
  assert.deepEqual(first, second);
  assert.equal(stableJsonStringify(first), stableJsonStringify(second));
  assert.deepEqual(input, snapshot);
  assert.equal(stableJsonStringify({ z: 1, a: { y: 2, b: 3 } }), '{\n  "a": {\n    "b": 3,\n    "y": 2\n  },\n  "z": 1\n}\n');
});

test('CLI is dry-run by default and writes config plus both reports only with --write', async (context) => {
  const directory = await mkdtemp(join(tmpdir(), 'authme-kc-import-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const input = join(directory, 'realm.json');
  await writeFile(input, JSON.stringify(realmExport({ components: [], identityProviders: [], identityProviderMappers: [] })));

  const dryRun = spawnSync(process.execPath, [
    'scripts/kc-import.mjs', input, '--public-url', 'https://login.example.test',
  ], { cwd: process.cwd(), encoding: 'utf8' });
  assert.equal(dryRun.status, 0, dryRun.stderr);
  const dryRunJson = JSON.parse(dryRun.stdout);
  assert.equal(dryRunJson.config.realm.name, 'acme');
  assert.equal(dryRunJson.report.realm, 'acme');
  assert.match(dryRun.stderr, /Keycloak compatibility report/u);
  await assert.rejects(readFile(join(directory, 'realm.authme.json')), /ENOENT/u);

  const written = spawnSync(process.execPath, [
    'scripts/kc-import.mjs', input, '--public-url', 'https://login.example.test', '--write',
  ], { cwd: process.cwd(), encoding: 'utf8' });
  assert.equal(written.status, 0, written.stderr);
  const config = JSON.parse(await readFile(join(directory, 'realm.authme.json'), 'utf8'));
  const report = JSON.parse(await readFile(join(directory, 'realm.compatibility.json'), 'utf8'));
  const human = await readFile(join(directory, 'realm.compatibility.txt'), 'utf8');
  assert.equal(config.realm.name, 'acme');
  assert.equal(report.realm, 'acme');
  assert.match(human, /Unsupported or skipped/u);
});
