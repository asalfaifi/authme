import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import request from 'supertest';
import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34997';
const host = new URL(base).host;
const token = 'authme-management-admin-token-000000000001';
let runtime;

function api(method, path, body) {
  const call = request(runtime.app)[method](path).set('host', host).set('authorization', `Bearer ${token}`);
  return body === undefined ? call : call.set('content-type', 'application/json').send(body);
}

before(async () => {
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true', AUTHME_PUBLIC_URL: base, AUTHME_PORT: '34997', AUTHME_LOG_LEVEL: 'silent', AUTHME_ADMIN_TOKEN: token,
  }));
});
after(async () => runtime?.close());

test('managed clients are validated, live immediately, listed without secrets, and revocable', async () => {
  const metadata = {
    client_id: 'managed-native', client_name: 'Managed native', application_type: 'native',
    token_endpoint_auth_method: 'none', redirect_uris: ['http://127.0.0.1:49001/callback'],
    response_types: ['code'], grant_types: ['authorization_code'],
  };
  const created = await api('post', '/admin/v1/realms/master/clients', metadata).expect(201);
  assert.equal(created.body.managed, true);
  assert.equal(created.body.client_secret, undefined);
  assert.equal((await runtime.providers.get('master').Client.find('managed-native')).clientId, 'managed-native');
  const scope = await runtime.data.management.createClientScope('master', { name: 'managed-policy', description: '', protocol: 'openid-connect', attributes: {} });
  await runtime.data.management.setClientScopeAssignment('master', 'managed-native', scope.id, 'default');
  await runtime.data.management.createClaimMapper('master', { ownerType: 'client', ownerId: 'managed-native', name: 'managed-claim', mapperType: 'hardcoded', config: { claim: 'managed_claim', value: true } });
  await api('put', '/admin/v1/realms/master/clients/managed-native/roles/read', {
    description: 'Read', composites: [], attributes: {},
  }).expect(201);
  await api('post', '/admin/v1/realms/master/authentication-flows', {
    alias: 'managed-native-only', enabled: true, priority: 5, clientIds: ['managed-native'],
    acr: 'urn:authme:managed-native', maxAgeSeconds: 300,
    steps: [{ type: 'password', requirement: 'required' }],
  }).expect(201);
  assert((await request(runtime.app).get('/realms/master/.well-known/openid-configuration')
    .set('host', host).expect(200)).body.acr_values_supported.includes('urn:authme:managed-native'));
  const assigned = await api('post', '/admin/v1/realms/master/users', {
    username: 'managed-client-role', email: 'managed-client-role@example.test', password: 'Correct-Horse-Battery-Staple-2026!',
    roles: [], groups: [], clientRoles: { 'managed-native': ['read'] },
  }).expect(201);
  const assignedVersion = (await runtime.store.findUserById('master', assigned.body.id)).securityVersion;
  const inventory = await api('get', '/admin/v1/realms/master/clients').expect(200);
  assert(inventory.body.clients.some((client) => client.client_id === 'managed-native' && client.managed));
  await api('delete', '/admin/v1/realms/master/clients/managed-native', {}).expect(204);
  assert.equal(await runtime.providers.get('master').Client.find('managed-native'), undefined);
  assert.deepEqual(await runtime.data.management.listClientScopeAssignments('master', 'managed-native'), []);
  assert.deepEqual(await runtime.data.management.listClaimMappers('master', 'client', 'managed-native'), []);
  assert.deepEqual(await runtime.data.management.listClientRoles('master', 'managed-native'), []);
  assert.equal((await runtime.data.management.listAuthenticationFlows('master'))
    .some(({ acr }) => acr === 'urn:authme:managed-native'), false);
  assert.equal((await request(runtime.app).get('/realms/master/.well-known/openid-configuration')
    .set('host', host).expect(200)).body.acr_values_supported.includes('urn:authme:managed-native'), false);
  const reconciled = await runtime.store.findUserById('master', assigned.body.id);
  assert.deepEqual(reconciled.clientRoles, {});
  assert(reconciled.securityVersion > assignedVersion);
  await api('post', '/admin/v1/realms/master/clients', { ...metadata, client_id: 'authme-admin-console' }).expect(409);
});

test('policy writes fail closed when their managed client disappears mid-request', async () => {
  const nativeClient = (clientId, port) => ({
    client_id: clientId,
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    redirect_uris: [`http://127.0.0.1:${port}/callback`],
    response_types: ['code'],
    grant_types: ['authorization_code'],
  });
  const scopeClientId = 'scope-lifecycle-client';
  const mapperClientId = 'mapper-lifecycle-client';
  await api('post', '/admin/v1/realms/master/clients', nativeClient(scopeClientId, 49011)).expect(201);
  const scope = await runtime.data.management.createClientScope('master', {
    name: 'lifecycle-scope', description: '', protocol: 'openid-connect', attributes: {},
  });
  const setAssignment = runtime.data.management.setClientScopeAssignment
    .bind(runtime.data.management);
  runtime.data.management.setClientScopeAssignment = async (...arguments_) => {
    const result = await setAssignment(...arguments_);
    await runtime.data.deleteManagedClient('master', scopeClientId);
    return result;
  };
  try {
    await api('put', `/admin/v1/realms/master/clients/${scopeClientId}/client-scopes/${scope.id}`, {
      assignmentType: 'default',
    }).expect(409);
  } finally {
    runtime.data.management.setClientScopeAssignment = setAssignment;
  }
  assert.deepEqual(await runtime.data.management.listClientScopeAssignments('master', scopeClientId), []);

  await api('post', '/admin/v1/realms/master/clients', nativeClient(mapperClientId, 49012)).expect(201);
  const createMapper = runtime.data.management.createClaimMapper.bind(runtime.data.management);
  runtime.data.management.createClaimMapper = async (...arguments_) => {
    const mapper = await createMapper(...arguments_);
    await runtime.data.deleteManagedClient('master', mapperClientId);
    return mapper;
  };
  try {
    await api('post', '/admin/v1/realms/master/claim-mappers', {
      ownerType: 'client', ownerId: mapperClientId, name: 'lifecycle-mapper',
      mapperType: 'hardcoded', config: { claim: 'lifecycle', value: true },
    }).expect(409);
  } finally {
    runtime.data.management.createClaimMapper = createMapper;
  }
  assert.deepEqual(await runtime.data.management.listClaimMappers('master', 'client', mapperClientId), []);
  assert.equal(await runtime.data.upsertManagedClient('master', nativeClient(mapperClientId, 49013), {
    mode: 'update',
  }), undefined);
  assert.equal(await runtime.providers.get('master').Client.find(mapperClientId), undefined);

  const member = await runtime.store.createUser({
    realm: 'master', username: 'membership-race', email: 'membership-race@example.test', passwordHash: 'hash',
  });
  const membershipOrganization = await runtime.data.management.createOrganization('master', {
    name: 'Membership race', alias: 'membership-race', enabled: true,
    domains: [], identityProviderIds: [], attributes: {},
  });
  const upsertMembership = runtime.data.management.upsertOrganizationMembership
    .bind(runtime.data.management);
  runtime.data.management.upsertOrganizationMembership = async (...arguments_) => {
    const membership = await upsertMembership(...arguments_);
    await runtime.store.deleteUser('master', member.id);
    return membership;
  };
  try {
    await api('put', `/admin/v1/realms/master/organizations/${membershipOrganization.id}/members/${member.id}`, {
      roles: ['member'],
    }).expect(409);
  } finally {
    runtime.data.management.upsertOrganizationMembership = upsertMembership;
  }
  assert.deepEqual(
    await runtime.data.management.listOrganizationMemberships('master', membershipOrganization.id),
    [],
  );

  const invitationOrganization = await runtime.data.management.createOrganization('master', {
    name: 'Invitation race', alias: 'invitation-race', enabled: true,
    domains: [], identityProviderIds: [], attributes: {},
  });
  const createInvitation = runtime.data.management.createOrganizationInvitation
    .bind(runtime.data.management);
  runtime.data.management.createOrganizationInvitation = async (...arguments_) => {
    const invitation = await createInvitation(...arguments_);
    await runtime.data.management.deleteOrganization('master', invitationOrganization.id);
    return invitation;
  };
  try {
    await api('post', `/admin/v1/realms/master/organizations/${invitationOrganization.id}/invitations`, {
      email: 'invitation-race@example.test', roles: ['member'], expiresInSeconds: 3600,
    }).expect(409);
  } finally {
    runtime.data.management.createOrganizationInvitation = createInvitation;
  }
  assert.deepEqual(
    await runtime.data.management.listOrganizationInvitations('master', invitationOrganization.id),
    [],
  );

  await runtime.data.management.putRole('master', {
    name: 'create-race-role', description: '', composites: [], attributes: {},
  });
  const createUser = runtime.store.createUser.bind(runtime.store);
  runtime.store.createUser = async (input) => {
    const user = await createUser(input);
    await runtime.data.management.deleteRole('master', 'create-race-role');
    return user;
  };
  try {
    await api('post', '/admin/v1/realms/master/users', {
      username: 'create-policy-race', email: 'create-policy-race@example.test',
      password: 'Correct-Horse-Battery-Staple-2026!', roles: ['create-race-role'], groups: [], clientRoles: {},
    }).expect(409);
  } finally {
    runtime.store.createUser = createUser;
  }
  assert.equal(await runtime.store.findUserByLogin('master', 'create-policy-race'), null);

  await runtime.data.management.putRole('master', {
    name: 'patch-race-role', description: '', composites: [], attributes: {},
  });
  const patchRaceUser = await createUser({
    realm: 'master', username: 'patch-policy-race', email: 'patch-policy-race@example.test', passwordHash: 'hash',
  });
  const updateUser = runtime.store.updateUser.bind(runtime.store);
  runtime.store.updateUser = async (...arguments_) => {
    const user = await updateUser(...arguments_);
    if (arguments_[2]?.roles?.includes('patch-race-role')) {
      await runtime.data.management.deleteRole('master', 'patch-race-role');
    }
    return user;
  };
  try {
    await api('patch', `/admin/v1/realms/master/users/${patchRaceUser.id}`, {
      roles: ['patch-race-role'],
    }).expect(409);
  } finally {
    runtime.store.updateUser = updateUser;
  }
  assert.deepEqual((await runtime.store.findUserById('master', patchRaceUser.id)).roles, []);
});

test('realm, role, nested group, scope, mapper, flow, and organization APIs are mutable and realm-scoped', async () => {
  await api('put', '/admin/v1/realms/master/roles/reader', { description: 'Read', composites: [], attributes: {} }).expect(201);
  await api('put', '/admin/v1/realms/master/roles/editor', { description: 'Edit', composites: ['reader'], attributes: {} }).expect(201);
  const group = await api('post', '/admin/v1/realms/master/groups', { name: 'engineering', parentId: null, roles: ['editor'], attributes: {} }).expect(201);
  assert.equal(group.body.path, '/engineering');
  const managedUser = await api('post', '/admin/v1/realms/master/users', {
    username: 'managed-relations', email: 'managed-relations@example.test', password: 'Correct-Horse-Battery-Staple-2026!',
    roles: ['editor'], groups: ['/engineering'], clientRoles: {},
  }).expect(201);
  await api('post', '/admin/v1/realms/master/users', {
    username: 'orphan-relations', email: 'orphan-relations@example.test', password: 'Correct-Horse-Battery-Staple-2026!',
    roles: ['missing-role'], groups: [], clientRoles: {},
  }).expect(400);
  await api('post', '/admin/v1/realms/master/users', {
    username: 'orphan-client-role', email: 'orphan-client-role@example.test', password: 'Correct-Horse-Battery-Staple-2026!',
    roles: [], groups: [], clientRoles: { 'missing-client': ['read'] },
  }).expect(400);
  const securityVersionBeforeMove = (await runtime.store.findUserById('master', managedUser.body.id)).securityVersion;
  await api('patch', `/admin/v1/realms/master/groups/${group.body.id}`, { name: 'platform' }).expect(200);
  const rewrittenUser = await api('get', `/admin/v1/realms/master/users/${managedUser.body.id}`).expect(200);
  assert.deepEqual(rewrittenUser.body.groups, ['/platform']);
  assert((await runtime.store.findUserById('master', managedUser.body.id)).securityVersion > securityVersionBeforeMove);
  await api('patch', `/admin/v1/realms/master/groups/${group.body.id}`, { roles: ['missing-role'] }).expect(400);
  await api('delete', '/admin/v1/realms/master/roles/editor', {}).expect(204);
  assert.deepEqual((await api('get', `/admin/v1/realms/master/users/${managedUser.body.id}`).expect(200)).body.roles, []);
  const scope = await api('post', '/admin/v1/realms/master/client-scopes', { name: 'profile-extra', description: '', protocol: 'openid-connect', attributes: {} }).expect(201);
  await api('post', '/admin/v1/realms/master/claim-mappers', { ownerType: 'client-scope', ownerId: scope.body.id, name: 'department', mapperType: 'user-attribute', config: { claim: 'department', source: 'attributes.department' } }).expect(201);
  await api('post', '/admin/v1/realms/master/claim-mappers', { ownerType: 'client-scope', ownerId: '00000000-0000-4000-8000-000000000000', name: 'orphan', mapperType: 'hardcoded', config: { claim: 'orphan', value: true } }).expect(404);
  await api('put', `/admin/v1/realms/master/clients/missing-client/client-scopes/${scope.body.id}`, { assignmentType: 'optional' }).expect(404);
  await api('post', '/admin/v1/realms/master/authentication-flows', { alias: 'strong', enabled: true, priority: 10, clientIds: [], acr: 'urn:authme:strong', maxAgeSeconds: 300, steps: [{ type: 'password', requirement: 'required' }] }).expect(201);
  assert.equal(await runtime.data.management.resolveAuthenticationFlow('master', {
    clientId: 'authme-admin-console', requestedAcrs: ['urn:authme:loa:2'],
  }), undefined);
  await api('post', '/admin/v1/realms/master/authentication-flows', { alias: 'impossible', enabled: true, priority: 11, clientIds: [], acr: 'urn:authme:impossible', maxAgeSeconds: 300, steps: [{ type: 'passkey', requirement: 'required' }, { type: 'totp', requirement: 'required' }] }).expect(400);
  const discovery = await request(runtime.app).get('/realms/master/.well-known/openid-configuration').set('host', host).expect(200);
  assert(discovery.body.scopes_supported.includes('profile-extra'));
  assert(discovery.body.acr_values_supported.includes('urn:authme:strong'));
  const organization = await api('post', '/admin/v1/realms/master/organizations', { name: 'Example', alias: 'example', enabled: true, domains: [{ domain: 'example.test', verified: false }], identityProviderIds: [], attributes: {} }).expect(201);
  assert.equal(organization.body.alias, 'example');
  await api('post', '/admin/v1/realms/master/organizations', {
    name: 'Ambiguous alias', alias: organization.body.id, enabled: true, domains: [], identityProviderIds: [], attributes: {},
  }).expect(400);
  await api('get', '/admin/v1/realms/master/organizations/00000000-0000-4000-8000-000000000000/members').expect(404);
  await api('put', `/admin/v1/realms/master/organizations/${organization.body.id}/members/${managedUser.body.id}`, { roles: ['owner'] }).expect(200);
  const invitation = await api('post', `/admin/v1/realms/master/organizations/${organization.body.id}/invitations`, {
    email: 'pending-invitation@example.test', roles: ['member'], expiresInSeconds: 3600,
  }).expect(201);
  assert.match(invitation.body.token, /^[A-Za-z0-9_-]{43}$/u);
  await api('delete', `/admin/v1/realms/master/organizations/${organization.body.id}/invitations/${invitation.body.id}`, {}).expect(204);
  await api('patch', `/admin/v1/realms/master/organizations/${organization.body.id}`, { identityProviderIds: ['unconfigured'] }).expect(400);

  await api('patch', '/admin/v1/realms/master', { displayName: 'Primary realm', enabled: false }).expect(200);
  await request(runtime.app).get('/realms/master/.well-known/openid-configuration').set('host', host).expect(503);
  await api('patch', '/admin/v1/realms/master', { enabled: true }).expect(200);
  await request(runtime.app).get('/realms/master/.well-known/openid-configuration').set('host', host).expect(200);
  await api('delete', `/admin/v1/realms/master/users/${managedUser.body.id}`, {}).expect(204);
  assert.deepEqual(await runtime.data.management.listOrganizationMemberships('master', organization.body.id), []);
});
