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
  const reconciled = await runtime.store.findUserById('master', assigned.body.id);
  assert.deepEqual(reconciled.clientRoles, {});
  assert(reconciled.securityVersion > assignedVersion);
  await api('post', '/admin/v1/realms/master/clients', { ...metadata, client_id: 'authme-admin-console' }).expect(409);
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
  await api('post', '/admin/v1/realms/master/authentication-flows', { alias: 'impossible', enabled: true, priority: 11, clientIds: [], acr: 'urn:authme:impossible', maxAgeSeconds: 300, steps: [{ type: 'passkey', requirement: 'required' }, { type: 'totp', requirement: 'required' }] }).expect(400);
  const discovery = await request(runtime.app).get('/realms/master/.well-known/openid-configuration').set('host', host).expect(200);
  assert(discovery.body.scopes_supported.includes('profile-extra'));
  assert(discovery.body.acr_values_supported.includes('urn:authme:strong'));
  const organization = await api('post', '/admin/v1/realms/master/organizations', { name: 'Example', alias: 'example', enabled: true, domains: [{ domain: 'example.test', verified: false }], identityProviderIds: [], attributes: {} }).expect(201);
  assert.equal(organization.body.alias, 'example');
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
});
