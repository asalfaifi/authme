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
  const inventory = await api('get', '/admin/v1/realms/master/clients').expect(200);
  assert(inventory.body.clients.some((client) => client.client_id === 'managed-native' && client.managed));
  await api('delete', '/admin/v1/realms/master/clients/managed-native', {}).expect(204);
  assert.equal(await runtime.providers.get('master').Client.find('managed-native'), undefined);
  assert.deepEqual(await runtime.data.management.listClientScopeAssignments('master', 'managed-native'), []);
  assert.deepEqual(await runtime.data.management.listClaimMappers('master', 'client', 'managed-native'), []);
  await api('post', '/admin/v1/realms/master/clients', { ...metadata, client_id: 'authme-admin-console' }).expect(409);
});

test('realm, role, nested group, scope, mapper, flow, and organization APIs are mutable and realm-scoped', async () => {
  await api('put', '/admin/v1/realms/master/roles/reader', { description: 'Read', composites: [], attributes: {} }).expect(201);
  await api('put', '/admin/v1/realms/master/roles/editor', { description: 'Edit', composites: ['reader'], attributes: {} }).expect(201);
  const group = await api('post', '/admin/v1/realms/master/groups', { name: 'engineering', parentId: null, roles: ['editor'], attributes: {} }).expect(201);
  assert.equal(group.body.path, '/engineering');
  const scope = await api('post', '/admin/v1/realms/master/client-scopes', { name: 'profile-extra', description: '', protocol: 'openid-connect', attributes: {} }).expect(201);
  await api('post', '/admin/v1/realms/master/claim-mappers', { ownerType: 'client-scope', ownerId: scope.body.id, name: 'department', mapperType: 'user-attribute', config: { claim: 'department', source: 'attributes.department' } }).expect(201);
  await api('post', '/admin/v1/realms/master/authentication-flows', { alias: 'strong', enabled: true, priority: 10, clientIds: [], acr: 'urn:authme:strong', maxAgeSeconds: 300, steps: [{ type: 'password', requirement: 'required' }] }).expect(201);
  const organization = await api('post', '/admin/v1/realms/master/organizations', { name: 'Example', alias: 'example', enabled: true, domains: [{ domain: 'example.test', verified: false }], identityProviderIds: [], attributes: {} }).expect(201);
  assert.equal(organization.body.alias, 'example');
  await api('patch', `/admin/v1/realms/master/organizations/${organization.body.id}`, { identityProviderIds: ['unconfigured'] }).expect(400);

  await api('patch', '/admin/v1/realms/master', { displayName: 'Primary realm', enabled: false }).expect(200);
  await request(runtime.app).get('/realms/master/.well-known/openid-configuration').set('host', host).expect(503);
  await api('patch', '/admin/v1/realms/master', { enabled: true }).expect(200);
  await request(runtime.app).get('/realms/master/.well-known/openid-configuration').set('host', host).expect(200);
});
