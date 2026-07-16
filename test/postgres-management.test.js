import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';
import { PostgresIdentityStore } from '../src/repositories/identity-store.js';
import { PostgresManagementStore } from '../src/repositories/management-store.js';

const databaseUrl = process.env.DATABASE_URL;
const realm = `mgmt-${randomUUID().slice(0, 8)}`;
let pool;
let management;
let identities;

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({ connectionString: databaseUrl, max: 2 });
  await pool.query('INSERT INTO realms (name,display_name) VALUES ($1,$2)', [realm, 'Management test']);
  management = new PostgresManagementStore(pool);
  identities = new PostgresIdentityStore(pool);
});

after(async () => {
  if (!pool) return;
  await pool.query('DELETE FROM realms WHERE name=$1', [realm]);
  await pool.end();
});

test('PostgreSQL management policy is durable, mutable, nested, and realm-scoped', { skip: !databaseUrl }, async () => {
  await management.putRole(realm, { name: 'reader', description: '', composites: [], attributes: {} });
  await management.putRole(realm, { name: 'editor', description: '', composites: ['reader'], attributes: {} });
  const parent = await management.createGroup(realm, { name: 'engineering', parentId: null, roles: ['reader'], attributes: {} });
  const child = await management.createGroup(realm, { name: 'platform', parentId: parent.id, roles: ['editor'], attributes: {} });
  assert.equal(child.path, '/engineering/platform');

  const scope = await management.createClientScope(realm, { name: 'tenant', description: '', protocol: 'openid-connect', attributes: {} });
  await management.setClientScopeAssignment(realm, 'portal', scope.id, 'default');
  await management.createClaimMapper(realm, { ownerType: 'client-scope', ownerId: scope.id, name: 'tenant', mapperType: 'hardcoded', config: { claim: 'tenant', value: 'one' } });
  assert.equal((await management.effectiveClaimMappers(realm, 'portal'))[0].config.claim, 'tenant');
  const optional = await management.createClientScope(realm, { name: 'optional-context', description: '', protocol: 'openid-connect', attributes: {} });
  await management.setClientScopeAssignment(realm, 'portal', optional.id, 'optional');
  await management.createClaimMapper(realm, { ownerType: 'client-scope', ownerId: optional.id, name: 'optional', mapperType: 'hardcoded', config: { claim: 'optional_context', value: true } });
  assert.equal((await management.effectiveClaimMappers(realm, 'portal')).some((mapper) => mapper.name === 'optional'), false);
  assert.equal((await management.effectiveClaimMappers(realm, 'portal', ['optional-context'])).some((mapper) => mapper.name === 'optional'), true);
  await management.deleteClientScope(realm, optional.id);
  assert.deepEqual(await management.listClaimMappers(realm, 'client-scope', optional.id), []);

  await management.createClaimMapper(realm, { ownerType: 'client', ownerId: 'portal', name: 'direct', mapperType: 'hardcoded', config: { claim: 'direct', value: true } });
  await management.deleteClientPolicy(realm, 'portal');
  assert.deepEqual(await management.listClientScopeAssignments(realm, 'portal'), []);
  assert.deepEqual(await management.listClaimMappers(realm, 'client', 'portal'), []);

  const flow = await management.createAuthenticationFlow(realm, { alias: 'strong', description: '', enabled: true, priority: 10, clientIds: ['portal'], acr: 'urn:test:strong', maxAgeSeconds: 300, steps: [{ type: 'password', requirement: 'required' }] });
  assert.equal((await management.resolveAuthenticationFlow(realm, { clientId: 'portal' })).id, flow.id);

  const user = await identities.createUser({ realm, username: 'member', email: 'member@example.test', passwordHash: 'hash' });
  const organization = await management.createOrganization(realm, { name: 'Example', alias: 'example', enabled: true, domains: [{ domain: 'example.test', verified: true }], identityProviderIds: [], attributes: {} });
  await management.upsertOrganizationMembership(realm, organization.id, user.id, ['owner']);
  assert.deepEqual((await management.listUserOrganizations(realm, user.id))[0].roles, ['owner']);

  await management.putSigningKey(realm, { keyId: 'key-1', provider: 'pkcs11', status: 'active', algorithm: 'ES256', materialReference: 'pkcs11:test', publicJwk: { kty: 'EC', kid: 'key-1' }, activatedAt: new Date(), retireAfter: null });
  assert.equal((await management.listSigningKeys(realm))[0].status, 'active');
  assert.deepEqual(await management.listOrganizations('master'), []);
});
