import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  applyClaimMappers,
  expandCompositeRoles,
  MemoryManagementStore,
} from '../src/repositories/management-store.js';
import { authenticationSatisfiesFlow } from '../src/routes/interactions.js';
import { authenticationFlowConfigurationError } from '../src/authentication/flow-policy.js';

test('realm roles compose without cycles and nested groups retain stable paths', async () => {
  const store = new MemoryManagementStore(['master', 'staff']);
  await store.putRole('master', { name: 'reader', description: '', composites: [], attributes: {} });
  await store.putRole('master', { name: 'editor', description: '', composites: ['reader'], attributes: {} });
  await store.putRole('master', { name: 'administrator', description: '', composites: ['editor'], attributes: {} });
  assert.deepEqual(expandCompositeRoles(['administrator'], await store.listRoles('master')), ['administrator', 'editor', 'reader']);
  await assert.rejects(
    store.putRole('master', { name: 'reader', description: '', composites: ['administrator'], attributes: {} }),
    /cycle/iu,
  );

  const parent = await store.createGroup('master', { name: 'engineering', parentId: null, roles: ['reader'], attributes: {} });
  const child = await store.createGroup('master', { name: 'platform', parentId: parent.id, roles: ['editor'], attributes: {} });
  assert.equal(child.path, '/engineering/platform');
  await assert.rejects(store.updateGroup('master', parent.id, { parentId: child.id }), /cycle/iu);
  assert.deepEqual(await store.listGroups('staff'), []);
});

test('client scopes aggregate safe claim mappers and authentication flows resolve by client and acr', async () => {
  const store = new MemoryManagementStore(['master']);
  const scope = await store.createClientScope('master', { name: 'tenant-context', description: '', protocol: 'openid-connect', attributes: {} });
  await store.setClientScopeAssignment('master', 'portal', scope.id, 'default');
  await store.createClaimMapper('master', {
    ownerType: 'client-scope', ownerId: scope.id, name: 'department', mapperType: 'user-attribute', config: { claim: 'department', source: 'attributes.department' },
  });
  const mappers = await store.effectiveClaimMappers('master', 'portal');
  assert.deepEqual(applyClaimMappers({ user: { attributes: { department: 'identity' } }, mappers }), { department: 'identity' });
  const optional = await store.createClientScope('master', { name: 'optional-context', description: '', protocol: 'openid-connect', attributes: {} });
  await store.setClientScopeAssignment('master', 'portal', optional.id, 'optional');
  await store.createClaimMapper('master', {
    ownerType: 'client-scope', ownerId: optional.id, name: 'optional', mapperType: 'hardcoded', config: { claim: 'optional_context', value: true },
  });
  assert.equal((await store.effectiveClaimMappers('master', 'portal')).some((mapper) => mapper.name === 'optional'), false);
  assert.equal((await store.effectiveClaimMappers('master', 'portal', ['optional-context'])).some((mapper) => mapper.name === 'optional'), true);
  await store.deleteClientScope('master', optional.id);
  assert.deepEqual(await store.listClaimMappers('master', 'client-scope', optional.id), []);

  await store.createClaimMapper('master', {
    ownerType: 'client', ownerId: 'portal', name: 'direct', mapperType: 'hardcoded', config: { claim: 'direct', value: true },
  });
  await store.deleteClientPolicy('master', 'portal');
  assert.deepEqual(await store.listClientScopeAssignments('master', 'portal'), []);
  assert.deepEqual(await store.listClaimMappers('master', 'client', 'portal'), []);

  await store.createAuthenticationFlow('master', {
    alias: 'portal-step-up', description: '', enabled: true, priority: 10, clientIds: ['portal'],
    acr: 'urn:authme:portal:loa2', maxAgeSeconds: 300,
    steps: [{ type: 'password', requirement: 'required' }, { type: 'totp', requirement: 'required' }],
  });
  const flow = await store.resolveAuthenticationFlow('master', { clientId: 'portal', requestedAcrs: ['urn:authme:portal:loa2'] });
  assert.equal(flow.alias, 'portal-step-up');
  assert.equal(authenticationSatisfiesFlow(flow, ['pwd', 'otp'], { totpConfirmed: true }), true);
  assert.equal(authenticationSatisfiesFlow(flow, ['pwd'], { totpConfirmed: true }), false);
});

test('authentication flows reject configurations the interaction engine cannot execute', async () => {
  assert.match(authenticationFlowConfigurationError([
    { type: 'passkey', requirement: 'required' },
    { type: 'totp', requirement: 'required' },
  ]), /TOTP can only be combined with password/iu);
  assert.match(authenticationFlowConfigurationError([
    { type: 'password', requirement: 'required' },
    { type: 'federated', requirement: 'alternative' },
  ]), /cannot be combined/iu);
  assert.equal(authenticationFlowConfigurationError([
    { type: 'password', requirement: 'required' },
    { type: 'totp', requirement: 'conditional' },
  ]), undefined);
});

test('organizations isolate domains, memberships, invitations, and signing-key lifecycle by realm', async () => {
  const store = new MemoryManagementStore(['master', 'staff']);
  const organization = await store.createOrganization('master', {
    name: 'Example', alias: 'example', enabled: true,
    domains: [{ domain: 'example.test', verified: true }], identityProviderIds: ['corporate'], attributes: {},
  });
  await assert.rejects(store.createOrganization('master', {
    name: 'Collision', alias: 'collision', enabled: true,
    domains: [{ domain: 'example.test', verified: false }], identityProviderIds: [], attributes: {},
  }), /domain/iu);
  const second = await store.createOrganization('master', {
    name: 'Second', alias: 'second', enabled: true,
    domains: [{ domain: 'second.test', verified: false }], identityProviderIds: [], attributes: {},
  });
  await assert.rejects(store.updateOrganization('master', second.id, {
    domains: [{ domain: 'example.test', verified: false }],
  }), /domain/iu);
  await store.upsertOrganizationMembership('master', organization.id, '00000000-0000-4000-8000-000000000001', ['owner']);
  assert.equal((await store.listUserOrganizations('master', '00000000-0000-4000-8000-000000000001'))[0].alias, 'example');
  assert.deepEqual(await store.listUserOrganizations('staff', '00000000-0000-4000-8000-000000000001'), []);

  await store.putSigningKey('master', { keyId: 'old', provider: 'aws-kms', status: 'active', algorithm: 'RS256', materialReference: 'kms:key/old', publicJwk: { kty: 'RSA', kid: 'old' }, activatedAt: new Date(), retireAfter: null });
  await store.putSigningKey('master', { keyId: 'new', provider: 'aws-kms', status: 'active', algorithm: 'RS256', materialReference: 'kms:key/new', publicJwk: { kty: 'RSA', kid: 'new' }, activatedAt: new Date(), retireAfter: null });
  const keys = await store.listSigningKeys('master');
  assert.equal(keys.find((entry) => entry.keyId === 'new').status, 'active');
  assert.equal(keys.find((entry) => entry.keyId === 'old').status, 'retiring');
});
