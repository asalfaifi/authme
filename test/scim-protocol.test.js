import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import request from 'supertest';
import { createIdentityExtensionRegistry } from '../src/authentication/registry.js';
import { createScimExtension, createScimRouter, MemoryScimRepository, SCIM_URNS } from '../src/scim/index.js';

function fixture() {
  const repository = new MemoryScimRepository();
  const audits = [];
  const app = express();
  app.use('/scim/v2/realms', createScimRouter({
    repository,
    authenticate: async ({ realm, token }) => token === `token-${realm}` ? { id: `provisioner-${realm}` } : null,
    realmExists: async (realm) => ['master', 'staff'].includes(realm),
    audit: async (event) => { audits.push(event); },
    baseUrl: 'https://auth.example.test/scim/v2/realms',
    maxPageSize: 2,
    defaultPageSize: 2,
  }));
  return { app, repository, audits };
}

function client(app, realm = 'master') {
  const authorization = `Bearer token-${realm}`;
  return {
    get: (path) => request(app).get(`/scim/v2/realms/${realm}${path}`).set('Authorization', authorization),
    post: (path) => request(app).post(`/scim/v2/realms/${realm}${path}`).set('Authorization', authorization).set('Content-Type', 'application/scim+json'),
    put: (path) => request(app).put(`/scim/v2/realms/${realm}${path}`).set('Authorization', authorization).set('Content-Type', 'application/scim+json'),
    patch: (path) => request(app).patch(`/scim/v2/realms/${realm}${path}`).set('Authorization', authorization).set('Content-Type', 'application/scim+json'),
    delete: (path) => request(app).delete(`/scim/v2/realms/${realm}${path}`).set('Authorization', authorization),
  };
}

function user(userName, externalId = `${userName}-external`) {
  return {
    schemas: [SCIM_URNS.user], userName, externalId, active: true,
    name: { givenName: userName, familyName: 'Example' },
    emails: [{ value: `${userName}@example.test`, type: 'work', primary: true }],
    password: 'write-only-secret',
  };
}

test('SCIM exposes AuthMe provisioning-extension metadata without runtime secrets', () => {
  const extension = createScimExtension({
    enabledFor: (realm) => realm === 'master',
    routerOptions: { repository: new MemoryScimRepository(), authenticate: async () => true },
  });
  const registry = createIdentityExtensionRegistry([extension]);
  assert.equal(registry.forRealm('provisioning', 'staff').length, 0);
  assert.deepEqual(registry.describe('master'), [{
    apiVersion: 'authme.identity/v1', id: 'builtin.scim2', kind: 'provisioning',
    displayName: 'SCIM 2.0 Provisioning', capabilities: ['groups', 'scim2', 'users'],
  }]);
  assert.equal(typeof extension.implementation.createRouter(), 'function');
});

test('SCIM discovery and errors are authenticated, realm-scoped, and canonical', async () => {
  const { app } = fixture();
  let response = await request(app).get('/scim/v2/realms/master/ServiceProviderConfig');
  assert.equal(response.status, 401);
  assert.equal(response.type, 'application/scim+json');
  assert.deepEqual(response.body.schemas, [SCIM_URNS.error]);
  assert.match(response.headers['www-authenticate'], /^Bearer/);

  response = await request(app).get('/scim/v2/realms/master/Schemas').set('Authorization', 'Bearer wrong');
  assert.equal(response.status, 401);

  response = await client(app).get('/ServiceProviderConfig');
  assert.equal(response.status, 200);
  assert.equal(response.body.patch.supported, true);
  assert.equal(response.body.filter.maxResults, 2);
  assert.equal(response.body.etag.supported, true);

  response = await client(app).get('/Schemas');
  assert.equal(response.body.totalResults, 2);
  assert.deepEqual(response.body.Resources.map(({ id }) => id), [SCIM_URNS.user, SCIM_URNS.group]);

  response = await client(app).get(`/Schemas/${encodeURIComponent(SCIM_URNS.user)}`);
  assert.equal(response.status, 200);
  assert.equal(response.body.name, 'User');

  response = await client(app).get('/ResourceTypes');
  assert.deepEqual(response.body.Resources.map(({ id }) => id), ['User', 'Group']);

  response = await client(app).get('/does-not-exist');
  assert.equal(response.status, 404);
  assert.deepEqual(response.body.schemas, [SCIM_URNS.error]);

  response = await request(app).get('/scim/v2/realms/unknown/Users').set('Authorization', 'Bearer anything');
  assert.equal(response.status, 401, 'authentication happens before realm existence disclosure');
});

test('User CRUD supports pagination, eq filters, uniqueness, write-only passwords, and realm isolation', async () => {
  const { app, audits } = fixture();
  const master = client(app);
  let response = await master.post('/Users').send(user('alice', 'employee-1'));
  assert.equal(response.status, 201);
  assert.equal(response.type, 'application/scim+json');
  assert.equal(response.body.userName, 'alice');
  assert.equal(response.body.password, undefined);
  assert.match(response.headers.etag, /^W\//);
  assert.equal(response.headers.location, response.body.meta.location);
  const alice = response.body;

  await master.post('/Users').send(user('bob', 'employee-2')).expect(201);
  await master.post('/Users').send(user('carol', 'employee-3')).expect(201);

  response = await master.get('/Users').query({ startIndex: 2, count: 50 });
  assert.equal(response.status, 200);
  assert.equal(response.body.totalResults, 3);
  assert.equal(response.body.startIndex, 2);
  assert.equal(response.body.itemsPerPage, 2, 'count is capped at the service maximum');

  response = await master.get('/Users').query({ filter: 'userName eq "ALICE"' });
  assert.equal(response.body.totalResults, 1);
  assert.equal(response.body.Resources[0].id, alice.id);

  response = await master.get('/Users').query({ filter: 'externalId eq "employee-1"', count: 0 });
  assert.equal(response.body.totalResults, 1);
  assert.equal(response.body.Resources.length, 0);

  response = await master.post('/Users').send(user('other', 'employee-1'));
  assert.equal(response.status, 409);
  assert.equal(response.body.scimType, 'uniqueness');

  response = await client(app, 'staff').post('/Users').send(user('alice', 'employee-1'));
  assert.equal(response.status, 201, 'identity keys are independent in another realm');
  assert.notEqual(response.body.id, alice.id);

  response = await client(app, 'staff').get(`/Users/${alice.id}`);
  assert.equal(response.status, 404, 'a resource id cannot cross realm boundaries');
  assert.equal(audits.filter(({ type }) => type === 'scim.user.created').length, 4);
  assert(audits.every(({ actor }) => actor.id.startsWith('provisioner-')));
  assert(audits.every((event) => !('req' in event) && !JSON.stringify(event).includes('token-master')),
    'audit events never receive the bearer credential or raw request');
});

test('ETags implement conditional GET and atomic mutation preconditions', async () => {
  const { app } = fixture();
  const scim = client(app);
  let response = await scim.post('/Users').send(user('alice'));
  const id = response.body.id;
  const firstEtag = response.headers.etag;

  response = await scim.get(`/Users/${id}`).set('If-None-Match', firstEtag);
  assert.equal(response.status, 304);

  response = await scim.patch(`/Users/${id}`).set('If-Match', 'W/"999"').send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'replace', path: 'displayName', value: 'Alice' }],
  });
  assert.equal(response.status, 412);

  response = await scim.patch(`/Users/${id}`).set('If-Match', firstEtag).send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'replace', path: 'displayName', value: 'Alice Updated' }],
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.displayName, 'Alice Updated');
  assert.notEqual(response.headers.etag, firstEtag);
  const secondEtag = response.headers.etag;

  response = await scim.put(`/Users/${id}`).set('If-Match', secondEtag).send({
    schemas: [SCIM_URNS.user], id, meta: response.body.meta,
    userName: 'alice-renamed', externalId: 'alice-external', active: true,
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.userName, 'alice-renamed');
  const thirdEtag = response.headers.etag;

  response = await scim.delete(`/Users/${id}`).set('If-Match', secondEtag);
  assert.equal(response.status, 412, 'a stale version cannot delete the replacement');
  await scim.delete(`/Users/${id}`).set('If-Match', thirdEtag).expect(204);
  await scim.get(`/Users/${id}`).expect(404);
});

test('Groups validate same-realm users and PATCH membership without re-enabling disabled users', async () => {
  const { app, repository, audits } = fixture();
  const scim = client(app);
  let response = await scim.post('/Users').send(user('alice'));
  const alice = response.body;
  response = await scim.post('/Users').send(user('bob'));
  const bob = response.body;

  response = await scim.post('/Groups').send({
    schemas: [SCIM_URNS.group], displayName: 'Engineering', externalId: 'group-1',
    members: [{ value: alice.id }],
  });
  assert.equal(response.status, 201);
  const groupId = response.body.id;
  let groupEtag = response.headers.etag;
  assert.equal(response.body.members[0].$ref, `https://auth.example.test/scim/v2/realms/master/Users/${alice.id}`);

  response = await scim.patch(`/Groups/${groupId}`).set('If-Match', groupEtag).send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'add', path: 'members', value: [{ value: bob.id }] }],
  });
  assert.equal(response.status, 200);
  assert.deepEqual(new Set(response.body.members.map(({ value }) => value)), new Set([alice.id, bob.id]));
  groupEtag = response.headers.etag;

  response = await scim.patch(`/Groups/${groupId}`).set('If-Match', groupEtag).send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'add', path: 'members', value: [{ value: bob.id }] }],
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.etag, groupEtag, 'adding an existing value is a no-op and preserves the version');

  response = await scim.patch(`/Users/${alice.id}`).send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'replace', path: 'active', value: false }],
  });
  assert.equal(response.body.active, false);
  assert.equal(await repository.isUserActive('master', alice.id), false);
  assert.equal(await repository.isUserActive('master', 'missing-user'), false);
  response = await scim.get(`/Groups/${groupId}`);
  assert(response.body.members.some(({ value }) => value === alice.id), 'disabling does not silently alter membership');

  response = await scim.patch(`/Groups/${groupId}`).set('If-Match', groupEtag).send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'remove', path: `members[value eq "${alice.id}"]` }],
  });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.members.map(({ value }) => value), [bob.id]);

  response = await scim.patch(`/Groups/${groupId}`).send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'remove', path: 'members[value eq "missing"]' }],
  });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'noTarget');

  response = await scim.post('/Groups').send({ displayName: 'Invalid', members: [{ value: 'not-in-this-realm' }] });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'invalidValue');

  response = await scim.post('/Groups').send({ displayName: 'Duplicate external id', externalId: 'group-1' });
  assert.equal(response.status, 409);
  assert.equal(response.body.scimType, 'uniqueness');

  await scim.delete(`/Users/${bob.id}`).expect(204);
  response = await scim.get(`/Groups/${groupId}`);
  assert.deepEqual(response.body.members, [], 'deleting a User removes dangling memberships');
  const afterCleanupEtag = response.headers.etag;

  response = await scim.put(`/Groups/${groupId}`).set('If-Match', afterCleanupEtag).send({
    schemas: [SCIM_URNS.group], id: groupId, meta: response.body.meta,
    displayName: 'Platform Engineering', externalId: 'group-1', members: [],
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.displayName, 'Platform Engineering');
  const replacedGroupEtag = response.headers.etag;
  await scim.delete(`/Groups/${groupId}`).set('If-Match', afterCleanupEtag).expect(412);
  await scim.delete(`/Groups/${groupId}`).set('If-Match', replacedGroupEtag).expect(204);
  await scim.get(`/Groups/${groupId}`).expect(404);
  assert(audits.some(({ type, resourceId }) => type === 'scim.group.patched' && resourceId === groupId));
  assert(audits.some(({ type, resourceId }) => type === 'scim.group.deleted' && resourceId === groupId));
});

test('invalid filters, bodies, pagination, PATCH paths, and readOnly fields use SCIM errors', async () => {
  const { app } = fixture();
  const scim = client(app);
  let response = await scim.get('/Users').query({ filter: 'userName co "a"' });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'invalidFilter');

  response = await scim.get('/Users').query({ startIndex: 0 });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'invalidValue');

  response = await scim.post('/Users').send('{broken');
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'invalidSyntax');

  response = await scim.post('/Users').send({ schemas: [SCIM_URNS.user], id: 'client-id', userName: 'alice' });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'mutability');

  response = await scim.post('/Users').send(user('alice'));
  const id = response.body.id;
  response = await scim.patch(`/Users/${id}`).send({
    schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'replace', path: 'unknown', value: 'x' }],
  });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'invalidPath');
  assert.deepEqual(response.body.schemas, [SCIM_URNS.error]);
  assert.equal(response.body.status, '400');
});
