import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import request from 'supertest';

import { createScimRouter, MemoryScimRepository, SCIM_URNS } from '../src/scim/index.js';

function fixture() {
  const repository = new MemoryScimRepository();
  const audits = [];
  const app = express();
  app.use('/scim/v2/realms', createScimRouter({
    repository,
    authenticate: async ({ realm, token }) => token === `token-${realm}` ? { id: `bulk-${realm}` } : null,
    realmExists: async (realm) => ['master', 'staff'].includes(realm),
    audit: async (event) => { audits.push(event); },
    baseUrl: 'https://auth.example.test/scim/v2/realms',
    maxOperations: 4,
    maxPayloadSize: 2048,
  }));
  return { app, repository, audits };
}

function client(app, realm = 'master') {
  const root = `/scim/v2/realms/${realm}`;
  const authorization = `Bearer token-${realm}`;
  return {
    get: (path) => request(app).get(`${root}${path}`).set('Authorization', authorization),
    post: (path) => request(app).post(`${root}${path}`).set('Authorization', authorization).set('Content-Type', 'application/scim+json'),
  };
}

function bulk(Operations, values = {}) {
  return { schemas: [SCIM_URNS.bulkRequest], Operations, ...values };
}

function user(userName) {
  return { schemas: [SCIM_URNS.user], userName, active: true };
}

test('Bulk discovery, authentication, forward bulkId references, and response metadata', async () => {
  const { app, audits } = fixture();
  const scim = client(app);
  let response = await scim.get('/ServiceProviderConfig');
  assert.deepEqual(response.body.bulk, { supported: true, maxOperations: 4, maxPayloadSize: 2048 });
  assert.equal(response.body.sort.supported, true);

  response = await request(app)
    .post('/scim/v2/realms/master/Bulk')
    .set('Content-Type', 'application/scim+json')
    .send(bulk([]));
  assert.equal(response.status, 401);

  response = await scim.post('/Bulk').send(bulk([
    {
      method: 'POST', path: '/Groups', bulkId: 'new-group',
      data: { schemas: [SCIM_URNS.group], displayName: 'Engineering', members: [{ value: 'bulkId:new-user' }] },
    },
    { method: 'POST', path: '/Users', bulkId: 'new-user', data: user('alice') },
    {
      method: 'PATCH', path: '/Users/bulkId:new-user',
      data: { schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'replace', path: 'displayName', value: 'Alice Bulk' }] },
    },
  ]));
  assert.equal(response.status, 200, response.text);
  assert.deepEqual(response.body.schemas, [SCIM_URNS.bulkResponse]);
  assert.deepEqual(response.body.Operations.map(({ status }) => status), ['201', '201', '200']);
  const groupResult = response.body.Operations[0];
  const userResult = response.body.Operations[1];
  assert.equal(groupResult.bulkId, 'new-group');
  assert.equal(userResult.bulkId, 'new-user');
  assert.match(userResult.version, /^W\//u);

  const userId = userResult.location.split('/').at(-1);
  const groupId = groupResult.location.split('/').at(-1);
  const storedUser = await scim.get(`/Users/${userId}`);
  const storedGroup = await scim.get(`/Groups/${groupId}`);
  assert.equal(storedUser.body.displayName, 'Alice Bulk');
  assert.deepEqual(storedGroup.body.members.map(({ value }) => value), [userId]);
  assert.deepEqual(audits.map(({ type }) => type), ['scim.user.created', 'scim.group.created', 'scim.user.patched']);
});

test('Bulk supports PUT, PATCH, DELETE, versions, and per-operation SCIM errors', async () => {
  const { app } = fixture();
  const scim = client(app);
  let response = await scim.post('/Users').send(user('alice'));
  const id = response.body.id;
  const version = response.headers.etag;

  response = await scim.post('/Bulk').send(bulk([
    { method: 'PUT', path: `/Users/${id}`, version, data: user('alice-renamed') },
    {
      method: 'PATCH', path: `/Users/${id}`, version: 'W/"stale"',
      data: { schemas: [SCIM_URNS.patchOp], Operations: [{ op: 'replace', path: 'title', value: 'Ignored' }] },
    },
    { method: 'DELETE', path: '/Users/missing', version: '*' },
  ]));
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.Operations.map(({ status }) => status), ['200', '412', '404']);
  for (const operation of response.body.Operations.slice(1)) {
    assert.deepEqual(operation.response.schemas, [SCIM_URNS.error]);
    assert.equal(operation.response.status, operation.status);
  }

  const current = await scim.get(`/Users/${id}`);
  response = await scim.post('/Bulk').send(bulk([
    { method: 'DELETE', path: `/Users/${id}`, version: current.headers.etag },
  ]));
  assert.equal(response.body.Operations[0].status, '204');
  await scim.get(`/Users/${id}`).expect(404);
});

test('Bulk continues after errors by default and failOnErrors stops unprocessed operations', async () => {
  const { app } = fixture();
  const scim = client(app);
  await scim.post('/Users').send(user('existing')).expect(201);

  let response = await scim.post('/Bulk').send(bulk([
    { method: 'POST', path: '/Users', bulkId: 'duplicate', data: user('existing') },
    { method: 'POST', path: '/Users', bulkId: 'continued', data: user('continued') },
  ]));
  assert.deepEqual(response.body.Operations.map(({ status }) => status), ['409', '201']);

  response = await scim.post('/Bulk').send(bulk([
    { method: 'POST', path: '/Users', bulkId: 'duplicate-again', data: user('existing') },
    { method: 'POST', path: '/Users', bulkId: 'not-run', data: user('not-run') },
  ], { failOnErrors: 1 }));
  assert.deepEqual(response.body.Operations.map(({ status }) => status), ['409']);
  const absent = await scim.get('/Users').query({ filter: 'userName eq "not-run"' });
  assert.equal(absent.body.totalResults, 0);
});

test('each Bulk PATCH is atomic and failed or unknown bulkId dependencies do not mutate resources', async () => {
  const { app } = fixture();
  const scim = client(app);
  const created = await scim.post('/Users').send(user('alice'));
  const id = created.body.id;

  let response = await scim.post('/Bulk').send(bulk([
    {
      method: 'PATCH', path: `/Users/${id}`,
      data: { schemas: [SCIM_URNS.patchOp], Operations: [
        { op: 'replace', path: 'displayName', value: 'Must Roll Back' },
        { op: 'replace', path: 'unknown', value: 'failure' },
      ] },
    },
    {
      method: 'POST', path: '/Groups', bulkId: 'dependent',
      data: { schemas: [SCIM_URNS.group], displayName: 'Invalid', members: [{ value: 'bulkId:unknown' }] },
    },
  ]));
  assert.deepEqual(response.body.Operations.map(({ status }) => status), ['400', '409']);
  assert.equal(response.body.Operations[0].response.scimType, 'invalidPath');
  const unchanged = await scim.get(`/Users/${id}`);
  assert.equal(unchanged.body.displayName, undefined);
});

test('Bulk enforces operation and payload limits with top-level 413 SCIM errors', async () => {
  const { app } = fixture();
  const scim = client(app);
  let response = await scim.post('/Bulk').send(bulk(Array.from({ length: 5 }, () => ({}))));
  assert.equal(response.status, 413);
  assert.match(response.body.detail, /maxOperations \(4\)/u);

  response = await scim.post('/Bulk').send(bulk([
    { method: 'POST', path: '/Users', bulkId: 'large', data: user(`large-${'x'.repeat(3000)}`) },
  ]));
  assert.equal(response.status, 413);
  assert.match(response.body.detail, /maxPayloadSize \(2048\)/u);
  assert.deepEqual(response.body.schemas, [SCIM_URNS.error]);
});

test('Bulk cannot read or mutate resource identifiers across realms', async () => {
  const { app } = fixture();
  const master = client(app);
  const staff = client(app, 'staff');
  const created = await master.post('/Users').send(user('master-user'));
  const id = created.body.id;

  const response = await staff.post('/Bulk').send(bulk([
    { method: 'DELETE', path: `/Users/${id}`, version: '*' },
  ]));
  assert.equal(response.status, 200);
  assert.equal(response.body.Operations[0].status, '404');
  await master.get(`/Users/${id}`).expect(200);
});
