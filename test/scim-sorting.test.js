import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import request from 'supertest';

import { createScimRouter, MemoryScimRepository, SCIM_URNS } from '../src/scim/index.js';

function fixture() {
  const app = express();
  app.use('/scim/v2/realms', createScimRouter({
    repository: new MemoryScimRepository(),
    authenticate: async ({ realm, token }) => token === `token-${realm}`,
    realmExists: async (realm) => ['master', 'staff'].includes(realm),
    maxPageSize: 20,
    defaultPageSize: 20,
  }));
  return app;
}

function client(app, realm = 'master') {
  const root = `/scim/v2/realms/${realm}`;
  const authorization = `Bearer token-${realm}`;
  return {
    get: (path) => request(app).get(`${root}${path}`).set('Authorization', authorization),
    post: (path) => request(app).post(`${root}${path}`).set('Authorization', authorization).set('Content-Type', 'application/scim+json'),
  };
}

function user(userName, values = {}) {
  return { schemas: [SCIM_URNS.user], userName, active: true, ...values };
}

test('sortBy and sortOrder sort strings case-insensitively in both directions', async () => {
  const app = fixture();
  const scim = client(app);
  await scim.post('/Users').send(user('zulu')).expect(201);
  await scim.post('/Users').send(user('Alpha')).expect(201);
  await scim.post('/Users').send(user('bravo')).expect(201);

  let response = await scim.get('/Users').query({ sortBy: 'userName' });
  assert.deepEqual(response.body.Resources.map(({ userName }) => userName), ['Alpha', 'bravo', 'zulu']);
  response = await scim.get('/Users').query({ sortBy: 'userName', sortOrder: 'descending' });
  assert.deepEqual(response.body.Resources.map(({ userName }) => userName), ['zulu', 'bravo', 'Alpha']);
});

test('sorting multi-valued attributes uses the primary value and orders missing values per RFC 7644', async () => {
  const app = fixture();
  const scim = client(app);
  await scim.post('/Users').send(user('charlie', {
    title: 'Zulu',
    emails: [{ value: 'z-first@test', type: 'home' }, { value: 'b-primary@test', type: 'work', primary: true }],
  })).expect(201);
  await scim.post('/Users').send(user('alice', {
    title: 'Alpha', emails: [{ value: 'a-primary@test', primary: true }],
  })).expect(201);
  await scim.post('/Users').send(user('missing', {
    emails: [{ value: 'c-primary@test', primary: true }],
  })).expect(201);

  let response = await scim.get('/Users').query({ sortBy: 'emails.value' });
  assert.deepEqual(response.body.Resources.map(({ userName }) => userName), ['alice', 'charlie', 'missing']);
  response = await scim.get('/Users').query({ sortBy: 'title', sortOrder: 'ascending' });
  assert.deepEqual(response.body.Resources.map(({ userName }) => userName), ['alice', 'charlie', 'missing']);
  response = await scim.get('/Users').query({ sortBy: 'title', sortOrder: 'descending' });
  assert.deepEqual(response.body.Resources.map(({ userName }) => userName), ['missing', 'charlie', 'alice']);
});

test('sorting uses an id tie-breaker so repeated and paginated results are stable', async () => {
  const app = fixture();
  const scim = client(app);
  const first = (await scim.post('/Users').send(user('one', { displayName: 'Same' }))).body;
  const second = (await scim.post('/Users').send(user('two', { displayName: 'same' }))).body;
  const expected = [first.id, second.id].sort((a, b) => a.localeCompare(b));

  const complete = await scim.get('/Users').query({ sortBy: 'displayName' });
  const repeated = await scim.get('/Users').query({ sortBy: 'displayName' });
  assert.deepEqual(complete.body.Resources.map(({ id }) => id), expected);
  assert.deepEqual(repeated.body.Resources.map(({ id }) => id), expected);

  const pageOne = await scim.get('/Users').query({ sortBy: 'displayName', startIndex: 1, count: 1 });
  const pageTwo = await scim.get('/Users').query({ sortBy: 'displayName', startIndex: 2, count: 1 });
  assert.deepEqual([pageOne.body.Resources[0].id, pageTwo.body.Resources[0].id], expected);
});

test('Groups sort independently by realm and invalid sort parameters use SCIM errors', async () => {
  const app = fixture();
  const master = client(app);
  const staff = client(app, 'staff');
  await master.post('/Groups').send({ schemas: [SCIM_URNS.group], displayName: 'Zulu' }).expect(201);
  await master.post('/Groups').send({ schemas: [SCIM_URNS.group], displayName: 'alpha' }).expect(201);
  await staff.post('/Groups').send({ schemas: [SCIM_URNS.group], displayName: 'Foreign' }).expect(201);

  let response = await master.get('/Groups').query({ sortBy: 'displayName' });
  assert.deepEqual(response.body.Resources.map(({ displayName }) => displayName), ['alpha', 'Zulu']);
  assert.equal(response.body.totalResults, 2);

  response = await master.get('/Users').query({ sortBy: 'unknown' });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'invalidValue');
  response = await master.get('/Users').query({ sortBy: 'userName', sortOrder: 'sideways' });
  assert.equal(response.status, 400);
  assert.equal(response.body.scimType, 'invalidValue');
  response = await master.get('/Users').query({ sortOrder: 'ascending' });
  assert.equal(response.status, 400);
});
