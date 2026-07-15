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
    maxPageSize: 50,
    defaultPageSize: 50,
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
  return {
    schemas: [SCIM_URNS.user],
    userName,
    displayName: userName,
    active: true,
    emails: [{ value: `${userName}@corp.test`, type: 'work', primary: true }],
    ...values,
  };
}

async function names(scim, filter) {
  const response = await scim.get('/Users').query({ filter });
  assert.equal(response.status, 200, response.text);
  return response.body.Resources.map(({ userName }) => userName).sort();
}

async function seeded() {
  const app = fixture();
  const scim = client(app);
  const alice = (await scim.post('/Users').send(user('alice', {
    displayName: 'Alice Adams', title: 'Engineer', userType: 'Employee',
    emails: [
      { value: 'alice@corp.test', type: 'work', primary: true },
      { value: 'alice@personal.test', type: 'home' },
    ],
  }))).body;
  const bob = (await scim.post('/Users').send(user('bob', {
    displayName: 'Bob Brown', userType: 'Intern', active: false,
    emails: [{ value: 'bob@other.test', type: 'work', primary: true }],
  }))).body;
  const carol = (await scim.post('/Users').send(user('carol', {
    displayName: 'Carol Clark', title: 'Analyst', userType: 'Employee',
    emails: [{ value: 'carol@corp.test', type: 'home', primary: true }],
  }))).body;
  return { app, scim, alice, bob, carol };
}

test('SCIM filter comparison and presence operators follow schema comparison rules', async () => {
  const { scim } = await seeded();
  const matrix = [
    ['userName eq "ALICE"', ['alice']],
    ['userName ne "alice"', ['bob', 'carol']],
    ['displayName co "LIC"', ['alice']],
    ['userName sw "A"', ['alice']],
    ['userName ew "OL"', ['carol']],
    ['userName gt "bob"', ['carol']],
    ['userName ge "bob"', ['bob', 'carol']],
    ['userName lt "bob"', ['alice']],
    ['userName le "bob"', ['alice', 'bob']],
    ['title pr', ['alice', 'carol']],
    ['active eq false', ['bob']],
    ['active ne "false"', ['alice', 'carol']],
  ];
  for (const [filter, expected] of matrix) assert.deepEqual(await names(scim, filter), expected, filter);

  assert.deepEqual(
    await names(scim, `${SCIM_URNS.user}:userName eq "alice"`),
    ['alice'],
  );
});

test('SCIM filter logical precedence, not, and parenthesised expressions are deterministic', async () => {
  const { scim } = await seeded();
  assert.deepEqual(
    await names(scim, 'userType eq "Employee" and title eq "Engineer" or userName eq "bob"'),
    ['alice', 'bob'],
  );
  assert.deepEqual(
    await names(scim, 'userType eq "Employee" and not (title eq "Engineer")'),
    ['carol'],
  );
  assert.deepEqual(
    await names(scim, '(userName eq "alice" or userName eq "bob") and active eq true'),
    ['alice'],
  );
});

test('SCIM complex value filters correlate predicates to the same multi-valued item', async () => {
  const { scim, alice } = await seeded();
  assert.deepEqual(
    await names(scim, 'emails[type eq "work" and value ew "@corp.test"]'),
    ['alice'],
  );
  assert.deepEqual(
    await names(scim, 'emails[type eq "home" and value co "@corp.test"]'),
    ['carol'],
  );
  assert.deepEqual(await names(scim, 'emails.value co "@other.test"'), ['bob']);

  await scim.post('/Groups').send({
    schemas: [SCIM_URNS.group], displayName: 'Engineering', members: [{ value: alice.id }],
  }).expect(201);
  const groups = await scim.get('/Groups').query({ filter: `members[value eq "${alice.id}"]` });
  assert.equal(groups.status, 200);
  assert.deepEqual(groups.body.Resources.map(({ displayName }) => displayName), ['Engineering']);
});

test('invalid filter syntax, types, attributes, and complex paths return invalidFilter', async () => {
  const { scim } = await seeded();
  const invalid = [
    'userName regex "alice"',
    'unknown eq "value"',
    'active gt true',
    'active co "tr"',
    'title[type eq "work"]',
    'emails[userName eq "alice"]',
    'not userName eq "alice"',
    '(userName eq "alice"',
  ];
  for (const filter of invalid) {
    const response = await scim.get('/Users').query({ filter });
    assert.equal(response.status, 400, filter);
    assert.equal(response.body.scimType, 'invalidFilter', filter);
    assert.deepEqual(response.body.schemas, [SCIM_URNS.error]);
  }
});

test('filtering remains realm-isolated', async () => {
  const { app, scim } = await seeded();
  const staff = client(app, 'staff');
  await staff.post('/Users').send(user('foreign', { title: 'Engineer' })).expect(201);
  assert.deepEqual(await names(scim, 'userName eq "foreign"'), []);
  assert.deepEqual(await names(staff, 'title pr'), ['foreign']);
});
