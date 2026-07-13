import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MemoryIdentityStore } from '../src/repositories/identity-store.js';
import { MemoryFederatedIdentityRepository } from '../src/repositories/federated-identity-repository.js';

const profile = {
  username: 'alice', email: 'alice@example.test', emailVerified: true, name: 'Alice Example',
  roles: ['developer'], groups: ['/engineering'],
};

test('federated identity resolution is stable, realm-bound, and does not auto-link collisions', async () => {
  const store = new MemoryIdentityStore();
  const repository = new MemoryFederatedIdentityRepository(store, { disabledPasswordHash: 'unusable-password-hash' });
  const first = await repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test',
    externalSubject: 'subject-1', profile, allowCreate: true,
  });
  assert.equal(first.status, 'created');
  assert.equal(first.user.username, 'alice');
  assert.equal(first.user.passwordHash, 'unusable-password-hash');
  const second = await repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test',
    externalSubject: 'subject-1', profile: { ...profile, name: 'Changed upstream name' },
  });
  assert.equal(second.status, 'resolved');
  assert.equal(second.user.id, first.user.id);
  assert.equal(second.user.name, 'Alice Example');

  const collision = await repository.resolve({
    realm: 'staff', providerId: 'partner', issuer: 'https://partner.example.test',
    externalSubject: 'different-subject', profile, allowCreate: true,
  });
  assert.equal(collision.status, 'link_required');
  assert.equal(collision.user.id, first.user.id);

  const otherRealm = await repository.resolve({
    realm: 'other', providerId: 'workforce', issuer: 'https://idp.example.test',
    externalSubject: 'subject-1', profile, allowCreate: true,
  });
  assert.equal(otherRealm.status, 'created');
  assert.notEqual(otherRealm.user.id, first.user.id);
});

test('explicit federation links cannot be reassigned or multiplied per provider', async () => {
  const store = new MemoryIdentityStore();
  const user = await store.createUser({
    realm: 'staff', username: 'local', email: 'local@example.test', name: 'Local', passwordHash: 'hash',
  });
  const other = await store.createUser({
    realm: 'staff', username: 'other', email: 'other@example.test', name: 'Other', passwordHash: 'hash',
  });
  const repository = new MemoryFederatedIdentityRepository(store, { disabledPasswordHash: 'unusable' });
  const input = {
    realm: 'staff', userId: user.id, providerId: 'workforce', issuer: 'https://idp.example.test',
    externalSubject: 'subject-1',
  };
  assert.equal((await repository.link(input)).status, 'linked');
  assert.equal((await repository.link(input)).status, 'linked');
  assert.equal((await repository.link({ ...input, userId: other.id })).status, 'conflict');
  assert.equal((await repository.link({ ...input, externalSubject: 'subject-2' })).status, 'conflict');
  assert.equal((await repository.list('staff', user.id)).length, 1);
  assert.equal((await repository.unlink({
    realm: 'staff', userId: user.id, providerId: 'workforce', issuer: 'https://idp.example.test',
  })).externalSubject, 'subject-1');
  assert.equal((await repository.list('staff', user.id)).length, 0);
});

test('disabled linked accounts remain denied and JIT can be disabled', async () => {
  const store = new MemoryIdentityStore();
  const repository = new MemoryFederatedIdentityRepository(store, { disabledPasswordHash: 'unusable' });
  const created = await repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test', externalSubject: 'subject-1', profile,
    allowCreate: true,
  });
  await store.updateUser('staff', created.user.id, { enabled: false });
  assert.equal((await repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test', externalSubject: 'subject-1', profile,
  })).status, 'disabled');
  assert.equal((await repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test', externalSubject: 'subject-2',
    profile: { ...profile, username: 'bob', email: 'bob@example.test' }, allowCreate: false,
  })).status, 'not_found');
});

test('JIT creation is opt-in and identity key delimiters are rejected', async () => {
  const repository = new MemoryFederatedIdentityRepository(new MemoryIdentityStore(), { disabledPasswordHash: 'unusable' });
  assert.equal((await repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test', externalSubject: 'subject-1', profile,
  })).status, 'not_found');
  await assert.rejects(repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test\0other',
    externalSubject: 'subject-1', profile, allowCreate: true,
  }), (error) => error.code === 'AUTHME_FEDERATED_IDENTITY_INVALID');
  await assert.rejects(repository.resolve({
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test',
    externalSubject: 'subject-1\0other', profile, allowCreate: true,
  }), (error) => error.code === 'AUTHME_FEDERATED_IDENTITY_INVALID');
});

test('concurrent JIT and explicit links preserve account and provider uniqueness', async () => {
  const store = new MemoryIdentityStore();
  const repository = new MemoryFederatedIdentityRepository(store, { disabledPasswordHash: 'unusable' });
  const resolutions = await Promise.all([
    repository.resolve({
      realm: 'staff', providerId: 'first-idp', issuer: 'https://first.example.test',
      externalSubject: 'subject-1', profile, allowCreate: true,
    }),
    repository.resolve({
      realm: 'staff', providerId: 'second-idp', issuer: 'https://second.example.test',
      externalSubject: 'subject-2', profile, allowCreate: true,
    }),
  ]);
  assert.deepEqual(resolutions.map(({ status }) => status).sort(), ['created', 'link_required']);

  const user = resolutions.find(({ status }) => status === 'created').user;
  const links = await Promise.all([
    repository.link({
      realm: 'staff', userId: user.id, providerId: 'partner', issuer: 'https://partner.example.test',
      externalSubject: 'partner-1',
    }),
    repository.link({
      realm: 'staff', userId: user.id, providerId: 'partner', issuer: 'https://partner.example.test',
      externalSubject: 'partner-2',
    }),
  ]);
  assert.deepEqual(links.map(({ status }) => status).sort(), ['conflict', 'linked']);
});
