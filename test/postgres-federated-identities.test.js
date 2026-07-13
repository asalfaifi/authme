import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';

import { PostgresFederatedIdentityRepository } from '../src/repositories/federated-identity-repository.js';

const databaseUrl = process.env.DATABASE_URL;
const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
const realm = `fed-a-${suffix}`;
const otherRealm = `fed-b-${suffix}`;
let pool;

const profile = (username) => ({
  username,
  email: `${username}@example.test`,
  emailVerified: true,
  name: username,
  roles: ['developer'],
  groups: ['/engineering'],
});

before(async () => {
  if (!databaseUrl) return;
  pool = new pg.Pool({ connectionString: databaseUrl, max: 8, application_name: 'authme-federation-test' });
  await pool.query(
    'INSERT INTO realms (name,display_name) VALUES ($1,$2),($3,$4)',
    [realm, realm, otherRealm, otherRealm],
  );
});

after(async () => {
  if (!pool) return;
  await pool.query('DELETE FROM realms WHERE name=ANY($1)', [[realm, otherRealm]]);
  await pool.end();
});

test('PostgreSQL federated identities are opt-in, realm-scoped, race-safe, and idempotent', {
  skip: !databaseUrl,
}, async () => {
  const repository = new PostgresFederatedIdentityRepository(pool, { disabledPasswordHash: '!federated!' });
  const identity = {
    realm,
    providerId: 'workforce',
    issuer: 'https://idp.example.test',
    externalSubject: 'subject-1',
    profile: profile(`alice-${suffix}`),
  };

  assert.equal((await repository.resolve(identity)).status, 'not_found');
  const created = await repository.resolve({ ...identity, allowCreate: true });
  assert.equal(created.status, 'created');
  assert.equal((await repository.resolve(identity)).status, 'resolved');
  assert.equal((await repository.resolve({ ...identity, realm: otherRealm, allowCreate: true })).status, 'created');

  const collision = await repository.resolve({
    ...identity,
    providerId: 'partner',
    issuer: 'https://partner.example.test',
    externalSubject: 'partner-subject',
    allowCreate: true,
  });
  assert.equal(collision.status, 'link_required');
  assert.equal(collision.user.id, created.user.id);

  const concurrentProfile = profile(`race-${suffix}`);
  const concurrent = await Promise.all([
    repository.resolve({
      realm, providerId: 'race-one', issuer: 'https://race-one.example.test',
      externalSubject: 'race-subject-1', profile: concurrentProfile, allowCreate: true,
    }),
    repository.resolve({
      realm, providerId: 'race-two', issuer: 'https://race-two.example.test',
      externalSubject: 'race-subject-2', profile: concurrentProfile, allowCreate: true,
    }),
  ]);
  assert.deepEqual(concurrent.map(({ status }) => status).sort(), ['created', 'link_required']);

  const link = {
    realm,
    userId: created.user.id,
    providerId: 'explicit',
    issuer: 'https://explicit.example.test',
    externalSubject: 'explicit-subject',
  };
  assert.deepEqual((await Promise.all([repository.link(link), repository.link(link)]))
    .map(({ status }) => status), ['linked', 'linked']);
  assert.equal((await repository.link({ ...link, externalSubject: 'other-subject' })).status, 'conflict');

  await pool.query('UPDATE users SET enabled=false WHERE realm_name=$1 AND id=$2', [realm, created.user.id]);
  assert.equal((await repository.resolve(identity)).status, 'disabled');

  await assert.rejects(
    pool.query(
      `INSERT INTO federated_identities
       (realm_name,provider_id,issuer,external_subject,user_id,profile)
       VALUES ($1,'invalid-control',$2,'subject',$3,'{}')`,
      [realm, 'https://idp.example.test\ninvalid', created.user.id],
    ),
    (error) => error.code === '23514',
  );
});
