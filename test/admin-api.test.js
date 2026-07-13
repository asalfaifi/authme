import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { afterEach, test } from 'node:test';
import express from 'express';
import request from 'supertest';
import { createDataLayer } from '../src/db.js';
import { MemoryFederatedIdentityRepository } from '../src/repositories/federated-identity-repository.js';
import { createAdminRouter } from '../src/routes/admin.js';

const adminToken = 'admin-test-token-that-is-long-enough';
const openDataLayers = new Set();

async function fixture({ webauthn } = {}) {
  const data = await createDataLayer({ devMode: true, databaseUrl: undefined });
  openDataLayers.add(data);
  const config = {
    realms: ['master', 'other'],
    publicUrl: 'http://127.0.0.1:3000',
    adminToken,
    passwordPepper: 'test-password-pepper-that-is-long-enough',
    fieldEncryptionKey: Buffer.alloc(32, 7),
    subjectSalt: 'admin-passkey-subject-salt-that-is-long-enough',
    webauthnChallengeTtl: 300,
    enableDynamicRegistration: false,
    ldapProvidersByRealm: { master: [], other: [] },
    oidcProvidersByRealm: {
      master: [{ id: 'workforce', issuer: 'https://idp.example.test' }],
      other: [],
    },
    samlProvidersByRealm: { master: [], other: [] },
  };
  const federatedIdentities = new MemoryFederatedIdentityRepository(data.store, {
    disabledPasswordHash: 'disabled-federated-password-hash',
  });
  const rateLimits = { async consumeAdmin() {} };
  const metrics = { contentType: 'text/plain', async render() { return ''; } };
  const app = express();
  app.use('/admin', createAdminRouter({
    config,
    store: data.store,
    rateLimits,
    metrics,
    providers: new Map(),
    data,
    webauthn,
    federatedIdentities,
  }));
  app.use((error, _req, res, _next) => {
    res.status(500).json({ error: error.message });
  });
  return { app, data, federatedIdentities };
}

function passkeyService({ verify = true } = {}) {
  return {
    async registrationOptions({ realm, user, credentials }) {
      return {
        challenge: `registration-challenge-${realm}-012345678901234567890123`,
        rp: { id: '127.0.0.1', name: `AuthMe (${realm})` },
        user: { id: `opaque-handle-${user.id}`, name: user.username, displayName: user.name },
        excludeCredentials: credentials.map(({ id }) => ({ id })),
        pubKeyCredParams: [],
      };
    },
    async verifyRegistration({ response }) {
      if (!verify) throw new Error('invalid authenticator response');
      return {
        id: response.id,
        publicKey: Uint8Array.from([1, 2, 3, 4]),
        counter: 0,
        transports: ['internal'],
        deviceType: 'multiDevice',
        backedUp: true,
        aaguid: '00000000-0000-0000-0000-000000000000',
      };
    },
  };
}

function registrationResponse(id = 'passkey-credential_1') {
  return {
    id,
    rawId: id,
    type: 'public-key',
    response: {
      clientDataJSON: 'client-data',
      attestationObject: 'attestation-object',
      transports: ['internal'],
    },
  };
}

function authorized(agent) {
  return agent.set('Authorization', `Bearer ${adminToken}`);
}

afterEach(async () => {
  await Promise.all([...openDataLayers].map((data) => data.close()));
  openDataLayers.clear();
});

test('admin user routes reject malformed UUIDs and pagination', async () => {
  const { app } = await fixture();

  const invalidId = await authorized(request(app).get('/admin/v1/realms/master/users/not-a-uuid'));
  assert.equal(invalidId.status, 400);
  assert.equal(invalidId.body.title, 'Invalid user identifier');

  for (const query of ['limit=0', 'limit=251', 'limit=1x', 'offset=-1', 'offset=1.5']) {
    const response = await authorized(request(app).get(`/admin/v1/realms/master/users?${query}`));
    assert.equal(response.status, 400, query);
    assert.equal(response.body.title, 'Invalid pagination');
  }
});

test('federated identities require an exact configured provider and explicit admin linking', async () => {
  const { app, data } = await fixture();
  const user = await data.store.createUser({
    realm: 'master', username: 'federated-owner', email: 'owner@example.test', passwordHash: 'hash',
  });
  const path = `/admin/v1/realms/master/users/${user.id}/federated-identities`;
  const identity = {
    providerId: 'workforce',
    issuer: 'https://idp.example.test',
    externalSubject: 'upstream-subject-1',
  };

  const unknown = await authorized(request(app).post(path).send({
    ...identity, issuer: 'https://lookalike.example.test',
  }));
  assert.equal(unknown.status, 400);
  const malformedSubject = await authorized(request(app).post(path).send({
    ...identity, externalSubject: 'subject\u0000suffix',
  }));
  assert.equal(malformedSubject.status, 400);

  const linked = await authorized(request(app).post(path).send(identity));
  assert.equal(linked.status, 201);
  assert.equal(linked.body.userId, user.id);
  assert.equal(linked.body.externalSubject, identity.externalSubject);

  const listed = await authorized(request(app).get(path));
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.identities.map(({ externalSubject }) => externalSubject), ['upstream-subject-1']);

  const duplicate = await authorized(request(app).post(path).send(identity));
  assert.equal(duplicate.status, 201);
  assert.equal(duplicate.body.userId, user.id);

  const removed = await authorized(request(app).delete(path).send({
    providerId: identity.providerId, issuer: identity.issuer,
  }));
  assert.equal(removed.status, 204);
  assert.deepEqual((await authorized(request(app).get(path))).body.identities, []);
  const types = (await data.store.listAudit('master')).map(({ type }) => type);
  assert.ok(types.includes('admin.user.federated_identity_linked'));
  assert.ok(types.includes('admin.user.federated_identity_unlinked'));
});

test('session revocation invalidates all account-bound state and bumps the security epoch', async () => {
  const { app, data } = await fixture();
  const user = await data.store.createUser({
    realm: 'master', username: 'session-owner', email: 'session-owner@example.test', passwordHash: 'hash',
  });
  const Adapter = data.adapterFor('master');
  const sessions = new Adapter('Session');
  const grants = new Adapter('Grant');
  const tokens = new Adapter('AccessToken');
  await sessions.upsert('session', { accountId: user.id }, 600);
  await grants.upsert('grant', { accountId: user.id }, 600);
  await tokens.upsert('token', { accountId: user.id, grantId: 'grant', clientId: 'app' }, 600);

  const response = await authorized(
    request(app).post(`/admin/v1/realms/master/users/${user.id}/sessions/revoke`),
  );
  assert.equal(response.status, 204);
  assert.equal(await sessions.find('session'), undefined);
  assert.equal(await grants.find('grant'), undefined);
  assert.equal(await tokens.find('token'), undefined);
  assert.equal((await data.store.findUserById('master', user.id)).securityVersion, 1);
  assert.equal((await data.store.listAudit('master')).some(({ type }) => type === 'admin.user.sessions_revoked'), true);

  const missing = await authorized(
    request(app).post(`/admin/v1/realms/master/users/${randomUUID()}/sessions/revoke`),
  );
  assert.equal(missing.status, 404);
});

test('user deletion is idempotent, realm-isolated, and revokes account artifacts', async () => {
  const { app, data } = await fixture();
  const id = randomUUID();
  await data.store.createUser({
    id, realm: 'master', username: 'delete-me', email: 'delete-me@example.test', passwordHash: 'hash',
  });
  await data.store.createUser({
    id, realm: 'other', username: 'keep-me', email: 'keep-me@example.test', passwordHash: 'hash',
  });
  const MasterAdapter = data.adapterFor('master');
  const OtherAdapter = data.adapterFor('other');
  const masterSession = new MasterAdapter('Session');
  const otherSession = new OtherAdapter('Session');
  await masterSession.upsert('same-session', { accountId: id }, 600);
  await otherSession.upsert('same-session', { accountId: id }, 600);

  const [first, second] = await Promise.all([
    authorized(request(app).delete(`/admin/v1/realms/master/users/${id}`)),
    authorized(request(app).delete(`/admin/v1/realms/master/users/${id}`)),
  ]);
  assert.equal(first.status, 204);
  assert.equal(second.status, 204);
  assert.equal(await data.store.findUserById('master', id), null);
  assert.equal((await data.store.findUserById('other', id)).username, 'keep-me');
  assert.equal(await masterSession.find('same-session'), undefined);
  assert.notEqual(await otherSession.find('same-session'), undefined);

  const deletionEvents = (await data.store.listAudit('master'))
    .filter(({ type }) => type === 'admin.user.deleted');
  assert.equal(deletionEvents.length, 1);
});

test('an audit failure rolls back in-memory user deletion before artifact revocation', async () => {
  const { app, data } = await fixture();
  const user = await data.store.createUser({
    realm: 'master',
    username: 'audit-rollback',
    email: 'audit-rollback@example.test',
    passwordHash: 'hash',
  });
  const Adapter = data.adapterFor('master');
  const sessions = new Adapter('Session');
  const grants = new Adapter('Grant');
  const tokens = new Adapter('AccessToken');
  await sessions.upsert('rollback-session', { accountId: user.id }, 600);
  await grants.upsert('rollback-grant', { accountId: user.id }, 600);
  await tokens.upsert('rollback-token', { accountId: user.id, grantId: 'rollback-grant' }, 600);

  const writeAudit = data.store.writeAudit.bind(data.store);
  data.store.writeAudit = async () => { throw new Error('injected audit failure'); };
  const response = await authorized(request(app).delete(`/admin/v1/realms/master/users/${user.id}`));
  data.store.writeAudit = writeAudit;

  assert.equal(response.status, 500);
  assert.equal((await data.store.findUserById('master', user.id)).username, user.username);
  assert.notEqual(await sessions.find('rollback-session'), undefined);
  assert.notEqual(await grants.find('rollback-grant'), undefined);
  assert.notEqual(await tokens.find('rollback-token'), undefined);
  assert.equal(
    (await data.store.listAudit('master')).some(({ type }) => type === 'admin.user.deleted'),
    false,
  );
});

test('an audit failure rolls back an in-memory security mutation', async () => {
  const { app, data } = await fixture();
  const user = await data.store.createUser({
    realm: 'master', username: 'rollback-patch', email: 'before@example.test', passwordHash: 'hash',
  });
  data.store.writeAudit = async () => { throw new Error('audit unavailable'); };

  const response = await authorized(request(app)
    .patch(`/admin/v1/realms/master/users/${user.id}`)
    .send({ email: 'after@example.test' }));
  assert.equal(response.status, 500);
  const current = await data.store.findUserById('master', user.id);
  assert.equal(current.email, 'before@example.test');
  assert.equal(current.securityVersion, 0);
});

test('admin passkey registration is one-use, audited, listed safely, and revokes account state', async () => {
  const { app, data } = await fixture({ webauthn: passkeyService() });
  const user = await data.store.createUser({
    realm: 'master', username: 'passkey-user', email: 'passkey@example.test', passwordHash: 'hash',
  });
  const options = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/options`));
  assert.equal(options.status, 201);
  assert.equal(options.body.publicKey.user.name, user.username);
  assert.equal(options.body.expiresIn, 300);

  const registered = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/verify`)
    .send({
      challengeId: options.body.challengeId,
      name: 'Alice phone',
      response: registrationResponse(),
    }));
  assert.equal(registered.status, 201);
  assert.equal(registered.body.id, 'passkey-credential_1');
  assert.equal(registered.body.name, 'Alice phone');
  assert.equal(registered.body.publicKey, undefined);
  assert.equal(registered.body.userHandle, undefined);
  assert.equal(registered.body.counter, undefined);
  assert.equal((await data.store.findUserById('master', user.id)).securityVersion, 1);

  const replay = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/verify`)
    .send({ challengeId: options.body.challengeId, response: registrationResponse() }));
  assert.equal(replay.status, 409);

  const listed = await authorized(request(app)
    .get(`/admin/v1/realms/master/users/${user.id}/passkeys`));
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.passkeys.map(({ id }) => id), ['passkey-credential_1']);
  assert.equal(listed.body.passkeys[0].publicKey, undefined);

  const removed = await authorized(request(app)
    .delete(`/admin/v1/realms/master/users/${user.id}/passkeys/passkey-credential_1`));
  assert.equal(removed.status, 204);
  assert.equal((await data.store.findUserById('master', user.id)).securityVersion, 2);
  assert.deepEqual(await data.store.listWebAuthnCredentials('master', user.id), []);
  const types = (await data.store.listAudit('master')).map(({ type }) => type);
  assert.ok(types.includes('admin.user.passkey_registered'));
  assert.ok(types.includes('admin.user.passkey_deleted'));
});

test('failed passkey verification consumes its challenge and leaves no credential', async () => {
  const { app, data } = await fixture({ webauthn: passkeyService({ verify: false }) });
  const user = await data.store.createUser({
    realm: 'master', username: 'bad-passkey', email: 'bad-passkey@example.test', passwordHash: 'hash',
  });
  const options = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/options`));
  const body = { challengeId: options.body.challengeId, response: registrationResponse() };
  const failed = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/verify`)
    .send(body));
  assert.equal(failed.status, 400);
  const replay = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/verify`)
    .send(body));
  assert.equal(replay.status, 409);
  assert.deepEqual(await data.store.listWebAuthnCredentials('master', user.id), []);
  assert.equal((await data.store.findUserById('master', user.id)).securityVersion, 0);
});

test('an audit failure rolls back in-memory passkey registration', async () => {
  const { app, data } = await fixture({ webauthn: passkeyService() });
  const user = await data.store.createUser({
    realm: 'master', username: 'passkey-rollback', email: 'passkey-rollback@example.test', passwordHash: 'hash',
  });
  const options = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/options`));
  data.store.writeAudit = async () => { throw new Error('audit unavailable'); };
  const response = await authorized(request(app)
    .post(`/admin/v1/realms/master/users/${user.id}/passkeys/registration/verify`)
    .send({ challengeId: options.body.challengeId, response: registrationResponse() }));
  assert.equal(response.status, 500);
  assert.deepEqual(await data.store.listWebAuthnCredentials('master', user.id), []);
  assert.equal((await data.store.findUserById('master', user.id)).securityVersion, 0);
});
