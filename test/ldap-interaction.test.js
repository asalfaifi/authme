import assert from 'node:assert/strict';
import { test } from 'node:test';
import express from 'express';
import request from 'supertest';

import { createCsrfToken } from '../src/crypto/csrf.js';
import { hashPassword } from '../src/crypto/password.js';
import { MemoryFederatedIdentityRepository } from '../src/repositories/federated-identity-repository.js';
import { MemoryIdentityStore } from '../src/repositories/identity-store.js';
import { createInteractionRouter } from '../src/routes/interactions.js';

const realm = 'master';
const uid = 'ldap-interaction-one';
const csrfSecret = 'ldap-interaction-csrf-secret-long-enough';
const passwordPepper = 'ldap-interaction-password-pepper-long-enough';

async function fixture({ existingUser = false } = {}) {
  const store = new MemoryIdentityStore();
  const dummyPasswordHash = await hashPassword('disabled password value', passwordPepper);
  if (existingUser) {
    await store.createUser({
      realm,
      username: 'alice',
      email: 'alice@example.test',
      passwordHash: dummyPasswordHash,
    });
  }
  const federatedIdentities = new MemoryFederatedIdentityRepository(store, { disabledPasswordHash: dummyPasswordHash });
  const finished = [];
  const provider = {
    Client: { async find() { return { clientId: 'console', clientName: 'Console' }; } },
    async interactionDetails() {
      return { uid, prompt: { name: 'login' }, params: { client_id: 'console' } };
    },
    async interactionFinished(_req, res, result, options) {
      finished.push({ result, options });
      res.status(204).end();
    },
  };
  const identityRuntime = {
    federatedIdentities,
    federationEntriesFor: () => [],
    ldap: {
      implementation: {
        enabledFor: () => true,
        async authenticate({ login, secret }) {
          if (login !== 'alice' || secret !== 'directory-secret') return { status: 'failure' };
          return {
            status: 'success',
            protocol: 'ldap',
            providerId: 'corporate-directory',
            issuer: 'ldaps://directory.example.test',
            allowCreate: true,
            profile: {
              externalSubject: 'entry-uuid-alice',
              username: 'alice',
              email: 'alice@example.test',
              name: 'Alice Directory',
              roles: ['employee'],
              groups: ['/engineering'],
            },
          };
        },
      },
    },
  };
  const app = express();
  app.use(createInteractionRouter({
    realm,
    provider,
    store,
    config: { csrfSecret, passwordPepper },
    rateLimits: { async consumeLogin() {} },
    dummyPasswordHash,
    logger: { warn() {} },
    webauthn: {},
    identityRuntime,
  }));
  app.use((error, _req, res, _next) => res.status(error.status ?? 500).send(error.message));
  return { app, finished, store, federatedIdentities };
}

test('LDAP authentication uses immutable federation linking and reports LDAP AMR', async () => {
  const { app, finished, store, federatedIdentities } = await fixture();
  const response = await request(app)
    .post(`/realms/${realm}/interaction/${uid}/login`)
    .type('form')
    .send({
      csrf: createCsrfToken(`${realm}:${uid}:login`, csrfSecret),
      login: 'alice',
      password: 'directory-secret',
    });
  assert.equal(response.status, 204);
  assert.equal(finished.length, 1);
  assert.deepEqual(finished[0].result.login.amr, ['ldap']);
  const user = await store.findUserByLogin(realm, 'alice');
  assert.equal(user.name, 'Alice Directory');
  assert.deepEqual(user.groups, ['/engineering']);
  assert.equal((await federatedIdentities.list(realm, user.id))[0].externalSubject, 'entry-uuid-alice');
  assert.equal((await store.listAudit(realm))[0].metadata.amr[0], 'ldap');
});

test('LDAP never auto-links a colliding local account', async () => {
  const { app, finished, store, federatedIdentities } = await fixture({ existingUser: true });
  const response = await request(app)
    .post(`/realms/${realm}/interaction/${uid}/login`)
    .type('form')
    .send({
      csrf: createCsrfToken(`${realm}:${uid}:login`, csrfSecret),
      login: 'alice',
      password: 'directory-secret',
    });
  assert.equal(response.status, 401);
  assert.equal(finished.length, 0);
  const user = await store.findUserByLogin(realm, 'alice');
  assert.deepEqual(await federatedIdentities.list(realm, user.id), []);
});
