import assert from 'node:assert/strict';
import { test } from 'node:test';
import express from 'express';
import request from 'supertest';

import { createCsrfToken } from '../src/crypto/csrf.js';
import { MemoryIdentityStore } from '../src/repositories/identity-store.js';
import { createInteractionRouter } from '../src/routes/interactions.js';

const realm = 'master';
const uid = 'interaction-uid-one';
const csrfSecret = 'passkey-interaction-csrf-secret-long-enough';

function providerFixture(finished) {
  return {
    Client: { async find() { return { clientId: 'console', clientName: 'Console' }; } },
    async interactionDetails() {
      return { uid, prompt: { name: 'login' }, params: { client_id: 'console' } };
    },
    async interactionFinished(_req, res, result, options) {
      finished.push({ result, options });
      res.status(204).end();
    },
  };
}

function assertion(id, userHandle) {
  return {
    id,
    rawId: id,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: 'client-data',
      authenticatorData: 'authenticator-data',
      signature: 'assertion-signature',
      userHandle,
    },
  };
}

async function fixture() {
  const store = new MemoryIdentityStore();
  const finished = [];
  const verifyCalls = [];
  const webauthn = {
    async authenticationOptions() {
      return {
        challenge: 'authentication-challenge-012345678901234567890123456789',
        rpId: 'login.example.test',
        userVerification: 'required',
      };
    },
    async verifyAuthentication(input) {
      verifyCalls.push(input);
      return { newCounter: input.credential.counter + 1, deviceType: 'singleDevice', backedUp: false };
    },
  };
  const config = {
    csrfSecret,
    webauthnChallengeTtl: 300,
    publicUrl: 'https://login.example.test',
    subjectSalt: 'passkey-subject-salt-that-is-long-enough',
  };
  const app = express();
  app.use(createInteractionRouter({
    realm,
    provider: providerFixture(finished),
    store,
    config,
    rateLimits: { async consumeLogin() {} },
    dummyPasswordHash: 'unused',
    logger: { warn() {} },
    webauthn,
  }));
  app.use((error, _req, res, _next) => res.status(error.status ?? 500).send(error.message));
  return { app, finished, store, verifyCalls };
}

test('a verified passkey assertion completes the OIDC login and cannot be replayed', async () => {
  const { app, finished, store, verifyCalls } = await fixture();
  const user = await store.createUser({
    realm,
    username: 'passkey-login',
    email: 'passkey-login@example.test',
    passwordHash: 'unused',
  });
  const credential = await store.createWebAuthnCredential({
    realm,
    userId: user.id,
    id: 'credential_login-1',
    userHandle: 'opaque-user-handle_1',
    publicKey: Uint8Array.from([1, 2, 3]),
    counter: 12,
    transports: ['internal'],
    deviceType: 'singleDevice',
    backedUp: false,
    aaguid: '00000000-0000-0000-0000-000000000000',
    name: 'Laptop',
  });
  const csrf = createCsrfToken(`${realm}:${uid}:login`, csrfSecret);
  const options = await request(app)
    .post(`/realms/${realm}/interaction/${uid}/passkey/options`)
    .type('form')
    .send({ csrf });
  assert.equal(options.status, 201);

  const body = {
    csrf,
    challengeId: options.body.challengeId,
    credential: JSON.stringify(assertion(credential.id, credential.userHandle)),
  };
  const completed = await request(app)
    .post(`/realms/${realm}/interaction/${uid}/passkey`)
    .type('form')
    .send(body);
  assert.equal(completed.status, 204);
  assert.equal(finished.length, 1);
  assert.deepEqual(finished[0], {
    result: {
      login: {
        accountId: user.id,
        acr: 'urn:authme:loa:2',
        amr: ['passkey'],
        remember: true,
      },
    },
    options: { mergeWithLastSubmission: false },
  });
  assert.equal(verifyCalls[0].challenge, options.body.publicKey.challenge);
  assert.equal(verifyCalls[0].credential.id, credential.id);
  assert.equal((await store.findWebAuthnCredential(realm, credential.id)).counter, 13);
  assert.equal((await store.findUserById(realm, user.id)).failedAttempts, 0);
  assert.equal((await store.listAudit(realm))[0].metadata.amr[0], 'passkey');

  const replay = await request(app)
    .post(`/realms/${realm}/interaction/${uid}/passkey`)
    .type('form')
    .send(body);
  assert.equal(replay.status, 401);
  assert.equal(finished.length, 1);
  assert.equal(verifyCalls.length, 1);
  assert.equal((await store.findWebAuthnCredential(realm, credential.id)).counter, 13);
});

test('passkey assertions cannot cross realm or user-handle boundaries', async () => {
  const { app, finished, store, verifyCalls } = await fixture();
  const id = '8afe7ddd-bafb-45e8-a771-10a34d50ce9f';
  await store.createUser({
    id,
    realm: 'staff',
    username: 'staff-passkey',
    email: 'staff-passkey@example.test',
    passwordHash: 'unused',
  });
  await store.createWebAuthnCredential({
    realm: 'staff',
    userId: id,
    id: 'staff-only-credential',
    userHandle: 'staff-user-handle',
    publicKey: Uint8Array.from([4, 5, 6]),
    counter: 0,
    transports: ['internal'],
    deviceType: 'multiDevice',
    backedUp: true,
    aaguid: '00000000-0000-0000-0000-000000000000',
    name: 'Staff phone',
  });
  const csrf = createCsrfToken(`${realm}:${uid}:login`, csrfSecret);
  const options = await request(app)
    .post(`/realms/${realm}/interaction/${uid}/passkey/options`)
    .type('form')
    .send({ csrf });
  const response = await request(app)
    .post(`/realms/${realm}/interaction/${uid}/passkey`)
    .type('form')
    .send({
      csrf,
      challengeId: options.body.challengeId,
      credential: JSON.stringify(assertion('staff-only-credential', 'staff-user-handle')),
    });
  assert.equal(response.status, 401);
  assert.equal(finished.length, 0);
  assert.equal(verifyCalls.length, 0);
});
