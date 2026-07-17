import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, before, test } from 'node:test';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34976';
const host = new URL(base).host;
const redirectUri = 'http://127.0.0.1:49176/callback';
const realms = ['master', 'staff'];
let runtime;

function csrf(html) {
  const match = /name="csrf" value="([^"]+)"/u.exec(html);
  assert(match, 'The form did not include a CSRF token');
  return match[1];
}

function realmClients() {
  return [{
    client_id: 'signup-client',
    client_name: 'Signup application',
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    redirect_uris: [redirectUri],
    response_types: ['code'],
    grant_types: ['authorization_code'],
    allow_user_registration: true,
  }, {
    client_id: 'closed-client',
    client_name: 'Closed application',
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    redirect_uris: [redirectUri],
    response_types: ['code'],
    grant_types: ['authorization_code'],
  }];
}

async function beginAuthorization(realm, clientId = 'signup-client') {
  const agent = request.agent(runtime.app);
  const verifier = randomBytes(32).toString('base64url');
  let response = await agent.get(`/realms/${realm}/protocol/openid-connect/auth`).set('host', host).query({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: randomBytes(16).toString('base64url'),
  });
  for (let step = 0; step < 5 && [302, 303].includes(response.status); step += 1) {
    const target = new URL(response.headers.location, base);
    assert.equal(target.origin, new URL(base).origin, 'Authorization redirected before the login interaction');
    response = await agent.get(`${target.pathname}${target.search}`).set('host', host);
  }
  assert.equal(response.status, 200, response.text);
  assert.match(response.text, /data-password-login/u);
  return {
    agent,
    verifier,
    interactionPath: new URL(response.request.url).pathname,
    login: response,
  };
}

async function finishAuthorization(realm, flow, response) {
  for (let step = 0; step < 8; step += 1) {
    if ([302, 303].includes(response.status)) {
      const target = new URL(response.headers.location, base);
      if (target.origin === new URL(redirectUri).origin) return target;
      response = await flow.agent.get(`${target.pathname}${target.search}`).set('host', host);
      continue;
    }
    if (response.status === 200 && response.text.includes('/confirm"')) {
      const interactionPath = new URL(response.request.url).pathname.replace(/\/$/u, '');
      response = await flow.agent.post(`${interactionPath}/confirm`).set('host', host).type('form')
        .send({ csrf: csrf(response.text) });
      continue;
    }
    break;
  }
  assert.fail(`Registration authorization did not complete in ${realm}; status ${response.status}: ${String(response.text).slice(0, 1000)}`);
}

before(async () => {
  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34976',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_REALMS: realms.join(','),
    AUTHME_CLIENTS_JSON: JSON.stringify(Object.fromEntries(realms.map((realm) => [realm, realmClients()]))),
  }));
});

after(async () => runtime?.close());

test('an opted-in application creates and signs in a user independently in each realm', async () => {
  for (const realm of realms) {
    const flow = await beginAuthorization(realm);
    assert.match(flow.login.text, /Create an account/u);
    const registration = await flow.agent.get(`${flow.interactionPath}/register`).set('host', host).expect(200);
    assert.match(registration.text, new RegExp(`belongs only to the ${realm} realm`, 'u'));

    const submitted = await flow.agent.post(`${flow.interactionPath}/register`).set('host', host).type('form').send({
      csrf: csrf(registration.text),
      username: 'new-user',
      email: 'new-user@example.test',
      name: 'New User',
      password: 'A-strong-registration-password-2026!',
      passwordConfirmation: 'A-strong-registration-password-2026!',
    });
    assert.equal([302, 303].includes(submitted.status), true, submitted.text);

    const callback = await finishAuthorization(realm, flow, submitted);
    const token = await request(runtime.app).post(`/realms/${realm}/protocol/openid-connect/token`)
      .set('host', host).type('form').send({
        grant_type: 'authorization_code',
        client_id: 'signup-client',
        redirect_uri: redirectUri,
        code: callback.searchParams.get('code'),
        code_verifier: flow.verifier,
      }).expect(200);
    assert.equal(typeof token.body.id_token, 'string');

    const user = await runtime.store.findUserByLogin(realm, 'new-user');
    assert.equal(user.email, 'new-user@example.test');
    assert.equal(user.emailVerified, false);
    const audit = await runtime.store.listAudit(realm);
    assert.equal(audit.some((event) => event.type === 'identity.registration.succeeded'
      && event.subjectId === user.id && event.clientId === 'signup-client'), true);
  }

  const master = await runtime.store.findUserByLogin('master', 'new-user');
  const staff = await runtime.store.findUserByLogin('staff', 'new-user');
  assert.notEqual(master.id, staff.id);
});

test('applications without the opt-in cannot expose or call account creation', async () => {
  const flow = await beginAuthorization('master', 'closed-client');
  assert.doesNotMatch(flow.login.text, /Create an account/u);
  const response = await flow.agent.get(`${flow.interactionPath}/register`).set('host', host);
  assert.equal(response.status, 403);
  assert.equal(await runtime.store.findUserByLogin('master', 'closed-user'), null);
});

test('an audit failure rolls back a newly registered account', async () => {
  const flow = await beginAuthorization('master');
  const registration = await flow.agent.get(`${flow.interactionPath}/register`).set('host', host).expect(200);
  const writeAudit = runtime.store.writeAudit.bind(runtime.store);
  runtime.store.writeAudit = async (event) => {
    if (event.type === 'identity.registration.succeeded') throw new Error('audit unavailable');
    return writeAudit(event);
  };
  try {
    const response = await flow.agent.post(`${flow.interactionPath}/register`).set('host', host).type('form').send({
      csrf: csrf(registration.text),
      username: 'rollback-user',
      email: 'rollback-user@example.test',
      name: 'Rollback User',
      password: 'A-strong-registration-password-2026!',
      passwordConfirmation: 'A-strong-registration-password-2026!',
    });
    assert.equal(response.status, 500);
  } finally {
    runtime.store.writeAudit = writeAudit;
  }
  assert.equal(await runtime.store.findUserByLogin('master', 'rollback-user'), null);
});
