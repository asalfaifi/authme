import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import { after, before, test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import express from 'express';
import * as OTPAuth from 'otpauth';
import supertest from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { hashPassword, verifyPassword } from '../src/crypto/password.js';
import { keyedDigest, randomToken } from '../src/crypto/secrets.js';
import { createAccountConsole } from '../src/routes/account-console.js';

const CSRF_SECRET = 'authme-account-test-csrf-secret-0000000001';
const PASSWORD_PEPPER = 'authme-account-test-password-pepper-000001';
const initialPassword = 'Account-Console-Initial-Password-2026!';
let currentPassword = initialPassword;
let runtime;
let server;
let baseUrl;
let user;
let otherUser;
let deliveries;

function cookiePathMatches(requestPath, cookiePath) {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

function defaultCookiePath(pathname) {
  const separator = pathname.lastIndexOf('/');
  return separator <= 0 ? '/' : pathname.slice(0, separator);
}

class CookieClient {
  constructor(origin) {
    this.origin = origin;
    this.cookies = new Map();
    this.lastSetCookies = [];
  }

  cookie(name, path = '/realms/master/account') {
    return this.cookies.get(`${name}\u0000${path}`)?.value;
  }

  collect(response, requestUrl) {
    this.lastSetCookies = response.headers.getSetCookie();
    for (const raw of this.lastSetCookies) {
      const parts = raw.split(';').map((part) => part.trim());
      const separator = parts[0].indexOf('=');
      if (separator <= 0) continue;
      const name = parts[0].slice(0, separator);
      const value = parts[0].slice(separator + 1);
      const attributes = new Map(parts.slice(1).map((attribute) => {
        const index = attribute.indexOf('=');
        return [(index < 0 ? attribute : attribute.slice(0, index)).toLowerCase(), index < 0 ? true : attribute.slice(index + 1)];
      }));
      const path = typeof attributes.get('path') === 'string' ? attributes.get('path') : defaultCookiePath(requestUrl.pathname);
      const key = `${name}\u0000${path}`;
      const maxAge = Number(attributes.get('max-age'));
      if (!value || maxAge === 0) this.cookies.delete(key);
      else this.cookies.set(key, { name, value, path, secure: attributes.has('secure') });
    }
  }

  async request(path, options = {}) {
    const url = new URL(path, this.origin);
    const headers = new Headers(options.headers);
    const cookie = [...this.cookies.values()]
      .filter((item) => cookiePathMatches(url.pathname, item.path) && (!item.secure || url.protocol === 'https:'))
      .sort((left, right) => right.path.length - left.path.length)
      .map((item) => `${item.name}=${item.value}`)
      .join('; ');
    if (cookie) headers.set('cookie', cookie);
    headers.set('user-agent', 'AuthMe account console integration test');
    const response = await fetch(url, { ...options, headers, redirect: 'manual' });
    this.collect(response, url);
    return response;
  }

  get(path, headers = {}) { return this.request(path, { headers }); }

  postForm(path, body = {}, headers = {}) {
    return this.request(path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded;charset=UTF-8', origin: this.origin, ...headers },
      body: new URLSearchParams(body),
    });
  }

  json(path, method, body, headers = {}) {
    return this.request(path, {
      method,
      headers: { 'content-type': 'application/json', origin: this.origin, ...headers },
      body: JSON.stringify(body),
    });
  }
}

function redirect(response) {
  assert([301, 302, 303, 307, 308].includes(response.status), `Expected redirect, received ${response.status}`);
  return new URL(response.headers.get('location'), baseUrl);
}

function csrfFrom(html) {
  const match = /name="csrf" value="([^"]+)"/u.exec(html);
  assert(match, 'Interaction page did not contain CSRF');
  return match[1];
}

async function loginAccount({ realm = 'master', password = currentPassword, otp = '' } = {}) {
  const client = new CookieClient(baseUrl);
  let response = await client.postForm(`/realms/${realm}/account/login`);
  const authorization = redirect(response);
  assert.equal(authorization.searchParams.get('client_id'), 'authme-account-console');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorization.searchParams.get('redirect_uri'), `${baseUrl}/realms/${realm}/account/oidc/callback`);
  assert.equal(authorization.searchParams.has('code_verifier'), false);
  assert.match(client.lastSetCookies.find((value) => value.startsWith('authme_account_login=')) ?? '', /Path=\/realms\/(?:master|staff)\/account\/oidc\/callback/iu);

  response = await client.get(authorization);
  let target = redirect(response);
  response = await client.get(target);
  const loginPage = await response.text();
  assert.match(loginPage, /Welcome back/u);
  response = await client.postForm(`${target.pathname}/login`, {
    csrf: csrfFrom(loginPage),
    login: user.username,
    password,
    otp,
  });
  for (let step = 0; step < 12; step += 1) {
    target = redirect(response);
    if (target.pathname === `/realms/${realm}/account/oidc/callback`) {
      response = await client.get(target);
      assert.equal(response.status, 303, await response.clone().text());
      assert.equal(redirect(response).pathname, `/realms/${realm}/account/`);
      const cookie = client.lastSetCookies.find((value) => value.startsWith('authme_account_console='));
      assert.match(cookie ?? '', /HttpOnly/iu);
      assert.match(cookie ?? '', /SameSite=Strict/iu);
      assert.match(cookie ?? '', new RegExp(`Path=\\/realms\\/${realm}\\/account`, 'u'));
      return client;
    }
    response = await client.get(target);
    if ([301, 302, 303, 307, 308].includes(response.status)) continue;
    const page = await response.text();
    assert.match(page, /\/confirm/u);
    response = await client.postForm(`${target.pathname}/confirm`, { csrf: csrfFrom(page) });
  }
  assert.fail('Account authorization did not reach its callback');
}

async function sessionFor(client, realm = 'master') {
  const response = await client.get(`/realms/${realm}/account/api/session`);
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(response.headers.get('cache-control'), 'no-store');
  return body;
}

async function eventually(read, message) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const value = read();
    if (value) return value;
    await delay(10);
  }
  assert.fail(message);
}

function resetOnlyApp({ devMode, delivery, logger }) {
  const config = Object.freeze({
    ...runtime.config,
    devMode,
    publicUrl: 'https://accounts.example.test',
  });
  const app = express();
  app.use('/realms/master/account', createAccountConsole({
    realm: 'master',
    config,
    store: runtime.store,
    data: runtime.data,
    rateLimits: {
      async consumeAccount() {},
      async consumePasswordReset() {},
    },
    jwks: { keys: [] },
    webauthn: {},
    logger,
    delivery,
  }).router);
  return { app, config };
}

async function listen(httpServer) {
  await new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(0, '127.0.0.1', () => { httpServer.off('error', reject); resolve(); });
  });
}

before(async () => {
  server = createHttpServer();
  await listen(server);
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
  deliveries = { verification: [], reset: [] };
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: baseUrl,
    AUTHME_PORT: String(address.port),
    AUTHME_REALMS: 'master,staff',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_ADMIN_TOKEN: 'authme-account-test-admin-token-00000000001',
    AUTHME_COOKIE_KEYS: 'authme-account-test-cookie-key-000000000001',
    AUTHME_CSRF_SECRET: CSRF_SECRET,
    AUTHME_PASSWORD_PEPPER: PASSWORD_PEPPER,
    AUTHME_SUBJECT_SALT: 'authme-account-test-subject-salt-000000001',
    AUTHME_FIELD_ENCRYPTION_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    AUTHME_DEV_ADMIN_PASSWORD: 'AuthMe-Account-Test-Admin-Password-2026!',
  });
  const webauthn = {
    async registrationOptions({ user, credentials }) {
      return {
        challenge: 'account-console-registration-challenge-0123456789',
        rp: { name: 'AuthMe', id: '127.0.0.1' },
        user: { id: 'account-console-user-handle', name: user.username, displayName: user.name },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 300_000,
        excludeCredentials: credentials.map((credential) => ({ id: credential.id, type: 'public-key' })),
      };
    },
    async verifyRegistration({ response }) {
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
    async authenticationOptions() { throw new Error('Passkey authentication is not used in this test'); },
  };
  runtime = await createAuthMeApp(config, {
    webauthn,
    accountEmailSender: {
      async sendEmailVerification(message) { deliveries.verification.push(message); },
      async sendPasswordReset(message) { deliveries.reset.push(message); },
    },
  });
  user = await runtime.store.createUser({
    id: randomUUID(),
    realm: 'master',
    username: 'account-owner',
    email: 'account-owner@example.test',
    name: 'Account Owner',
    passwordHash: await hashPassword(initialPassword, PASSWORD_PEPPER),
  });
  await runtime.store.createUser({
    id: user.id,
    realm: 'staff',
    username: user.username,
    email: 'staff-account-owner@example.test',
    name: 'Staff Account Owner',
    passwordHash: await hashPassword(initialPassword, PASSWORD_PEPPER),
  });
  otherUser = await runtime.store.createUser({
    realm: 'master',
    username: 'different-user',
    email: 'different-user@example.test',
    passwordHash: await hashPassword('Different-User-Password-2026!', PASSWORD_PEPPER),
  });
  server.on('request', runtime.app);
});

after(async () => {
  server?.closeIdleConnections();
  if (server?.listening) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await runtime?.close();
});

test('account console requires its real OIDC login and enforces origin, CSRF, JSON, self-scope, and realm boundaries', { timeout: 120_000 }, async () => {
  const anonymous = new CookieClient(baseUrl);
  let response = await anonymous.get('/realms/master/account/api/session');
  assert.equal(response.status, 401);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  response = await anonymous.get('/realms/master/account/');
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-security-policy') ?? '', /default-src 'none'/u);

  const client = await loginAccount();
  const session = await sessionFor(client);
  assert.equal(session.user.username, user.username);
  assert.match(session.csrf, /^[A-Za-z0-9_-]{43}$/u);
  const opaque = client.cookie('authme_account_console');
  const digest = createHmac('sha256', CSRF_SECRET)
    .update(`authme-account-console-session-v1\u0000master\u0000${opaque}`)
    .digest('base64url');
  assert.equal(await runtime.store.findAccountSession(opaque), null);
  assert.equal((await runtime.store.findAccountSession(digest)).userId, user.id);

  const profile = { email: user.email, name: 'Safe Name', givenName: 'Safe', familyName: 'Name' };
  response = await client.json('/realms/master/account/api/profile', 'PATCH', profile);
  assert.equal(response.status, 403);
  response = await client.json('/realms/master/account/api/profile', 'PATCH', profile, {
    'x-authme-csrf': session.csrf,
    origin: 'http://attacker.example.test',
  });
  assert.equal(response.status, 403);
  response = await client.postForm('/realms/master/account/api/profile', profile, { 'x-authme-csrf': session.csrf });
  assert.equal(response.status, 415);
  response = await client.json(`/realms/master/account/api/profile/${otherUser.id}`, 'PATCH', profile, { 'x-authme-csrf': session.csrf });
  assert.equal(response.status, 404);
  assert.equal((await runtime.store.findUserById('master', otherUser.id)).name, otherUser.name);

  const forgedRealmClient = new CookieClient(baseUrl);
  forgedRealmClient.cookies.set('authme_account_console\u0000/realms/staff/account', {
    name: 'authme_account_console', value: opaque, path: '/realms/staff/account', secure: false,
  });
  response = await forgedRealmClient.get('/realms/staff/account/api/session');
  assert.equal(response.status, 401, 'A master realm account session crossed into staff');
});

test('profile email verification and password reset tokens are single-use, realm-bound, enumeration-safe, and rate-limited', { timeout: 120_000 }, async () => {
  let client = await loginAccount();
  let session = await sessionFor(client);
  const newEmail = 'new-account-owner@example.test';
  let response = await client.json('/realms/master/account/api/profile', 'PATCH', {
    email: newEmail,
    name: '<Account & Owner>',
    givenName: 'Account',
    familyName: 'Owner',
  }, { 'x-authme-csrf': session.csrf });
  const profileResult = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(Object.keys(profileResult), ['message']);
  assert.equal((await runtime.store.findUserById('master', user.id)).email, user.email, 'Unverified email was committed early');
  assert.equal(deliveries.verification.at(-1).email, newEmail);
  const verificationToken = deliveries.verification.at(-1).token;
  assert.match(verificationToken, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(JSON.stringify(profileResult).includes(verificationToken), false);

  response = await client.json('/realms/staff/account/email-verification/confirm', 'POST', { token: verificationToken });
  assert.equal(response.status, 400, 'An email token crossed realms');
  response = await client.json('/realms/master/account/email-verification/confirm', 'POST', { token: verificationToken });
  assert.equal(response.status, 204);
  response = await client.json('/realms/master/account/email-verification/confirm', 'POST', { token: verificationToken });
  assert.equal(response.status, 400, 'An email token was reusable');
  user = await runtime.store.findUserById('master', user.id);
  assert.equal(user.email, newEmail);
  assert.equal(user.emailVerified, true);

  const expiredVerification = randomToken(32);
  await runtime.store.createAccountActionToken({
    realm: 'master',
    userId: user.id,
    type: 'email-verification',
    tokenDigest: keyedDigest(
      `authme-account-action-v1\u0000master\u0000email-verification\u0000${expiredVerification}`,
      PASSWORD_PEPPER,
    ),
    email: 'expired-verification@example.test',
    expiresAt: new Date(Date.now() - 1_000),
  });
  response = await client.json('/realms/master/account/email-verification/confirm', 'POST', { token: expiredVerification });
  assert.equal(response.status, 400, 'An expired email verification token was accepted');
  assert.equal((await runtime.store.findUserById('master', user.id)).email, newEmail);

  const resetClient = new CookieClient(baseUrl);
  const resetDeliveriesBefore = deliveries.reset.length;
  const existingResponse = await resetClient.json('/realms/master/account/password-reset', 'POST', { email: newEmail });
  const existingBody = await existingResponse.json();
  const absentResponse = await resetClient.json('/realms/master/account/password-reset', 'POST', { email: 'absent@example.test' });
  const absentBody = await absentResponse.json();
  assert.equal(existingResponse.status, 202);
  assert.equal(absentResponse.status, 202);
  assert.deepEqual(existingBody, absentBody);
  assert.deepEqual(Object.keys(existingBody), ['message']);
  const resetDelivery = await eventually(
    () => deliveries.reset.length > resetDeliveriesBefore && deliveries.reset.at(-1),
    'Password reset delivery was not dispatched',
  );
  assert.equal(resetDelivery.email, newEmail);
  assert.match(resetDelivery.token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(JSON.stringify(existingBody).includes(resetDelivery.token), false);
  const resetPage = await resetClient.get(`/realms/master/account/reset-password?token=${resetDelivery.token}`);
  assert.equal(resetPage.status, 200);
  assert.equal((await resetPage.text()).includes(resetDelivery.token), false, 'Action token was reflected into an HTML response');
  response = await resetClient.json('/realms/master/account/password-reset/confirm', 'POST', {
    token: randomToken(32),
    newPassword: 'Absent-Account-Password-2026!',
  });
  assert.equal(response.status, 400);

  const resetPassword = 'Account-Console-Reset-Password-2026!';
  response = await resetClient.json('/realms/master/account/password-reset/confirm', 'POST', {
    token: resetDelivery.token,
    newPassword: resetPassword,
  });
  assert.equal(response.status, 204);
  response = await resetClient.json('/realms/master/account/password-reset/confirm', 'POST', {
    token: resetDelivery.token,
    newPassword: 'Account-Console-Replay-Password-2026!',
  });
  assert.equal(response.status, 400);
  currentPassword = resetPassword;
  assert.equal(await verifyPassword((await runtime.store.findUserById('master', user.id)).passwordHash, currentPassword, PASSWORD_PEPPER), true);

  const originalLimit = runtime.rateLimits.consumePasswordReset;
  runtime.rateLimits.consumePasswordReset = async () => { throw { msBeforeNext: 2_100 }; };
  try {
    response = await resetClient.json('/realms/master/account/password-reset', 'POST', { email: newEmail });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get('retry-after'), '3');
  } finally {
    runtime.rateLimits.consumePasswordReset = originalLimit;
  }

  client = await loginAccount();
  session = await sessionFor(client);
  response = await client.json('/realms/master/account/api/password', 'PUT', {
    currentPassword: 'wrong-current-password',
    newPassword: 'Account-Console-Wrong-Attempt-2026!',
  }, { 'x-authme-csrf': session.csrf });
  assert.equal(response.status, 403);
  const changedPassword = 'Account-Console-Changed-Password-2026!';
  response = await client.json('/realms/master/account/api/password', 'PUT', {
    currentPassword,
    newPassword: changedPassword,
  }, { 'x-authme-csrf': session.csrf });
  assert.equal(response.status, 204);
  currentPassword = changedPassword;
  assert.equal((await client.get('/realms/master/account/api/session')).status, 401, 'Password change did not invalidate the console session');
});

test('password reset is response-independent in production and never returns its delivery token', { timeout: 120_000 }, async () => {
  const deliveryStarted = Promise.withResolvers();
  const releaseDelivery = Promise.withResolvers();
  const delivered = [];
  const logs = [];
  const { app, config } = resetOnlyApp({
    devMode: false,
    delivery: {
      async sendPasswordReset(message) {
        delivered.push(message);
        deliveryStarted.resolve();
        await releaseDelivery.promise;
      },
    },
    logger: {
      error: (...entry) => logs.push(entry),
      warn: (...entry) => logs.push(entry),
    },
  });

  const responsePromise = supertest(app)
    .post('/realms/master/account/password-reset')
    .set('origin', config.publicUrl)
    .send({ email: otherUser.email })
    .then((response) => response);
  await deliveryStarted.promise;
  const responseBeforeDelivery = await Promise.race([
    responsePromise,
    delay(500).then(() => null),
  ]);
  releaseDelivery.resolve();
  const existingResponse = await responsePromise;
  assert.notEqual(responseBeforeDelivery, null, 'Password reset response waited for account-specific delivery work');
  assert.equal(existingResponse.status, 202);
  assert.deepEqual(Object.keys(existingResponse.body), ['message']);
  assert.match(delivered[0].token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(JSON.stringify(existingResponse.body).includes(delivered[0].token), false);

  const absentResponse = await supertest(app)
    .post('/realms/master/account/password-reset')
    .set('origin', config.publicUrl)
    .send({ email: 'production-absent@example.test' });
  assert.equal(absentResponse.status, 202);
  assert.deepEqual(absentResponse.body, existingResponse.body);
  assert.equal(JSON.stringify(logs).includes(delivered[0].token), false);
});

test('malformed and oversized account JSON never logs request secrets', async () => {
  const secrets = {
    currentPassword: 'Malformed-Current-Password-Secret!',
    newPassword: 'Malformed-New-Password-Secret!',
    token: 'MalformedTokenSecretValue',
    totp: '654321',
    recoveryCodes: 'Malformed-Recovery-Code-Secret',
  };
  const logs = [];
  const originalWarn = runtime.logger.warn;
  const originalError = runtime.logger.error;
  runtime.logger.warn = (entry) => logs.push(entry);
  runtime.logger.error = (entry) => logs.push(entry);
  const client = new CookieClient(baseUrl);
  let malformedResponse;
  let oversizedResponse;
  try {
    malformedResponse = await client.request('/realms/master/account/api/password', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', origin: baseUrl },
      body: `{"currentPassword":${secrets.currentPassword},"newPassword":"${secrets.newPassword}","token":"${secrets.token}"}`,
    });
    oversizedResponse = await client.request('/realms/master/account/api/password', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', origin: baseUrl },
      body: JSON.stringify({ ...secrets, padding: 'x'.repeat(70 * 1024) }),
    });
  } finally {
    runtime.logger.warn = originalWarn;
    runtime.logger.error = originalError;
  }
  assert.equal(malformedResponse.status, 400);
  assert.equal(oversizedResponse.status, 413);
  assert.equal(malformedResponse.headers.get('cache-control'), 'no-store');
  assert.equal(oversizedResponse.headers.get('cache-control'), 'no-store');
  assert.equal(logs.length, 2);
  const serialized = JSON.stringify(logs);
  for (const [field, value] of Object.entries(secrets)) {
    assert.equal(serialized.includes(field), false, `${field} field name was logged`);
    assert.equal(serialized.includes(value), false, `${field} value was logged`);
  }
  assert.equal(serialized.includes('"body":'), false, 'Raw request body metadata was logged');
  for (const entry of logs) assert.deepEqual(Object.keys(entry.error).sort(), ['code', 'message', 'name']);
});

test('users manage only their own MFA, recovery codes, passkeys, and active sessions', { timeout: 120_000 }, async () => {
  let client = await loginAccount();
  let session = await sessionFor(client);
  let response = await client.json('/realms/master/account/api/mfa/totp', 'POST', {}, { 'x-authme-csrf': session.csrf });
  const setup = await response.json();
  assert.equal(response.status, 201);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const totp = new OTPAuth.TOTP({
    algorithm: 'SHA1', digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(setup.secret),
  });
  response = await client.json('/realms/master/account/api/mfa/totp/confirm', 'POST', { token: totp.generate() }, { 'x-authme-csrf': session.csrf });
  let recoveryCodes = (await response.json()).recoveryCodes;
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(recoveryCodes.length, 10);
  assert.equal((await client.get('/realms/master/account/api/session')).status, 401);

  client = await loginAccount({ otp: recoveryCodes.shift() });
  session = await sessionFor(client);
  assert.equal(session.user.mfaEnabled, true);
  response = await client.json('/realms/master/account/api/mfa/recovery-codes', 'POST', {}, { 'x-authme-csrf': session.csrf });
  recoveryCodes = (await response.json()).recoveryCodes;
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(recoveryCodes.length, 10);

  client = await loginAccount({ otp: recoveryCodes.shift() });
  session = await sessionFor(client);
  response = await client.json('/realms/master/account/api/passkeys/registration/options', 'POST', {}, { 'x-authme-csrf': session.csrf });
  const options = await response.json();
  assert.equal(response.status, 201);
  response = await client.json('/realms/master/account/api/passkeys/registration/verify', 'POST', {
    challengeId: options.challengeId,
    name: '<Primary passkey>',
    response: {
      id: 'account-owner-passkey',
      rawId: 'account-owner-passkey',
      type: 'public-key',
      response: { clientDataJSON: 'Y2xpZW50', attestationObject: 'YXR0ZXN0YXRpb24', transports: ['internal'] },
    },
  }, { 'x-authme-csrf': session.csrf });
  assert.equal(response.status, 201);
  await runtime.store.createWebAuthnCredential({
    realm: 'master',
    userId: otherUser.id,
    id: 'other-user-passkey',
    userHandle: 'other-user-handle',
    publicKey: Uint8Array.from([5, 6, 7]),
    counter: 0,
    transports: ['internal'],
    deviceType: 'singleDevice',
    backedUp: false,
    aaguid: '00000000-0000-0000-0000-000000000000',
    name: 'Other passkey',
  });

  client = await loginAccount({ otp: recoveryCodes.shift() });
  session = await sessionFor(client);
  response = await client.json('/realms/master/account/api/passkeys/other-user-passkey', 'DELETE', {}, { 'x-authme-csrf': session.csrf });
  assert.equal(response.status, 404);
  assert.notEqual(await runtime.store.findWebAuthnCredential('master', 'other-user-passkey'), null, 'Another user passkey was removed');
  response = await client.get('/realms/master/account/api/passkeys');
  const passkeys = (await response.json()).passkeys;
  assert.deepEqual(passkeys.map((passkey) => passkey.id), ['account-owner-passkey']);
  assert.equal(passkeys[0].name, '<Primary passkey>');

  const secondClient = await loginAccount({ otp: recoveryCodes.shift() });
  const secondSession = await sessionFor(secondClient);
  response = await secondClient.get('/realms/master/account/api/sessions');
  const sessions = (await response.json()).sessions;
  assert(sessions.some((item) => item.kind === 'oidc'));
  const firstAccountSession = sessions.find((item) => item.kind === 'account-console' && !item.current);
  assert(firstAccountSession);
  const originalWriteAudit = runtime.store.writeAudit;
  runtime.store.writeAudit = async function writeAuditWithFailure(event) {
    if (event.type === 'account.session.revoked') throw new Error('Deliberate session audit failure');
    return originalWriteAudit.call(this, event);
  };
  try {
    response = await secondClient.json(`/realms/master/account/api/sessions/${firstAccountSession.reference}`, 'DELETE', {}, { 'x-authme-csrf': secondSession.csrf });
    assert.equal(response.status, 500);
    assert.equal((await client.get('/realms/master/account/api/session')).status, 200, 'Session mutation committed before its audit record');
  } finally {
    runtime.store.writeAudit = originalWriteAudit;
  }
  response = await secondClient.json(`/realms/master/account/api/sessions/${firstAccountSession.reference}`, 'DELETE', {}, { 'x-authme-csrf': secondSession.csrf });
  assert.equal(response.status, 204);
  assert.equal((await client.get('/realms/master/account/api/session')).status, 401, 'Revoked account-console session stayed active');

  runtime.store.writeAudit = async function writeAuditWithFailure(event) {
    if (event.type === 'account.console.logout') throw new Error('Deliberate logout audit failure');
    return originalWriteAudit.call(this, event);
  };
  try {
    response = await secondClient.json('/realms/master/account/api/logout', 'POST', {}, { 'x-authme-csrf': secondSession.csrf });
    assert.equal(response.status, 500);
    assert.equal((await secondClient.get('/realms/master/account/api/session')).status, 200, 'Logout committed before its audit record');
  } finally {
    runtime.store.writeAudit = originalWriteAudit;
  }
  response = await secondClient.json('/realms/master/account/api/logout', 'POST', {}, { 'x-authme-csrf': secondSession.csrf });
  assert.equal(response.status, 204);
  assert.equal((await secondClient.get('/realms/master/account/api/session')).status, 401);
});
