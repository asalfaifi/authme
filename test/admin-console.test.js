import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const ADMIN_PASSWORD = 'AuthMe-Console-Test-Password-2026!';
const ROOT_TOKEN = 'authme-console-test-root-token-000000000001';
const CSRF_SECRET = 'authme-console-test-csrf-secret-0000000001';

function adminSessionDigest(value) {
  return createHmac('sha256', CSRF_SECRET)
    .update(`authme-admin-console-session-v1\u0000${value}`)
    .digest('base64url');
}

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
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookies = new Map();
    this.lastSetCookies = [];
  }

  clone() {
    const copy = new CookieClient(this.baseUrl);
    copy.cookies = structuredClone(this.cookies);
    return copy;
  }

  cookie(name, path = '/admin') {
    return this.cookies.get(`${name}\u0000${path}`)?.value;
  }

  replaceCookie(name, path, value) {
    const key = `${name}\u0000${path}`;
    const current = this.cookies.get(key);
    assert(current, `Cookie ${name} at ${path} was not available`);
    this.cookies.set(key, { ...current, value });
  }

  collectCookies(response, requestUrl) {
    this.lastSetCookies = response.headers.getSetCookie();
    for (const raw of this.lastSetCookies) {
      const parts = raw.split(';').map((part) => part.trim());
      const separator = parts[0].indexOf('=');
      if (separator <= 0) continue;
      const name = parts[0].slice(0, separator);
      const value = parts[0].slice(separator + 1);
      const attributes = new Map();
      for (const attribute of parts.slice(1)) {
        const attributeSeparator = attribute.indexOf('=');
        const key = (attributeSeparator < 0 ? attribute : attribute.slice(0, attributeSeparator)).toLowerCase();
        const attributeValue = attributeSeparator < 0 ? true : attribute.slice(attributeSeparator + 1);
        attributes.set(key, attributeValue);
      }
      const path = typeof attributes.get('path') === 'string'
        ? attributes.get('path')
        : defaultCookiePath(requestUrl.pathname);
      const key = `${name}\u0000${path}`;
      const maxAge = Number(attributes.get('max-age'));
      const expires = Date.parse(String(attributes.get('expires') ?? ''));
      if (!value || maxAge === 0 || (Number.isFinite(expires) && expires <= Date.now())) {
        this.cookies.delete(key);
        continue;
      }
      this.cookies.set(key, {
        name,
        value,
        path,
        secure: attributes.has('secure'),
      });
    }
  }

  cookieHeader(url) {
    return [...this.cookies.values()]
      .filter((cookie) => cookiePathMatches(url.pathname, cookie.path)
        && (!cookie.secure || url.protocol === 'https:'))
      .sort((left, right) => right.path.length - left.path.length)
      .map(({ name, value }) => `${name}=${value}`)
      .join('; ');
  }

  async request(input, options = {}) {
    const url = new URL(input, this.baseUrl);
    const headers = new Headers(options.headers);
    const cookie = this.cookieHeader(url);
    if (cookie) headers.set('cookie', cookie);
    headers.set('user-agent', 'AuthMe admin console integration test');
    const response = await fetch(url, {
      ...options,
      headers,
      redirect: 'manual',
    });
    this.collectCookies(response, url);
    return response;
  }

  get(input, headers = {}) {
    return this.request(input, { headers });
  }

  postForm(input, values, headers = {}) {
    return this.request(input, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        origin: this.baseUrl,
        ...headers,
      },
      body: new URLSearchParams(values),
    });
  }

  postJson(input, body, headers = {}) {
    return this.request(input, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: this.baseUrl,
        ...headers,
      },
      body: JSON.stringify(body),
    });
  }
}

function redirectLocation(response, baseUrl) {
  assert([301, 302, 303, 307, 308].includes(response.status), `Expected a redirect, received ${response.status}`);
  const value = response.headers.get('location');
  assert(value, 'Redirect response did not include a Location header');
  return new URL(value, baseUrl);
}

function csrfFrom(html) {
  const match = /name="csrf" value="([^"]+)"/u.exec(html);
  assert(match, 'Interaction page did not include a CSRF token');
  return match[1];
}

async function startAdminLogin(client, { realm = 'master', login = 'admin', password = ADMIN_PASSWORD } = {}) {
  const response = await client.postForm('/admin/ui/login', {
    realm,
    login,
    password,
    otp: '',
  });
  assert.equal(response.status, 303);

  const authorization = redirectLocation(response, client.baseUrl);
  assert.equal(authorization.pathname, `/realms/${realm}/protocol/openid-connect/auth`);
  assert.equal(authorization.searchParams.get('client_id'), 'authme-admin-console');
  assert.equal(authorization.searchParams.get('response_type'), 'code');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.match(authorization.searchParams.get('code_challenge') ?? '', /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(authorization.searchParams.get('redirect_uri'), `${client.baseUrl}/admin/oidc/callback`);
  assert.match(authorization.searchParams.get('state') ?? '', /^[A-Za-z0-9_-]{20,}$/u);
  assert.match(authorization.searchParams.get('nonce') ?? '', /^[A-Za-z0-9_-]{20,}$/u);
  assert.equal(authorization.searchParams.has('code_verifier'), false);

  const loginCookie = client.lastSetCookies.find((value) => value.startsWith('authme_admin_login='));
  assert(loginCookie, 'Administrator login transaction cookie was not set');
  assert.match(loginCookie, /; HttpOnly(?:;|$)/iu);
  assert.match(loginCookie, /; SameSite=Lax(?:;|$)/iu);
  assert.match(loginCookie, /; Path=\/admin\/oidc\/callback(?:;|$)/iu);

  let interactionResponse = await client.get(authorization);
  const interactionUrl = redirectLocation(interactionResponse, client.baseUrl);
  assert.match(interactionUrl.pathname, new RegExp(`^/realms/${realm}/interaction/[^/]+$`, 'u'));
  interactionResponse = await client.get(interactionUrl);
  const html = await interactionResponse.text();
  assert.equal(interactionResponse.status, 200);
  assert.match(html, /Welcome back/u);

  return { interactionUrl, html };
}

async function finishAdminLogin(client, credentials = {}) {
  const { interactionUrl, html } = await startAdminLogin(client, credentials);
  let response = await client.postForm(`${interactionUrl}/login`, {
    csrf: csrfFrom(html),
    login: credentials.login ?? 'admin',
    password: credentials.password ?? ADMIN_PASSWORD,
    otp: credentials.otp ?? '',
  });

  for (let step = 0; step < 12; step += 1) {
    const target = redirectLocation(response, client.baseUrl);
    if (target.pathname === '/admin/oidc/callback') {
      const callback = await client.get(target);
      return { callback, callbackUrl: target };
    }

    response = await client.get(target);
    if ([301, 302, 303, 307, 308].includes(response.status)) continue;
    const page = await response.text();
    assert.equal(response.status, 200, `Unexpected authorization response: ${response.status}`);
    assert.match(page, /\/confirm/u, 'Authorization stopped on an unknown interaction page');
    response = await client.postForm(`${target}/confirm`, { csrf: csrfFrom(page) });
  }
  assert.fail('Administrator authorization did not return to the console callback');
}

async function loginGrantedAdmin(baseUrl, credentials = {}) {
  const client = new CookieClient(baseUrl);
  const { callback } = await finishAdminLogin(client, credentials);
  const callbackFailure = callback.status === 303 ? '' : await callback.clone().text();
  assert.equal(callback.status, 303, callbackFailure);
  assert.equal(redirectLocation(callback, baseUrl).pathname, '/admin/');

  const setCookie = client.lastSetCookies.find((value) => value.startsWith('authme_admin_console='));
  assert(setCookie, 'Administrator session cookie was not set');
  assert.match(setCookie, /; HttpOnly(?:;|$)/iu);
  assert.match(setCookie, /; SameSite=Strict(?:;|$)/iu);
  assert.match(setCookie, /; Path=\/admin(?:;|$)/iu);
  const value = client.cookie('authme_admin_console');
  assert.match(value ?? '', /^[A-Za-z0-9_-]{43}$/u);
  return client;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
}

async function closeServer(server) {
  if (!server.listening) return;
  server.closeIdleConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test('administrator console uses its real OIDC flow and enforces session boundaries', { timeout: 120_000 }, async () => {
  const server = createServer();
  let runtime;
  try {
    await listen(server);
    const address = server.address();
    assert(address && typeof address === 'object');
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const config = loadConfig({
      AUTHME_DEV_MODE: 'true',
      AUTHME_PUBLIC_URL: baseUrl,
      AUTHME_PORT: String(address.port),
      AUTHME_REALMS: 'master,staff',
      AUTHME_LOG_LEVEL: 'silent',
      AUTHME_ADMIN_TOKEN: ROOT_TOKEN,
      AUTHME_COOKIE_KEYS: 'authme-console-test-cookie-key-000000000001',
      AUTHME_CSRF_SECRET: CSRF_SECRET,
      AUTHME_PASSWORD_PEPPER: 'authme-console-test-password-pepper-000001',
      AUTHME_SUBJECT_SALT: 'authme-console-test-subject-salt-000000001',
      AUTHME_FIELD_ENCRYPTION_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      AUTHME_DEV_ADMIN_PASSWORD: ADMIN_PASSWORD,
    });
    runtime = await createAuthMeApp(config);
    server.on('request', runtime.app);

    const anonymous = new CookieClient(baseUrl);
    const loopbackAlias = new CookieClient(`http://localhost:${address.port}`);
    let response = await loopbackAlias.get('/admin/');
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), `${baseUrl}/admin/`);
    assert.equal(response.headers.get('cache-control'), 'no-store');

    response = await anonymous.get('/admin/');
    const loginHtml = await response.text();
    assert.equal(response.status, 200);
    assert.match(response.headers.get('cache-control') ?? '', /no-store/iu);
    assert.equal(
      response.headers.get('content-security-policy'),
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    assert.match(loginHtml, /action="\/admin\/ui\/login"/u);
    assert.doesNotMatch(loginHtml, new RegExp(ROOT_TOKEN, 'u'));

    const loginBody = new URLSearchParams({ realm: 'master' });
    for (const origin of [undefined, 'null', 'http://attacker.example.test']) {
      const headers = { 'content-type': 'application/x-www-form-urlencoded;charset=UTF-8' };
      if (origin) headers.origin = origin;
      const originResponse = await anonymous.request('/admin/ui/login', {
        method: 'POST',
        headers,
        body: loginBody,
        signal: AbortSignal.timeout(2_000),
      });
      const originBody = await originResponse.text();
      assert.equal(originResponse.status, 403, `${origin ? 'Cross-origin' : 'Origin-less'} login did not fail closed`);
      assert.equal(originResponse.headers.get('cache-control'), 'no-store');
      assert.match(originResponse.headers.get('content-type') ?? '', /^application\/problem\+json/iu);
      assert(originBody.length <= 512, 'Invalid-origin response was not bounded');
      assert.equal(JSON.parse(originBody).title, 'Invalid request origin');
    }
    const metadataFallback = await request(runtime.app)
      .post('/admin/ui/login')
      .set('host', `127.0.0.1:${address.port}`)
      .set('origin', 'null')
      .set('sec-fetch-site', 'same-origin')
      .set('sec-fetch-mode', 'navigate')
      .set('sec-fetch-dest', 'document')
      .type('form')
      .send(loginBody.toString());
    assert.equal(metadataFallback.status, 303);
    assert.match(metadataFallback.headers.location ?? '', /\/realms\/master\/protocol\/openid-connect\/auth\?/u);
    response = await anonymous.request('/admin/ui/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        origin: `http://localhost:${address.port}`,
      },
      body: loginBody,
    });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get('location'), `${baseUrl}/admin/`);

    const throttled = new CookieClient(baseUrl);
    throttled.cookies.set('authme_admin_console\u0000/admin', {
      name: 'authme_admin_console',
      value: 'x'.repeat(43),
      path: '/admin',
      secure: false,
    });
    const originalConsumeAdmin = runtime.rateLimits.consumeAdmin;
    const originalFindAdminSession = runtime.store.findAdminSession;
    let sessionLookups = 0;
    runtime.rateLimits.consumeAdmin = async () => { throw { msBeforeNext: 2_100 }; };
    runtime.store.findAdminSession = async (...arguments_) => {
      sessionLookups += 1;
      return originalFindAdminSession(...arguments_);
    };
    try {
      response = await throttled.get('/admin/ui/session');
      assert.equal(response.status, 429);
      assert.equal(response.headers.get('retry-after'), '3');
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(sessionLookups, 0, 'A durable console session was read before rate limiting');
    } finally {
      runtime.rateLimits.consumeAdmin = originalConsumeAdmin;
      runtime.store.findAdminSession = originalFindAdminSession;
    }

    const failedAuditClient = new CookieClient(baseUrl);
    const originalCreateAdminSession = runtime.store.createAdminSession.bind(runtime.store);
    const originalWriteAudit = runtime.store.writeAudit.bind(runtime.store);
    let failedSessionDigest;
    runtime.store.createAdminSession = async (input) => {
      failedSessionDigest = input.idDigest;
      return originalCreateAdminSession(input);
    };
    runtime.store.writeAudit = async (event) => {
      if (event.type === 'admin.console.login.succeeded') throw new Error('simulated console audit outage');
      return originalWriteAudit(event);
    };
    const failedLogin = await finishAdminLogin(failedAuditClient);
    assert.equal(failedLogin.callback.status, 403);
    assert.equal(failedAuditClient.cookie('authme_admin_console'), undefined);
    assert(failedSessionDigest);
    assert.equal(await runtime.store.findAdminSession(failedSessionDigest), null, 'Failed audited login left a durable session');
    runtime.store.createAdminSession = originalCreateAdminSession;
    runtime.store.writeAudit = originalWriteAudit;

    let admin = await loginGrantedAdmin(baseUrl);
    const opaqueSession = admin.cookie('authme_admin_console');
    assert(opaqueSession);
    assert.equal(await runtime.store.findAdminSession(opaqueSession), null, 'Raw session bearer was stored server-side');
    assert(await runtime.store.findAdminSession(adminSessionDigest(opaqueSession)), 'Durable session digest was not stored');
    response = await admin.get('/admin/ui/session');
    const session = await response.json();
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(session.realm, 'master');
    assert.equal(session.user.username, 'admin');
    assert.deepEqual(session.permissions, ['*']);
    assert.match(session.csrf, /^[A-Za-z0-9_-]{43}$/u);

    response = await admin.get('/admin/v1/realms/master/users');
    assert.equal(response.status, 200);
    assert((await response.json()).users.some((user) => user.username === 'admin'));

    const newUser = {
      username: 'console-security-test',
      email: 'console-security-test@example.test',
      password: 'Console-Test-User-Password-2026!',
      name: 'Console Security Test',
      enabled: true,
      roles: ['member'],
      groups: ['/test'],
    };
    response = await admin.postJson('/admin/v1/realms/master/users', newUser);
    assert.equal(response.status, 403);
    assert.equal((await response.json()).title, 'Invalid CSRF token');
    response = await admin.postJson('/admin/v1/realms/master/users', newUser, { 'x-authme-csrf': 'wrong-token' });
    assert.equal(response.status, 403);
    response = await admin.postJson('/admin/v1/realms/master/users', newUser, {
      'x-authme-csrf': session.csrf,
      origin: 'http://attacker.example.test',
    });
    assert.equal(response.status, 403, 'A cross-origin console mutation was accepted');
    response = await admin.postForm('/admin/v1/realms/master/users', { ignored: 'body' }, {
      'x-authme-csrf': session.csrf,
    });
    assert.equal(response.status, 415, 'A non-JSON console mutation was accepted');
    response = await admin.postJson('/admin/v1/realms/master/users', newUser, { 'x-authme-csrf': session.csrf });
    const created = await response.json();
    assert.equal(response.status, 201);
    assert.equal(created.username, newUser.username);

    await runtime.store.upsertAdminGrant('master', created.id, ['configuration.read']);
    const restrictedAdmin = await loginGrantedAdmin(baseUrl, {
      login: newUser.username,
      password: newUser.password,
    });
    response = await restrictedAdmin.get('/admin/v1/realms/master/users');
    assert.equal(response.status, 403, 'The canonical user route ignored the restricted grant');
    assert.equal((await response.json()).title, 'Permission denied');
    response = await restrictedAdmin.get('/admin/v1/realms/master/users/');
    assert.equal(response.status, 403, 'A trailing slash bypassed the users.read permission');
    assert.equal((await response.json()).title, 'Permission denied');
    response = await restrictedAdmin.get('/admin/V1/REALMS/master/USERS');
    assert.equal(response.status, 403, 'Mixed-case path segments bypassed the users.read permission');
    assert.equal((await response.json()).title, 'Permission denied');
    response = await restrictedAdmin.get('/admin/V1/REALMS/staff/USERS');
    assert.equal(response.status, 403, 'Mixed-case path segments bypassed the console realm boundary');
    assert.equal((await response.json()).title, 'Realm access denied');

    await runtime.store.upsertAdminGrant('master', created.id, [
      'users.read',
      'users.write',
      'users.delete',
      'credentials.manage',
      'sessions.revoke',
      'federation.manage',
    ]);
    const credentialAdministrator = await loginGrantedAdmin(baseUrl, {
      login: newUser.username,
      password: newUser.password,
    });
    response = await credentialAdministrator.get('/admin/ui/session');
    const credentialSession = await response.json();
    assert.equal(response.status, 200);
    response = await credentialAdministrator.postJson(
      `/admin/v1/realms/master/users/${session.user.id}/passkeys/registration/options`,
      {},
      { 'x-authme-csrf': credentialSession.csrf },
    );
    assert.equal(response.status, 403, 'A limited credential administrator could enroll a passkey for an administrator');
    assert.equal((await response.json()).title, 'Administrator account protection');
    response = await credentialAdministrator.request(
      `/admin/v1/realms/master/users/${session.user.id}/password`,
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          origin: baseUrl,
          'x-authme-csrf': credentialSession.csrf,
        },
        body: JSON.stringify({ password: 'Limited-Administrator-Takeover-2026!' }),
      },
    );
    assert.equal(response.status, 403, 'A limited credential administrator could reset an administrator password');
    assert.equal((await response.json()).title, 'Administrator account protection');

    const credentialCookie = credentialAdministrator.cookie('authme_admin_console');
    const credentialDigest = adminSessionDigest(credentialCookie);
    const durableCredentialSession = await runtime.store.findAdminSession(credentialDigest);
    assert(durableCredentialSession);
    await runtime.store.deleteAdminSession(credentialDigest);
    await runtime.store.createAdminSession({
      ...durableCredentialSession,
      createdAt: new Date(Date.now() - (16 * 60 * 1000)).toISOString(),
      lastSeenAt: new Date().toISOString(),
      idleExpiresAt: new Date(Date.now() + (10 * 60 * 1000)).toISOString(),
    });
    response = await credentialAdministrator.postJson('/admin/v1/realms/master/users', {
      username: 'stale-admin-attempt',
      email: 'stale-admin-attempt@example.test',
      password: 'Stale-Administrator-Password-2026!',
    }, { 'x-authme-csrf': credentialSession.csrf });
    assert.equal(response.status, 403, 'A stale administrator authentication performed a security mutation');
    assert.equal((await response.json()).title, 'Recent administrator authentication required');
    await runtime.store.revokeAdminGrant('master', created.id);

    response = await admin.get('/admin/v1/realms/staff/users');
    assert.equal(response.status, 403);
    assert.equal((await response.json()).title, 'Realm access denied');

    const tampered = admin.clone();
    const signedCookie = tampered.cookie('authme_admin_console');
    assert(signedCookie);
    const last = signedCookie.at(-1);
    tampered.replaceCookie('authme_admin_console', '/admin', `${signedCookie.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`);
    response = await tampered.get('/admin/ui/session');
    assert.equal(response.status, 401, 'A modified console cookie was accepted');

    const administrator = await runtime.store.findUserById('master', session.user.id);
    assert(administrator);
    await runtime.store.bumpSecurityVersion('master', administrator.id);
    response = await admin.get('/admin/ui/session');
    assert.equal(response.status, 401, 'A stale user security version did not invalidate the console session');

    admin = await loginGrantedAdmin(baseUrl);
    response = await admin.get('/admin/ui/session');
    const grantSession = await response.json();
    assert.equal(response.status, 200);
    const grant = await runtime.store.findAdminGrant('master', grantSession.user.id);
    assert(grant?.enabled);
    await runtime.store.upsertAdminGrant('master', grantSession.user.id, grant.permissions);
    response = await admin.get('/admin/ui/session');
    assert.equal(response.status, 401, 'A stale administrator-grant version did not invalidate the console session');

    const ungranted = new CookieClient(baseUrl);
    const denied = await finishAdminLogin(ungranted, {
      login: newUser.username,
      password: newUser.password,
    });
    assert.equal(denied.callback.status, 403);
    const deniedHtml = await denied.callback.text();
    assert.match(deniedHtml, /does not have an active AuthMe administrator grant/u);
    assert.equal(ungranted.cookie('authme_admin_console'), undefined);
    response = await ungranted.get('/admin/ui/session');
    assert.equal(response.status, 401);

    admin = await loginGrantedAdmin(baseUrl);
    response = await admin.get('/admin/ui/session');
    const logoutSession = await response.json();
    assert.equal(response.status, 200);
    const logoutReplay = admin.clone();
    response = await admin.postJson('/admin/ui/logout', {}, { 'x-authme-csrf': logoutSession.csrf });
    assert.equal(response.status, 204);
    assert.equal(admin.cookie('authme_admin_console'), undefined);
    response = await admin.get('/admin/ui/session');
    assert.equal(response.status, 401, 'Logout did not clear console access');
    response = await logoutReplay.get('/admin/ui/session');
    assert.equal(response.status, 401, 'Logout did not revoke the durable console session');
  } finally {
    await closeServer(server);
    await runtime?.close();
  }
});
