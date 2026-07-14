import { createHash, createHmac, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Router, json, urlencoded } from 'express';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { safeEqual } from '../crypto/secrets.js';
import { ADMIN_CONSOLE_CLIENT_ID } from '../provider.js';
import { renderAdminConsole, renderAdminLogin } from '../ui/admin-render.js';

const SESSION_COOKIE = 'authme_admin_console';
const LOGIN_COOKIE = 'authme_admin_login';
const LOGIN_TYPE = 'admin-login';
const MAX_COOKIE_LENGTH = 4096;
const consoleCssPath = fileURLToPath(new URL('../ui/admin-console.css', import.meta.url));
const consoleScriptPath = fileURLToPath(new URL('../ui/admin-console.js', import.meta.url));

function problem(res, status, title, detail) {
  return res.status(status).type('application/problem+json').json({
    type: 'about:blank', title, status, detail,
  });
}

function cookieMap(header) {
  const cookies = new Map();
  if (typeof header !== 'string' || header.length > 16_384) return cookies;
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=');
    if (separator <= 0) continue;
    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (name && value && !cookies.has(name)) cookies.set(name, value);
  }
  return cookies;
}

function signature(value, key) {
  return createHmac('sha256', key).update(`authme-admin-console-v1\u0000${value}`).digest('base64url');
}

function seal(payload, key, now = Date.now()) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${encoded}.${signature(encoded, key)}`;
}

function unseal(value, type, keys, now = Date.now()) {
  if (typeof value !== 'string' || value.length < 40 || value.length > MAX_COOKIE_LENGTH) return null;
  const parts = value.split('.');
  if (parts.length !== 2 || !parts.every((part) => /^[A-Za-z0-9_-]+$/.test(part))) return null;
  if (!keys.some((key) => safeEqual(parts[1], signature(parts[0], key)))) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  const nowSeconds = Math.floor(now / 1000);
  if (!payload || payload.type !== type || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) return null;
  if (payload.iat > nowSeconds + 30 || payload.exp <= nowSeconds || payload.exp - payload.iat > 28_800) return null;
  return payload;
}

function cookieOptions(config, { callback = false, maxAge } = {}) {
  return {
    httpOnly: true,
    secure: !config.devMode,
    sameSite: callback ? 'lax' : 'strict',
    path: callback ? '/admin/oidc/callback' : '/admin',
    maxAge,
  };
}

function clearCookie(res, config, name, callback = false) {
  res.clearCookie(name, cookieOptions(config, { callback }));
}

function consoleHeaders(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  res.set('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)');
}

function sameOrigin(req, config) {
  const origin = req.get('origin');
  return origin === config.publicUrl;
}

function csrfFor(sessionValue, config) {
  return createHmac('sha256', config.csrfSecret)
    .update(`authme-admin-console-csrf-v1\u0000${sessionValue}`)
    .digest('base64url');
}

function sessionDigest(sessionValue, config) {
  return createHmac('sha256', config.csrfSecret)
    .update(`authme-admin-console-session-v1\u0000${sessionValue}`)
    .digest('base64url');
}

function publicJwks(jwks) {
  return {
    keys: (jwks?.keys ?? []).map(({ d, p, q, dp, dq, qi, oth, k, ...publicKey }) => publicKey),
  };
}

export function hasStrongAdminAuthentication(amr) {
  const methods = new Set(Array.isArray(amr) ? amr.filter((method) => typeof method === 'string') : []);
  if (methods.has('passkey') || methods.has('webauthn')) return true;
  const primary = methods.has('pwd') || methods.has('ldap') || methods.has('federated');
  const secondFactor = methods.has('otp') || methods.has('recovery');
  return primary && secondFactor;
}

function authorizationUrl(config, realm, transaction) {
  const url = new URL(`${config.publicUrl}/realms/${realm}/protocol/openid-connect/auth`);
  const challenge = createHash('sha256').update(transaction.verifier).digest('base64url');
  const parameters = {
    client_id: ADMIN_CONSOLE_CLIENT_ID,
    redirect_uri: `${config.publicUrl}/admin/oidc/callback`,
    response_type: 'code',
    response_mode: 'query',
    scope: 'openid profile email roles',
    max_age: '900',
    acr_values: 'urn:authme:loa:2',
    state: transaction.state,
    nonce: transaction.nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  };
  for (const [name, value] of Object.entries(parameters)) url.searchParams.set(name, value);
  return url.toString();
}

async function tokenExchange({ config, realm, code, verifier, fetchImpl }) {
  const response = await fetchImpl(`${config.publicUrl}/realms/${realm}/protocol/openid-connect/token`, {
    method: 'POST',
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: ADMIN_CONSOLE_CLIENT_ID,
      redirect_uri: `${config.publicUrl}/admin/oidc/callback`,
      code,
      code_verifier: verifier,
    }),
  });
  const body = await response.text();
  if (!response.ok || body.length > 65_536) throw new Error('The authorization code could not be exchanged safely.');
  let token;
  try { token = JSON.parse(body); } catch { throw new Error('The token endpoint returned an invalid response.'); }
  if (typeof token.id_token !== 'string' || token.id_token.length > 16_384) {
    throw new Error('The token endpoint did not return a usable identity token.');
  }
  return token;
}

export function createAdminConsole({ config, store, rateLimits, jwksByRealm, fetch: fetchOverride }) {
  config = {
    ...config,
    cookieKeys: config.cookieKeys?.length ? config.cookieKeys : [config.adminToken],
    csrfSecret: config.csrfSecret ?? config.adminToken,
    sessionTtl: config.sessionTtl ?? 28_800,
  };
  jwksByRealm ??= new Map();
  const router = Router();
  const fetchImpl = fetchOverride ?? globalThis.fetch;
  const sessionTtl = Math.min(config.sessionTtl, 28_800);
  const idleTtl = Math.min(sessionTtl, 1_800);

  async function authenticate(req) {
    const sessionValue = cookieMap(req.get('cookie')).get(SESSION_COOKIE);
    if (!/^[A-Za-z0-9_-]{43}$/.test(sessionValue ?? '')) return null;
    const digest = sessionDigest(sessionValue, config);
    let session = await store.findAdminSession(digest);
    const now = Date.now();
    if (!session || !config.realms.includes(session.realm)
      || new Date(session.expiresAt).getTime() <= now || new Date(session.idleExpiresAt).getTime() <= now) {
      if (session) await store.deleteAdminSession(digest);
      return null;
    }
    const user = await store.findUserById(session.realm, session.userId);
    const grant = await store.findAdminGrant(session.realm, session.userId);
    if (!user?.enabled || user.securityVersion !== session.securityVersion
      || !grant?.enabled || grant.version !== session.grantVersion) {
      await store.deleteAdminSession(digest);
      return null;
    }
    if (now - new Date(session.lastSeenAt).getTime() >= 60_000) {
      const idleExpiresAt = new Date(Math.min(now + idleTtl * 1000, new Date(session.expiresAt).getTime()));
      session = await store.touchAdminSession(digest, idleExpiresAt) ?? session;
    }
    return { type: 'session', realm: session.realm, session, sessionValue, sessionDigest: digest, user, grant };
  }

  function verifyCsrf(req, authentication) {
    if (!authentication?.sessionValue || !sameOrigin(req, config)) return false;
    const provided = req.get('x-authme-csrf') ?? req.body?.csrf;
    return typeof provided === 'string' && provided.length <= 256
      && safeEqual(provided, csrfFor(authentication.sessionValue, config));
  }

  async function consumeRateLimit(req, res) {
    try {
      await rateLimits.consumeAdmin(req.ip);
      return true;
    } catch (error) {
      res.set('Cache-Control', 'no-store');
      res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
      problem(res, 429, 'Too many requests', 'Wait before retrying the administration console.');
      return false;
    }
  }

  async function authenticateConsoleRequest(req, res) {
    const sessionValue = cookieMap(req.get('cookie')).get(SESSION_COOKIE);
    if (!/^[A-Za-z0-9_-]{43}$/.test(sessionValue ?? '')) {
      return { authentication: null, handled: false };
    }
    if (!await consumeRateLimit(req, res)) return { authentication: null, handled: true };
    return { authentication: await authenticate(req), handled: false };
  }

  async function beginLogin(req, res, realm, { jsonResponse = false, rateLimited = false } = {}) {
    if (!sameOrigin(req, config)) {
      consoleHeaders(res);
      return problem(
        res,
        403,
        'Invalid request origin',
        'Administrator sign-in must originate from the configured AuthMe service.',
      );
    }
    if (!config.realms.includes(realm)) {
      consoleHeaders(res);
      return res.status(400).send(renderAdminLogin({ realms: config.realms, error: 'Choose a configured realm.' }));
    }
    if (!rateLimited && !await consumeRateLimit(req, res)) return undefined;
    const now = Math.floor(Date.now() / 1000);
    const transaction = {
      type: LOGIN_TYPE,
      iat: now,
      exp: now + 600,
      realm,
      state: randomBytes(24).toString('base64url'),
      nonce: randomBytes(24).toString('base64url'),
      verifier: randomBytes(48).toString('base64url'),
    };
    res.cookie(LOGIN_COOKIE, seal(transaction, config.cookieKeys[0]), cookieOptions(config, { callback: true, maxAge: 600_000 }));
    const location = authorizationUrl(config, realm, transaction);
    return jsonResponse ? res.json({ authorizationUrl: location }) : res.redirect(303, location);
  }

  router.get('/assets/admin-console.css', async (_req, res, next) => {
    try {
      res.set('Cache-Control', 'public, max-age=300').type('text/css').send(await readFile(consoleCssPath, 'utf8'));
    } catch (error) { next(error); }
  });
  router.get('/assets/admin-console.js', async (_req, res, next) => {
    try {
      res.set('Cache-Control', 'public, max-age=300').type('text/javascript').send(await readFile(consoleScriptPath, 'utf8'));
    } catch (error) { next(error); }
  });

  router.get('/', async (req, res, next) => {
    try {
      consoleHeaders(res);
      const { authentication, handled } = await authenticateConsoleRequest(req, res);
      if (handled) return undefined;
      if (!authentication) {
        if (cookieMap(req.get('cookie')).has(SESSION_COOKIE)) clearCookie(res, config, SESSION_COOKIE);
        return res.send(renderAdminLogin({ realms: config.realms, error: '' }));
      }
      return res.send(renderAdminConsole());
    } catch (error) { return next(error); }
  });

  router.post('/ui/login', urlencoded({ extended: false, limit: '4kb', parameterLimit: 8 }), async (req, res, next) => {
    try { return await beginLogin(req, res, req.body?.realm); } catch (error) { return next(error); }
  });

  router.get('/oidc/callback', async (req, res) => {
    consoleHeaders(res);
    const loginValue = cookieMap(req.get('cookie')).get(LOGIN_COOKIE);
    const previousSessionValue = cookieMap(req.get('cookie')).get(SESSION_COOKIE);
    const transaction = unseal(loginValue, LOGIN_TYPE, config.cookieKeys);
    let createdSessionDigest;
    clearCookie(res, config, LOGIN_COOKIE, true);
    const fail = (message, status = 400) => res.status(status).send(renderAdminLogin({ realms: config.realms, error: message }));
    if (!transaction || !config.realms.includes(transaction.realm)) return fail('The administrator sign-in request expired. Start again.');
    if (typeof req.query.state !== 'string' || !safeEqual(req.query.state, transaction.state)) {
      return fail('The administrator sign-in response could not be verified.');
    }
    if (req.query.error) return fail('AuthMe did not authorize access to the administration console.', 403);
    if (typeof req.query.code !== 'string' || req.query.code.length > 4096) return fail('The authorization response did not contain a valid code.');
    try {
      const token = await tokenExchange({
        config,
        realm: transaction.realm,
        code: req.query.code,
        verifier: transaction.verifier,
        fetchImpl,
      });
      const jwks = jwksByRealm.get(transaction.realm);
      if (!jwks) throw new Error('The realm signing keys are unavailable.');
      const { payload } = await jwtVerify(token.id_token, createLocalJWKSet(publicJwks(jwks)), {
        issuer: `${config.publicUrl}/realms/${transaction.realm}`,
        audience: ADMIN_CONSOLE_CLIENT_ID,
        clockTolerance: 5,
        requiredClaims: ['sub', 'iat', 'exp', 'nonce', 'auth_time'],
      });
      if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, transaction.nonce)) {
        throw new Error('The identity token nonce did not match.');
      }
      const user = await store.findUserById(transaction.realm, payload.sub);
      const grant = user ? await store.findAdminGrant(transaction.realm, user.id) : null;
      const amr = Array.isArray(payload.amr) ? payload.amr : [];
      const authenticationAge = Math.floor(Date.now() / 1000) - payload.auth_time;
      const recentAuthentication = Number.isSafeInteger(payload.auth_time)
        && authenticationAge >= -30
        && authenticationAge <= 930;
      const strongAuthentication = hasStrongAdminAuthentication(amr);
      if (!user?.enabled || !grant?.enabled) return fail('This account does not have an active AuthMe administrator grant.', 403);
      if (!recentAuthentication || (!config.devMode && !strongAuthentication)) {
        return fail('Administrator access requires a recent multi-factor or passkey sign-in.', 403);
      }
      const now = Math.floor(Date.now() / 1000);
      const sessionValue = randomBytes(32).toString('base64url');
      createdSessionDigest = sessionDigest(sessionValue, config);
      const session = await store.createAdminSession({
        idDigest: createdSessionDigest,
        realm: transaction.realm,
        userId: user.id,
        securityVersion: user.securityVersion,
        grantVersion: grant.version,
        createdAt: new Date(payload.auth_time * 1000).toISOString(),
        idleExpiresAt: new Date((now + idleTtl) * 1000),
        expiresAt: new Date((now + sessionTtl) * 1000),
      });
      if (!session) throw new Error('The administrator session could not be created.');
      await store.writeAudit({
        realm: transaction.realm,
        type: 'admin.console.login.succeeded',
        actorId: user.id,
        subjectId: user.id,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        metadata: { amr, acr: payload.acr },
      });
      if (/^[A-Za-z0-9_-]{43}$/.test(previousSessionValue ?? '')) {
        const previousDigest = sessionDigest(previousSessionValue, config);
        if (previousDigest !== createdSessionDigest) await store.deleteAdminSession(previousDigest).catch(() => {});
      }
      res.cookie(SESSION_COOKIE, sessionValue, cookieOptions(config, { maxAge: sessionTtl * 1000 }));
      return res.redirect(303, '/admin/');
    } catch {
      if (createdSessionDigest) await store.deleteAdminSession(createdSessionDigest).catch(() => {});
      return fail('The administrator sign-in could not be completed safely. Start again.', 403);
    }
  });

  router.use('/ui', json({ limit: '4kb', strict: true }));
  router.get('/ui/session', async (req, res, next) => {
    try {
      const { authentication, handled } = await authenticateConsoleRequest(req, res);
      if (handled) return undefined;
      if (!authentication) return problem(res, 401, 'Administrator sign-in required', 'Sign in to the AuthMe administration console.');
      res.set('Cache-Control', 'no-store').json({
        realm: authentication.realm,
        csrf: csrfFor(authentication.sessionValue, config),
        user: {
          id: authentication.user.id,
          username: authentication.user.username,
          email: authentication.user.email,
          name: authentication.user.name,
        },
        permissions: authentication.grant.permissions,
      });
    } catch (error) { next(error); }
  });
  router.post('/ui/switch-realm', async (req, res, next) => {
    try {
      const { authentication, handled } = await authenticateConsoleRequest(req, res);
      if (handled) return undefined;
      if (!authentication) return problem(res, 401, 'Administrator sign-in required', 'Sign in to the AuthMe administration console.');
      if (!req.is('application/json')) return problem(res, 415, 'Unsupported media type', 'Console mutations require application/json.');
      if (!verifyCsrf(req, authentication)) return problem(res, 403, 'Invalid CSRF token', 'Reload the console and try again.');
      return await beginLogin(req, res, req.body?.realm, { jsonResponse: true, rateLimited: true });
    } catch (error) { return next(error); }
  });
  router.post('/ui/logout', async (req, res, next) => {
    try {
      const { authentication, handled } = await authenticateConsoleRequest(req, res);
      if (handled) return undefined;
      if (!req.is('application/json')) return problem(res, 415, 'Unsupported media type', 'Console mutations require application/json.');
      if (authentication && !verifyCsrf(req, authentication)) {
        return problem(res, 403, 'Invalid CSRF token', 'Reload the console and try again.');
      }
      if (authentication) {
        await store.deleteAdminSession(authentication.sessionDigest);
        await store.writeAudit({
          realm: authentication.realm,
          type: 'admin.console.logout',
          actorId: authentication.user.id,
          subjectId: authentication.user.id,
          ip: req.ip,
          userAgent: req.get('user-agent'),
        });
      }
      clearCookie(res, config, SESSION_COOKIE);
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  return {
    router,
    authenticate,
    verifyCsrf,
    csrfFor,
  };
}

export const adminConsoleCookies = Object.freeze({ session: SESSION_COOKIE, login: LOGIN_COOKIE });
