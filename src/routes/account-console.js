import { createHash, createHmac, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Router, json, urlencoded } from 'express';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { createRecoveryCodes, createTotp, totpStep } from '../crypto/mfa.js';
import { publicSigningJwks } from '../crypto/jwks.js';
import { hashPassword, verifyPassword } from '../crypto/password.js';
import { decryptSecret, encryptSecret, keyedDigest, randomToken, safeEqual } from '../crypto/secrets.js';
import { loggableError } from '../logging.js';
import { ACCOUNT_CONSOLE_CLIENT_ID } from '../provider.js';
import { createWebAuthn } from '../security/webauthn.js';
import { renderAccountAction, renderAccountConsole, renderAccountLogin } from '../ui/account-render.js';

const SESSION_COOKIE = 'authme_account_console';
const LOGIN_COOKIE = 'authme_account_login';
const LOGIN_TYPE = 'account-login';
const MAX_COOKIE_LENGTH = 4096;
const TOKEN_TTL_MS = 30 * 60_000;
const RECENT_AUTHENTICATION_MS = 15 * 60_000;
const base64url = /^[A-Za-z0-9_-]+$/;
const consoleCssPath = fileURLToPath(new URL('../ui/account-console.css', import.meta.url));
const consoleScriptPath = fileURLToPath(new URL('../ui/account-console.js', import.meta.url));
const passwordSchema = z.string().min(12).max(1024);
const profileSchema = z.object({
  email: z.email().max(254),
  name: z.string().trim().min(1).max(255),
  givenName: z.string().trim().max(255),
  familyName: z.string().trim().max(255),
}).strict();
const encodedWebAuthnData = z.string().min(1).max(32_768).regex(base64url);
const registrationResponse = z.object({
  id: z.string().min(1).max(2048).regex(base64url),
  rawId: z.string().min(1).max(2048).regex(base64url),
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: encodedWebAuthnData,
    attestationObject: encodedWebAuthnData,
    transports: z.array(z.enum(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'])).max(7).optional(),
  }).passthrough(),
}).passthrough();

function problem(res, status, title, detail) {
  return res.status(status).type('application/problem+json').json({ type: 'about:blank', title, status, detail });
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
  return createHmac('sha256', key).update(`authme-account-console-login-v1\u0000${value}`).digest('base64url');
}

function seal(payload, key) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${encoded}.${signature(encoded, key)}`;
}

function unseal(value, keys, now = Date.now()) {
  if (typeof value !== 'string' || value.length < 40 || value.length > MAX_COOKIE_LENGTH) return null;
  const parts = value.split('.');
  if (parts.length !== 2 || !parts.every((part) => base64url.test(part))) return null;
  if (!keys.some((key) => safeEqual(parts[1], signature(parts[0], key)))) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch { return null; }
  const nowSeconds = Math.floor(now / 1000);
  if (!payload || payload.type !== LOGIN_TYPE || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) return null;
  if (payload.iat > nowSeconds + 30 || payload.exp <= nowSeconds || payload.exp - payload.iat > 600) return null;
  return payload;
}

function requestOrigin(req) {
  try { return new URL(`${req.protocol}://${req.get('host')}`).origin; } catch { return null; }
}

function sameOrigin(req, config) {
  return req.get('origin') === config.publicUrl;
}

function sameOriginLoginNavigation(req, config) {
  const origin = req.get('origin');
  if (origin === config.publicUrl) return true;
  if (origin !== undefined && origin !== 'null') return false;
  return requestOrigin(req) === config.publicUrl
    && req.get('sec-fetch-site') === 'same-origin'
    && req.get('sec-fetch-mode') === 'navigate'
    && req.get('sec-fetch-dest') === 'document';
}

function consoleHeaders(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  res.set('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)');
}

function parse(schema, req, res) {
  const result = schema.safeParse(req.body);
  if (result.success) return result.data;
  problem(res, 400, 'Invalid request', result.error.issues.map((issue) => `${issue.path.join('.') || 'body'}: ${issue.message}`).join('; '));
  return null;
}

function publicPasskey(credential) {
  const { publicKey, userHandle, counter, realm, userId, ...safe } = credential;
  return safe;
}

export function createAccountConsole({
  realm,
  config,
  store,
  data,
  management,
  rateLimits,
  jwks,
  webauthn,
  logger,
  delivery,
  fetch: fetchOverride,
}) {
  const router = Router();
  const passkeys = webauthn ?? createWebAuthn(config);
  const fetchImpl = fetchOverride ?? globalThis.fetch;
  const root = `/realms/${realm}/account`;
  const callbackPath = `${root}/oidc/callback`;
  const sessionTtl = Math.min(config.sessionTtl ?? 28_800, 28_800);
  const idleTtl = Math.min(sessionTtl, 1_800);
  const cookieKeys = config.cookieKeys?.length ? config.cookieKeys : [config.adminToken];

  function cookieOptions({ callback = false, maxAge } = {}) {
    return {
      httpOnly: true,
      secure: !config.devMode,
      sameSite: callback ? 'lax' : 'strict',
      path: callback ? callbackPath : root,
      maxAge,
    };
  }

  function clearCookie(res, name, callback = false) {
    res.clearCookie(name, cookieOptions({ callback }));
  }

  function sessionDigest(value) {
    return createHmac('sha256', config.csrfSecret)
      .update(`authme-account-console-session-v1\u0000${realm}\u0000${value}`)
      .digest('base64url');
  }

  function csrfFor(value) {
    return createHmac('sha256', config.csrfSecret)
      .update(`authme-account-console-csrf-v1\u0000${realm}\u0000${value}`)
      .digest('base64url');
  }

  function actionDigest(type, token) {
    return keyedDigest(`authme-account-action-v1\u0000${realm}\u0000${type}\u0000${token}`, config.passwordPepper);
  }

  function sessionReference(kind, identifier) {
    return keyedDigest(`authme-account-session-reference-v1\u0000${realm}\u0000${kind}\u0000${identifier}`, config.csrfSecret);
  }

  function auditEvent(req, type, userId, metadata = {}) {
    return {
      realm,
      type,
      actorId: userId,
      subjectId: userId,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      metadata,
    };
  }

  async function authenticate(req) {
    const sessionValue = cookieMap(req.get('cookie')).get(SESSION_COOKIE);
    if (!/^[A-Za-z0-9_-]{43}$/.test(sessionValue ?? '')) return null;
    const digest = sessionDigest(sessionValue);
    let session = await store.findAccountSession(digest);
    const now = Date.now();
    if (!session || session.realm !== realm
      || new Date(session.expiresAt).getTime() <= now || new Date(session.idleExpiresAt).getTime() <= now) {
      if (session) await store.deleteAccountSession(digest);
      return null;
    }
    const user = await store.findUserById(realm, session.userId);
    if (!user?.enabled || user.securityVersion !== session.securityVersion) {
      await store.deleteAccountSession(digest);
      return null;
    }
    if (now - new Date(session.lastSeenAt).getTime() >= 60_000) {
      const idleExpiresAt = new Date(Math.min(now + idleTtl * 1000, new Date(session.expiresAt).getTime()));
      session = await store.touchAccountSession(digest, idleExpiresAt) ?? session;
    }
    return { realm, user, session, sessionValue, sessionDigest: digest };
  }

  async function consumeAccountLimit(req, res) {
    try {
      await rateLimits.consumeAccount(req.ip);
      return true;
    } catch (error) {
      res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
      problem(res, 429, 'Too many requests', 'Wait before retrying the account console.');
      return false;
    }
  }

  async function authenticatedRequest(req, res) {
    const value = cookieMap(req.get('cookie')).get(SESSION_COOKIE);
    if (!/^[A-Za-z0-9_-]{43}$/.test(value ?? '')) return { authentication: null, handled: false };
    if (!await consumeAccountLimit(req, res)) return { authentication: null, handled: true };
    return { authentication: await authenticate(req), handled: false };
  }

  function verifyCsrf(req, authentication) {
    const supplied = req.get('x-authme-csrf') ?? req.body?.csrf;
    return Boolean(authentication?.sessionValue && sameOrigin(req, config)
      && typeof supplied === 'string' && supplied.length <= 256
      && safeEqual(supplied, csrfFor(authentication.sessionValue)));
  }

  function hasRecentAuthentication(authentication) {
    const authenticatedAt = new Date(authentication?.session?.createdAt).getTime();
    const age = Date.now() - authenticatedAt;
    return Number.isFinite(authenticatedAt) && age >= -30_000 && age <= RECENT_AUTHENTICATION_MS;
  }

  async function dispatch(kind, payload) {
    const method = kind === 'email-verification' ? 'sendEmailVerification' : 'sendPasswordReset';
    if (typeof delivery?.[method] === 'function') return delivery[method](Object.freeze(payload));
    throw Object.assign(new Error('Account email delivery is unavailable'), { code: 'ACCOUNT_DELIVERY_UNAVAILABLE' });
  }

  function schedulePasswordReset(email, request) {
    setImmediate(() => {
      void (async () => {
        const validEmail = z.email().max(254).safeParse(email).success;
        const user = validEmail ? await store.findUserByLogin(realm, email) : null;
        if (!user?.enabled || user.email !== email) return;
        const token = randomToken(32);
        await store.createAccountActionToken({
          realm,
          userId: user.id,
          type: 'password-reset',
          tokenDigest: actionDigest('password-reset', token),
          expiresAt: new Date(Date.now() + TOKEN_TTL_MS),
        });
        const url = `${config.publicUrl}${root}/reset-password?token=${encodeURIComponent(token)}`;
        await dispatch('password-reset', {
          realm,
          email,
          token,
          url,
          user: { id: user.id, username: user.username, name: user.name },
        });
        await store.writeAudit({
          realm,
          type: 'account.password_reset.requested',
          actorId: user.id,
          subjectId: user.id,
          ip: request.ip,
          userAgent: request.userAgent,
          metadata: {},
        });
      })().catch((error) => {
        logger?.error({
          error: loggableError(error, 'Password reset delivery failed.'),
          realm,
        }, 'Password reset delivery failed');
      });
    });
  }

  function authorizationUrl(transaction) {
    const url = new URL(`${config.publicUrl}/realms/${realm}/protocol/openid-connect/auth`);
    const challenge = createHash('sha256').update(transaction.verifier).digest('base64url');
    const parameters = {
      client_id: ACCOUNT_CONSOLE_CLIENT_ID,
      redirect_uri: `${config.publicUrl}${callbackPath}`,
      response_type: 'code',
      response_mode: 'query',
      scope: 'openid profile email',
      max_age: '900',
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    };
    for (const [name, value] of Object.entries(parameters)) url.searchParams.set(name, value);
    return url.toString();
  }

  async function tokenExchange(code, verifier) {
    const response = await fetchImpl(`${config.publicUrl}/realms/${realm}/protocol/openid-connect/token`, {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: ACCOUNT_CONSOLE_CLIENT_ID,
        redirect_uri: `${config.publicUrl}${callbackPath}`,
        code,
        code_verifier: verifier,
      }),
    });
    const body = await response.text();
    if (!response.ok || body.length > 65_536) throw new Error('The authorization code could not be exchanged safely.');
    let token;
    try { token = JSON.parse(body); } catch { throw new Error('The token endpoint returned an invalid response.'); }
    if (typeof token.id_token !== 'string' || token.id_token.length > 16_384) throw new Error('The identity token is unavailable.');
    return token;
  }

  router.get('/assets/account-console.css', async (_req, res, next) => {
    try { res.set('Cache-Control', 'public, max-age=300').type('text/css').send(await readFile(consoleCssPath, 'utf8')); } catch (error) { next(error); }
  });
  router.get('/assets/account-console.js', async (_req, res, next) => {
    try { res.set('Cache-Control', 'public, max-age=300').type('text/javascript').send(await readFile(consoleScriptPath, 'utf8')); } catch (error) { next(error); }
  });

  router.get('/', async (req, res, next) => {
    try {
      consoleHeaders(res);
      const { authentication, handled } = await authenticatedRequest(req, res);
      if (handled) return undefined;
      if (!authentication) {
        if (cookieMap(req.get('cookie')).has(SESSION_COOKIE)) clearCookie(res, SESSION_COOKIE);
        return res.send(renderAccountLogin({ realm }));
      }
      return res.send(renderAccountConsole({ realm }));
    } catch (error) { return next(error); }
  });

  router.post('/login', urlencoded({ extended: false, limit: '2kb', parameterLimit: 4 }), async (req, res, next) => {
    try {
      consoleHeaders(res);
      if (!sameOriginLoginNavigation(req, config)) return problem(res, 403, 'Invalid request origin', 'Account sign-in must originate from AuthMe.');
      if (!await consumeAccountLimit(req, res)) return undefined;
      const now = Math.floor(Date.now() / 1000);
      const transaction = {
        type: LOGIN_TYPE,
        realm,
        iat: now,
        exp: now + 600,
        state: randomBytes(24).toString('base64url'),
        nonce: randomBytes(24).toString('base64url'),
        verifier: randomBytes(48).toString('base64url'),
      };
      res.cookie(LOGIN_COOKIE, seal(transaction, cookieKeys[0]), cookieOptions({ callback: true, maxAge: 600_000 }));
      return res.redirect(303, authorizationUrl(transaction));
    } catch (error) { return next(error); }
  });

  router.get('/oidc/callback', async (req, res) => {
    consoleHeaders(res);
    const loginValue = cookieMap(req.get('cookie')).get(LOGIN_COOKIE);
    const previousSessionValue = cookieMap(req.get('cookie')).get(SESSION_COOKIE);
    const transaction = unseal(loginValue, cookieKeys);
    let createdDigest;
    clearCookie(res, LOGIN_COOKIE, true);
    const fail = (message, status = 400) => res.status(status).send(renderAccountLogin({ realm, error: message }));
    if (!transaction || transaction.realm !== realm) return fail('The account sign-in request expired. Start again.');
    if (typeof req.query.state !== 'string' || !safeEqual(req.query.state, transaction.state)) return fail('The account sign-in response could not be verified.');
    if (req.query.error) return fail('AuthMe did not authorize access to the account console.', 403);
    if (typeof req.query.code !== 'string' || req.query.code.length > 4096) return fail('The authorization response did not contain a valid code.');
    try {
      const token = await tokenExchange(req.query.code, transaction.verifier);
      const { payload } = await jwtVerify(token.id_token, createLocalJWKSet(publicSigningJwks(jwks)), {
        issuer: `${config.publicUrl}/realms/${realm}`,
        audience: ACCOUNT_CONSOLE_CLIENT_ID,
        clockTolerance: 5,
        requiredClaims: ['sub', 'iat', 'exp', 'nonce', 'auth_time'],
      });
      if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, transaction.nonce)) throw new Error('Identity token nonce mismatch.');
      const age = Math.floor(Date.now() / 1000) - payload.auth_time;
      if (!Number.isSafeInteger(payload.auth_time) || age < -30 || age > 930) throw new Error('Recent authentication is required.');
      const user = await store.findUserById(realm, payload.sub);
      if (!user?.enabled) return fail('This account is not available.', 403);
      const now = Math.floor(Date.now() / 1000);
      const sessionValue = randomBytes(32).toString('base64url');
      createdDigest = sessionDigest(sessionValue);
      const session = await store.createAccountSession({
        idDigest: createdDigest,
        realm,
        userId: user.id,
        securityVersion: user.securityVersion,
        authenticationMethods: Array.isArray(payload.amr) ? payload.amr : [],
        createdAt: new Date(payload.auth_time * 1000).toISOString(),
        idleExpiresAt: new Date((now + idleTtl) * 1000),
        expiresAt: new Date((now + sessionTtl) * 1000),
        ip: req.ip,
        userAgent: req.get('user-agent'),
      });
      if (!session) throw new Error('The account session could not be created.');
      await store.writeAudit(auditEvent(req, 'account.console.login.succeeded', user.id, { amr: session.authenticationMethods }));
      if (/^[A-Za-z0-9_-]{43}$/.test(previousSessionValue ?? '')) {
        const previousDigest = sessionDigest(previousSessionValue);
        if (previousDigest !== createdDigest) await store.deleteAccountSession(previousDigest).catch(() => {});
      }
      res.cookie(SESSION_COOKIE, sessionValue, cookieOptions({ maxAge: sessionTtl * 1000 }));
      return res.redirect(303, `${root}/`);
    } catch {
      if (createdDigest) await store.deleteAccountSession(createdDigest).catch(() => {});
      return fail('The account sign-in could not be completed safely. Start again.', 403);
    }
  });

  const resetParser = json({ limit: '4kb', strict: true });
  const resetMessage = 'If an eligible account exists, password reset instructions have been sent.';
  router.post('/password-reset', resetParser, async (req, res, next) => {
    try {
      if (!sameOrigin(req, config)) return problem(res, 403, 'Invalid request origin', 'Password reset requests must originate from AuthMe.');
      if (!req.is('application/json')) return problem(res, 415, 'Unsupported media type', 'Password reset requests require application/json.');
      const email = String(req.body?.email ?? '').trim().toLowerCase().slice(0, 254);
      try {
        await rateLimits.consumePasswordReset(req.ip, `${realm}:${email}`);
      } catch (error) {
        res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
        return problem(res, 429, 'Too many requests', 'Wait before requesting another password reset.');
      }
      schedulePasswordReset(email, { ip: req.ip, userAgent: req.get('user-agent') });
      return res.status(202).json({ message: resetMessage });
    } catch (error) { return next(error); }
  });

  router.post('/password-reset/confirm', resetParser, async (req, res, next) => {
    try {
      if (!sameOrigin(req, config)) return problem(res, 403, 'Invalid request origin', 'Password reset confirmation must originate from AuthMe.');
      if (!req.is('application/json')) return problem(res, 415, 'Unsupported media type', 'Password reset confirmation requires application/json.');
      const input = parse(z.object({ token: z.string().length(43).regex(base64url), newPassword: passwordSchema }).strict(), req, res);
      if (!input) return undefined;
      try { await rateLimits.consumePasswordReset(req.ip, `${realm}:confirm:${input.token}`); } catch (error) {
        res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
        return problem(res, 429, 'Too many requests', 'Wait before retrying password reset.');
      }
      const passwordHash = await hashPassword(input.newPassword, config.passwordPepper);
      const token = await store.consumeAccountActionToken({ realm, type: 'password-reset', tokenDigest: actionDigest('password-reset', input.token) });
      if (!token) return problem(res, 400, 'Password reset unavailable', 'The reset link is invalid, expired, or already used.');
      const mutation = await data.mutateAccountSecurity(realm, token.userId, async (transactionalStore) => {
        const updated = await transactionalStore.updateUser(realm, token.userId, { passwordHash });
        if (updated) await transactionalStore.unlockUser(realm, token.userId);
        if (updated) await transactionalStore.writeAudit(auditEvent(req, 'account.password_reset.completed', token.userId));
        return updated;
      });
      if (!mutation.applied) return problem(res, 400, 'Password reset unavailable', 'The reset link is invalid, expired, or already used.');
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.get('/reset-password', (req, res) => {
    consoleHeaders(res);
    return res.send(renderAccountAction({ realm, type: 'password-reset' }));
  });
  router.get('/verify-email', (req, res) => {
    consoleHeaders(res);
    return res.send(renderAccountAction({ realm, type: 'email-verification' }));
  });

  router.post('/email-verification/confirm', resetParser, async (req, res, next) => {
    try {
      if (!sameOrigin(req, config)) return problem(res, 403, 'Invalid request origin', 'Email verification must originate from AuthMe.');
      if (!req.is('application/json')) return problem(res, 415, 'Unsupported media type', 'Email verification requires application/json.');
      const input = parse(z.object({ token: z.string().length(43).regex(base64url) }).strict(), req, res);
      if (!input) return undefined;
      if (!await consumeAccountLimit(req, res)) return undefined;
      const token = await store.consumeAccountActionToken({ realm, type: 'email-verification', tokenDigest: actionDigest('email-verification', input.token) });
      if (!token) return problem(res, 400, 'Email verification unavailable', 'The verification link is invalid, expired, or already used.');
      const mutation = await data.mutateAccountSecurity(realm, token.userId, async (transactionalStore) => {
        const updated = await transactionalStore.updateUser(realm, token.userId, { email: token.email, emailVerified: true });
        if (updated) await transactionalStore.writeAudit(auditEvent(req, 'account.email.verified', token.userId));
        return updated;
      });
      if (!mutation.applied) return problem(res, 400, 'Email verification unavailable', 'The verification link is invalid, expired, or already used.');
      return res.status(204).end();
    } catch (error) {
      if (error.code === 'USER_EXISTS') return problem(res, 409, 'Email unavailable', 'This email address cannot be assigned.');
      return next(error);
    }
  });

  router.use('/api', (_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  router.use('/api', json({ limit: '64kb', strict: true }));
  router.use('/api', async (req, res, next) => {
    try {
      const { authentication, handled } = await authenticatedRequest(req, res);
      if (handled) return undefined;
      if (!authentication) return problem(res, 401, 'Account sign-in required', 'Sign in to manage your AuthMe account.');
      if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        if (!req.is('application/json')) return problem(res, 415, 'Unsupported media type', 'Account mutations require application/json.');
        if (!verifyCsrf(req, authentication)) return problem(res, 403, 'Invalid CSRF token', 'Reload the account console and try again.');
        if (req.path !== '/logout' && !hasRecentAuthentication(authentication)) {
          return problem(res, 403, 'Recent authentication required', 'Sign out and complete a fresh sign-in before changing account settings.');
        }
      }
      req.authmeAccount = authentication;
      return next();
    } catch (error) { return next(error); }
  });

  router.get('/api/session', async (req, res, next) => {
    try {
    const { user, sessionValue } = req.authmeAccount;
    const organizations = management ? await management.listUserOrganizations(realm, user.id) : [];
    return res.json({
      realm,
      csrf: csrfFor(sessionValue),
      user: {
        username: user.username,
        email: user.email,
        emailVerified: user.emailVerified,
        name: user.name,
        givenName: user.givenName,
        familyName: user.familyName,
        mfaEnabled: Boolean(user.totpConfirmed),
        recoveryCodesRemaining: user.recoveryCodeHashes.length,
      },
      organizations: organizations.map(({ id, name, alias, roles }) => ({ id, name, alias, roles })),
    });
    } catch (error) { return next(error); }
  });

  router.get('/api/organizations', async (req, res, next) => {
    try {
      const organizations = management
        ? await management.listUserOrganizations(realm, req.authmeAccount.user.id)
        : [];
      return res.json({ organizations: organizations.map(({ id, name, alias, domains, roles }) => ({ id, name, alias, domains, roles })) });
    } catch (error) { return next(error); }
  });

  router.post('/api/organization-invitations/accept', async (req, res, next) => {
    try {
      const input = parse(z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict(), req, res);
      if (!input) return undefined;
      const { user } = req.authmeAccount;
      const invitation = management && await management.consumeOrganizationInvitation(
        realm,
        keyedDigest(`organization-invitation:${realm}:${input.token}`, config.passwordPepper),
        user,
      );
      if (!invitation) return problem(res, 400, 'Invitation unavailable', 'The invitation is invalid, expired, already used, or belongs to another email address.');
      await store.writeAudit(auditEvent(req, 'account.organization_invitation.accepted', user.id, {
        invitationId: invitation.id,
        organizationId: invitation.organizationId,
      }));
      await data.revokeAccount(realm, user.id);
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.patch('/api/profile', async (req, res, next) => {
    try {
      const input = parse(profileSchema, req, res);
      if (!input) return undefined;
      const { user } = req.authmeAccount;
      const email = input.email.trim().toLowerCase();
      const duplicate = await store.findUserByLogin(realm, email);
      if (duplicate && duplicate.id !== user.id) return problem(res, 409, 'Email unavailable', 'This email address cannot be assigned.');
      const updated = await store.updateUser(realm, user.id, {
        name: input.name,
        givenName: input.givenName,
        familyName: input.familyName,
      });
      await store.writeAudit(auditEvent(req, 'account.profile.updated', user.id, { fields: ['name', 'givenName', 'familyName'] }));
      const verificationRequired = email !== updated.email || !updated.emailVerified;
      if (verificationRequired) {
        const token = randomToken(32);
        await store.createAccountActionToken({
          realm,
          userId: user.id,
          type: 'email-verification',
          tokenDigest: actionDigest('email-verification', token),
          email,
          expiresAt: new Date(Date.now() + TOKEN_TTL_MS),
        });
        const url = `${config.publicUrl}${root}/verify-email?token=${encodeURIComponent(token)}`;
        await dispatch('email-verification', { realm, email, token, url, user: { id: user.id, username: user.username, name: updated.name } });
        await store.writeAudit(auditEvent(req, 'account.email.verification_requested', user.id));
      }
      return res.json({
        message: verificationRequired ? 'Profile saved. Check the requested email address for a verification link.' : 'Profile saved.',
      });
    } catch (error) {
      if (error.code === 'ACCOUNT_DELIVERY_UNAVAILABLE') return problem(res, 503, 'Email delivery unavailable', 'Email verification cannot be delivered right now.');
      return next(error);
    }
  });

  router.put('/api/password', async (req, res, next) => {
    try {
      const input = parse(z.object({ currentPassword: z.string().max(1024), newPassword: passwordSchema }).strict(), req, res);
      if (!input) return undefined;
      const { user } = req.authmeAccount;
      if (!await verifyPassword(user.passwordHash, input.currentPassword, config.passwordPepper)) {
        await store.writeAudit(auditEvent(req, 'account.password_change.failed', user.id));
        return problem(res, 403, 'Password change denied', 'The current password is incorrect.');
      }
      const passwordHash = await hashPassword(input.newPassword, config.passwordPepper);
      const mutation = await data.mutateAccountSecurity(realm, user.id, async (transactionalStore) => {
        const changed = await transactionalStore.rehashPasswordIfCurrent(realm, user.id, user.passwordHash, passwordHash);
        if (changed) await transactionalStore.writeAudit(auditEvent(req, 'account.password.changed', user.id));
        return changed;
      });
      if (!mutation.applied) return problem(res, 409, 'Password changed elsewhere', 'Sign in again before retrying the password change.');
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.post('/api/mfa/totp', async (req, res, next) => {
    try {
      const { user } = req.authmeAccount;
      const setup = createTotp({ issuer: `AuthMe (${realm})`, accountName: user.email });
      const pending = encryptSecret(setup.secret, config.fieldEncryptionKey, `${realm}:${user.id}:totp:pending`);
      await store.beginTotpEnrollment(realm, user.id, pending);
      await store.writeAudit(auditEvent(req, 'account.mfa_totp.started', user.id));
      return res.status(201).json({ provisioningUri: setup.uri, secret: setup.secret, confirmationRequired: true });
    } catch (error) { return next(error); }
  });

  router.post('/api/mfa/totp/confirm', async (req, res, next) => {
    try {
      const input = parse(z.object({ token: z.string().regex(/^\d{6}$/) }).strict(), req, res);
      if (!input) return undefined;
      const current = await store.findUserById(realm, req.authmeAccount.user.id);
      if (!current?.pendingTotpSecret) return problem(res, 409, 'TOTP setup not started', 'Start authenticator enrollment before confirming it.');
      const secret = decryptSecret(current.pendingTotpSecret, config.fieldEncryptionKey, `${realm}:${current.id}:totp:pending`);
      const step = totpStep(secret, input.token);
      if (step === null) return problem(res, 400, 'Invalid authenticator code', 'The code is not valid for this enrollment.');
      const recovery = createRecoveryCodes(config.passwordPepper);
      const activeSecret = encryptSecret(secret, config.fieldEncryptionKey, `${realm}:${current.id}:totp`);
      const mutation = await data.mutateAccountSecurity(realm, current.id, async (transactionalStore) => {
        const applied = await transactionalStore.confirmTotpEnrollment(realm, current.id, {
          pendingSecret: current.pendingTotpSecret,
          activeSecret,
          step,
          recoveryCodeHashes: recovery.digests,
        });
        if (applied) await transactionalStore.writeAudit(auditEvent(req, 'account.mfa_totp.enabled', current.id));
        return applied;
      });
      if (!mutation.applied) return problem(res, 409, 'TOTP enrollment changed', 'This enrollment was already confirmed or replaced.');
      return res.json({ recoveryCodes: recovery.codes });
    } catch (error) { return next(error); }
  });

  router.delete('/api/mfa/totp', async (req, res, next) => {
    try {
      const { user } = req.authmeAccount;
      const mutation = await data.mutateAccountSecurity(realm, user.id, async (transactionalStore) => {
        const updated = await transactionalStore.configureTotp(realm, user.id, { secret: null, confirmed: false, recoveryCodeHashes: [] });
        if (updated) await transactionalStore.writeAudit(auditEvent(req, 'account.mfa_totp.disabled', user.id));
        return updated;
      });
      if (!mutation.applied) return problem(res, 409, 'Account changed', 'Sign in again before retrying.');
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.post('/api/mfa/recovery-codes', async (req, res, next) => {
    try {
      const { user } = req.authmeAccount;
      if (!user.totpConfirmed || !user.totpSecret) return problem(res, 409, 'Authenticator required', 'Enroll an authenticator before creating recovery codes.');
      const recovery = createRecoveryCodes(config.passwordPepper);
      const mutation = await data.mutateAccountSecurity(realm, user.id, async (transactionalStore) => {
        const updated = await transactionalStore.configureTotp(realm, user.id, {
          secret: user.totpSecret,
          confirmed: true,
          recoveryCodeHashes: recovery.digests,
        });
        if (updated) await transactionalStore.writeAudit(auditEvent(req, 'account.recovery_codes.regenerated', user.id));
        return updated;
      });
      if (!mutation.applied) return problem(res, 409, 'Account changed', 'Sign in again before retrying.');
      return res.json({ recoveryCodes: recovery.codes });
    } catch (error) { return next(error); }
  });

  router.get('/api/passkeys', async (req, res, next) => {
    try {
      const credentials = await store.listWebAuthnCredentials(realm, req.authmeAccount.user.id);
      return res.json({ passkeys: credentials.map(publicPasskey) });
    } catch (error) { return next(error); }
  });

  router.post('/api/passkeys/registration/options', async (req, res, next) => {
    try {
      const { user } = req.authmeAccount;
      const credentials = await store.listWebAuthnCredentials(realm, user.id);
      const publicKey = await passkeys.registrationOptions({ realm, user, credentials });
      const challenge = await store.createWebAuthnChallenge({
        realm,
        purpose: 'registration',
        userId: user.id,
        userHandle: publicKey.user.id,
        challenge: publicKey.challenge,
        expiresAt: new Date(Date.now() + config.webauthnChallengeTtl * 1000),
      });
      return res.status(201).json({ challengeId: challenge.id, expiresIn: config.webauthnChallengeTtl, publicKey });
    } catch (error) { return next(error); }
  });

  router.post('/api/passkeys/registration/verify', async (req, res, next) => {
    try {
      const input = parse(z.object({ challengeId: z.uuid(), name: z.string().trim().min(1).max(100), response: registrationResponse }).strict(), req, res);
      if (!input) return undefined;
      const { user } = req.authmeAccount;
      const challenge = await store.consumeWebAuthnChallenge({ realm, id: input.challengeId, purpose: 'registration', userId: user.id });
      if (!challenge) return problem(res, 409, 'Passkey ceremony unavailable', 'The registration challenge expired or was already used.');
      let verified;
      try { verified = await passkeys.verifyRegistration({ response: input.response, challenge: challenge.challenge }); } catch { verified = null; }
      if (!verified || verified.id !== input.response.id) {
        await store.writeAudit(auditEvent(req, 'account.passkey_registration.failed', user.id));
        return problem(res, 400, 'Passkey registration failed', 'The authenticator response could not be verified.');
      }
      const mutation = await data.mutateAccountSecurity(realm, user.id, async (transactionalStore) => {
        const credential = await transactionalStore.createWebAuthnCredential({
          ...verified,
          realm,
          userId: user.id,
          userHandle: challenge.userHandle,
          name: input.name,
        });
        if (credential) await transactionalStore.writeAudit(auditEvent(req, 'account.passkey.registered', user.id, { credentialId: credential.id }));
        return credential;
      });
      if (!mutation.applied) return problem(res, 409, 'Passkey registration changed', 'Sign in again and start a new registration.');
      return res.status(201).json(publicPasskey(mutation.result));
    } catch (error) {
      if (error.code === 'WEBAUTHN_CREDENTIAL_EXISTS') return problem(res, 409, 'Passkey already registered', 'This passkey is already registered.');
      return next(error);
    }
  });

  router.delete('/api/passkeys/:credentialId', async (req, res, next) => {
    try {
      if (!/^[A-Za-z0-9_-]{1,2048}$/.test(req.params.credentialId)) return problem(res, 400, 'Invalid passkey identifier', 'The passkey identifier is invalid.');
      const { user } = req.authmeAccount;
      const mutation = await data.mutateAccountSecurity(realm, user.id, async (transactionalStore) => {
        const credential = await transactionalStore.deleteWebAuthnCredential(realm, user.id, req.params.credentialId);
        if (credential) await transactionalStore.writeAudit(auditEvent(req, 'account.passkey.removed', user.id, { credentialId: credential.id }));
        return credential;
      });
      if (!mutation.applied) return problem(res, 404, 'Passkey not found', 'The passkey does not exist on this account.');
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.get('/api/sessions', async (req, res, next) => {
    try {
      const { user, sessionDigest: currentDigest } = req.authmeAccount;
      const now = Date.now();
      const accountSessions = (await store.listAccountSessions(realm, user.id))
        .filter((session) => session.securityVersion === user.securityVersion
          && new Date(session.expiresAt).getTime() > now && new Date(session.idleExpiresAt).getTime() > now)
        .map((session) => ({
          reference: sessionReference('account-console', session.idDigest),
          kind: 'account-console',
          current: session.idDigest === currentDigest,
          createdAt: session.createdAt,
          lastSeenAt: session.lastSeenAt,
          expiresAt: session.expiresAt,
          clientIds: [],
          ip: session.ip,
          userAgent: session.userAgent,
        }));
      const oidcSessions = (await data.listOidcSessions(realm, user.id)).map((session) => ({
        reference: sessionReference('oidc', session.id),
        kind: 'oidc',
        current: false,
        createdAt: session.createdAt,
        lastSeenAt: session.lastSeenAt,
        expiresAt: session.expiresAt,
        clientIds: session.clientIds,
        ip: null,
        userAgent: null,
      }));
      return res.json({ sessions: [...accountSessions, ...oidcSessions] });
    } catch (error) { return next(error); }
  });

  router.delete('/api/sessions/:reference', async (req, res, next) => {
    try {
      if (!/^[A-Za-z0-9_-]{43}$/.test(req.params.reference)) return problem(res, 404, 'Session not found', 'The requested session does not exist on this account.');
      const { user, sessionDigest: currentDigest } = req.authmeAccount;
      const accountSessions = await store.listAccountSessions(realm, user.id);
      const account = accountSessions.find((session) => safeEqual(req.params.reference, sessionReference('account-console', session.idDigest)));
      let revoked = false;
      let current = false;
      let kind;
      if (account) {
        current = account.idDigest === currentDigest;
        kind = 'account-console';
        await store.writeAudit(auditEvent(req, 'account.session.revoked', user.id, { kind, current }));
        revoked = await store.deleteAccountSession(account.idDigest);
      } else {
        const sessions = await data.listOidcSessions(realm, user.id);
        const oidc = sessions.find((session) => safeEqual(req.params.reference, sessionReference('oidc', session.id)));
        if (oidc) {
          kind = 'oidc';
          await store.writeAudit(auditEvent(req, 'account.session.revoked', user.id, { kind, current }));
          revoked = await data.revokeOidcSession(realm, user.id, oidc.id);
        }
      }
      if (!revoked) return problem(res, 404, 'Session not found', 'The requested session does not exist on this account.');
      if (current) clearCookie(res, SESSION_COOKIE);
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.post('/api/logout', async (req, res, next) => {
    try {
      const { user, sessionDigest: digest } = req.authmeAccount;
      await store.writeAudit(auditEvent(req, 'account.console.logout', user.id));
      await store.deleteAccountSession(digest);
      clearCookie(res, SESSION_COOKIE);
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.use((error, req, res, _next) => {
    logger?.[error?.status >= 500 || !error?.status ? 'error' : 'warn']({
      error: loggableError(error),
      realm,
    }, 'Account console request failed');
    if (res.headersSent) return res.end();
    return problem(
      res,
      Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500,
      'Account request failed',
      error.safe ? error.message : 'The account request could not be completed safely.',
    );
  });

  return { router, authenticate, csrfFor, sessionDigest };
}

export const accountConsoleCookies = Object.freeze({ session: SESSION_COOKIE, login: LOGIN_COOKIE });
