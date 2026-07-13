import { Router, json } from 'express';
import { z } from 'zod';
import { createRecoveryCodes, createTotp, totpStep } from '../crypto/mfa.js';
import { hashPassword } from '../crypto/password.js';
import { decryptSecret, encryptSecret, safeEqual } from '../crypto/secrets.js';
import { publicUser } from '../repositories/identity-store.js';

const identifier = z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9._@+-]+$/);
const role = z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9:._/-]+$/);
const group = z.string().trim().min(1).max(256).regex(/^\/.+|^[a-zA-Z0-9:._-]+$/);
const password = z.string().min(12).max(1024);
const clientRoles = z.record(z.string().min(1).max(255), z.array(role).max(200)).default({});

const createUserSchema = z.object({
  username: identifier,
  email: z.email().max(254),
  password,
  emailVerified: z.boolean().optional().default(false),
  name: z.string().trim().min(1).max(255).optional(),
  givenName: z.string().trim().max(255).optional(),
  familyName: z.string().trim().max(255).optional(),
  enabled: z.boolean().optional().default(true),
  roles: z.array(role).max(200).optional().default([]),
  groups: z.array(group).max(200).optional().default([]),
  clientRoles: clientRoles.optional(),
}).strict();

const updateUserSchema = z.object({
  email: z.email().max(254).optional(),
  emailVerified: z.boolean().optional(),
  name: z.string().trim().min(1).max(255).optional(),
  givenName: z.string().trim().max(255).optional(),
  familyName: z.string().trim().max(255).optional(),
  enabled: z.boolean().optional(),
  roles: z.array(role).max(200).optional(),
  groups: z.array(group).max(200).optional(),
  clientRoles: clientRoles.optional(),
}).strict();

function problem(res, status, title, detail) {
  return res.status(status).type('application/problem+json').json({
    type: 'about:blank', title, status, detail,
  });
}

function parse(schema, req, res) {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    problem(res, 400, 'Invalid request', result.error.issues.map((issue) => `${issue.path.join('.') || 'body'}: ${issue.message}`).join('; '));
    return null;
  }
  return result.data;
}

function page(req) {
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), 250);
  const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);
  return { limit, offset };
}

async function audit(store, req, type, subjectId, metadata = {}) {
  await store.writeAudit({
    realm: req.params.realm,
    type,
    subjectId,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    metadata,
  });
}

export function createAdminRouter({ config, store, rateLimits, metrics, providers, data }) {
  const router = Router();
  router.use(json({ limit: '64kb', strict: true }));
  router.use(async (req, res, next) => {
    try {
      await rateLimits.consumeAdmin(req.ip);
    } catch (error) {
      res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
      return problem(res, 429, 'Too many requests', 'Wait before retrying the administration API.');
    }
    const match = /^Bearer ([^\s]+)$/.exec(req.get('authorization') ?? '');
    if (!match || !safeEqual(match[1], config.adminToken)) {
      res.set('WWW-Authenticate', 'Bearer realm="authme-admin"');
      return problem(res, 401, 'Unauthorized', 'A valid AuthMe administration token is required.');
    }
    res.set('Cache-Control', 'no-store');
    return next();
  });

  router.get('/metrics', async (_req, res, next) => {
    try {
      res.type(metrics.contentType).send(await metrics.render());
    } catch (error) { next(error); }
  });

  router.get('/v1/realms', (_req, res) => {
    res.json({ realms: config.realms.map((name) => ({ name, issuer: `${config.publicUrl}/realms/${name}` })) });
  });

  router.post('/v1/realms/:realm/client-registration-tokens', async (req, res, next) => {
    try {
      if (!config.realms.includes(req.params.realm)) return problem(res, 404, 'Realm not found', 'The requested realm does not exist.');
      if (!config.enableDynamicRegistration) return problem(res, 409, 'Dynamic registration disabled', 'Enable dynamic registration before issuing an initial access token.');
      const input = parse(z.object({ expiresInSeconds: z.number().int().min(60).max(3600).optional().default(900) }).strict(), req, res);
      if (!input) return;
      const provider = providers.get(req.params.realm);
      const token = await new provider.InitialAccessToken({
        expiresIn: input.expiresInSeconds,
        policies: ['authme-secure-client'],
      }).save();
      await audit(store, req, 'admin.client_registration_token.issued', undefined, { expiresInSeconds: input.expiresInSeconds });
      res.status(201).json({ token, tokenType: 'Bearer', expiresIn: input.expiresInSeconds });
    } catch (error) { next(error); }
  });

  router.use('/v1/realms/:realm', (req, res, next) => {
    if (!config.realms.includes(req.params.realm)) return problem(res, 404, 'Realm not found', 'The requested realm does not exist.');
    return next();
  });

  router.get('/v1/realms/:realm/users', async (req, res, next) => {
    try {
      const pagination = page(req);
      const users = await store.listUsers(req.params.realm, pagination);
      res.json({ users: users.map(publicUser), ...pagination });
    } catch (error) { next(error); }
  });

  router.post('/v1/realms/:realm/users', async (req, res, next) => {
    try {
      const input = parse(createUserSchema, req, res);
      if (!input) return;
      const user = await store.createUser({
        ...input,
        realm: req.params.realm,
        passwordHash: await hashPassword(input.password, config.passwordPepper),
      });
      await audit(store, req, 'admin.user.created', user.id);
      res.status(201).location(`/admin/v1/realms/${encodeURIComponent(req.params.realm)}/users/${user.id}`).json(publicUser(user));
    } catch (error) {
      if (error.code === 'USER_EXISTS') return problem(res, 409, 'User already exists', error.message);
      next(error);
    }
  });

  router.get('/v1/realms/:realm/users/:id', async (req, res, next) => {
    try {
      const user = await store.findUserById(req.params.realm, req.params.id);
      if (!user) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      res.json(publicUser(user));
    } catch (error) { next(error); }
  });

  router.patch('/v1/realms/:realm/users/:id', async (req, res, next) => {
    try {
      const input = parse(updateUserSchema, req, res);
      if (!input) return;
      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, (transactionalStore) => (
        transactionalStore.updateUser(req.params.realm, req.params.id, input)
      ));
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const user = mutation.user;
      await audit(store, req, 'admin.user.updated', user.id, { fields: Object.keys(input) });
      res.json(publicUser(user));
    } catch (error) {
      if (error.code === 'USER_EXISTS') return problem(res, 409, 'User already exists', error.message);
      next(error);
    }
  });

  router.put('/v1/realms/:realm/users/:id/password', async (req, res, next) => {
    try {
      const input = parse(z.object({ password }).strict(), req, res);
      if (!input) return;
      const passwordHash = await hashPassword(input.password, config.passwordPepper);
      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, async (transactionalStore) => {
        const updated = await transactionalStore.updateUser(req.params.realm, req.params.id, { passwordHash });
        if (updated) await transactionalStore.unlockUser(req.params.realm, req.params.id);
        return updated;
      });
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const user = mutation.user;
      await audit(store, req, 'admin.user.password_reset', user.id);
      res.status(204).end();
    } catch (error) { next(error); }
  });

  router.post('/v1/realms/:realm/users/:id/unlock', async (req, res, next) => {
    try {
      const user = await store.unlockUser(req.params.realm, req.params.id);
      if (!user) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      await audit(store, req, 'admin.user.unlocked', user.id);
      res.status(204).end();
    } catch (error) { next(error); }
  });

  router.post('/v1/realms/:realm/users/:id/mfa/totp', async (req, res, next) => {
    try {
      const user = await store.findUserById(req.params.realm, req.params.id);
      if (!user) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const setup = createTotp({ issuer: `AuthMe (${req.params.realm})`, accountName: user.email });
      const encrypted = encryptSecret(setup.secret, config.fieldEncryptionKey, `${req.params.realm}:${user.id}:totp:pending`);
      await store.beginTotpEnrollment(req.params.realm, user.id, encrypted);
      await audit(store, req, 'admin.user.mfa_totp_started', user.id);
      res.status(201).json({ provisioningUri: setup.uri, secret: setup.secret, confirmationRequired: true });
    } catch (error) { next(error); }
  });

  router.post('/v1/realms/:realm/users/:id/mfa/totp/confirm', async (req, res, next) => {
    try {
      const input = parse(z.object({ token: z.string().regex(/^\d{6}$/) }).strict(), req, res);
      if (!input) return;
      const user = await store.findUserById(req.params.realm, req.params.id);
      if (!user) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      if (!user.pendingTotpSecret) return problem(res, 409, 'TOTP setup not started', 'Start TOTP enrollment before confirming it.');
      const secret = decryptSecret(user.pendingTotpSecret, config.fieldEncryptionKey, `${req.params.realm}:${user.id}:totp:pending`);
      const step = totpStep(secret, input.token);
      if (step === null) return problem(res, 400, 'Invalid authenticator code', 'The code is not valid for the pending TOTP enrollment.');
      const recovery = createRecoveryCodes(config.passwordPepper);
      const activeSecret = encryptSecret(secret, config.fieldEncryptionKey, `${req.params.realm}:${user.id}:totp`);
      const mutation = await data.mutateAccountSecurity(req.params.realm, user.id, (transactionalStore) => (
        transactionalStore.confirmTotpEnrollment(req.params.realm, user.id, {
          pendingSecret: user.pendingTotpSecret,
          activeSecret,
          step,
          recoveryCodeHashes: recovery.digests,
        })
      ));
      if (!mutation.applied) return problem(res, 409, 'TOTP enrollment changed', 'This enrollment was already confirmed or replaced. Start again.');
      await audit(store, req, 'admin.user.mfa_totp_enabled', user.id);
      res.json({ recoveryCodes: recovery.codes });
    } catch (error) { next(error); }
  });

  router.delete('/v1/realms/:realm/users/:id/mfa/totp', async (req, res, next) => {
    try {
      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, (transactionalStore) => (
        transactionalStore.configureTotp(req.params.realm, req.params.id, { secret: null, confirmed: false, recoveryCodeHashes: [] })
      ));
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const user = mutation.user;
      await audit(store, req, 'admin.user.mfa_totp_disabled', user.id);
      res.status(204).end();
    } catch (error) { next(error); }
  });

  router.get('/v1/realms/:realm/audit', async (req, res, next) => {
    try {
      const pagination = page(req);
      await audit(store, req, 'admin.audit.read', undefined, pagination);
      res.json({ events: await store.listAudit(req.params.realm, pagination), ...pagination });
    } catch (error) { next(error); }
  });

  return router;
}
