import { Router, json } from 'express';
import { z } from 'zod';
import { createRecoveryCodes, createTotp, totpStep } from '../crypto/mfa.js';
import { hashPassword } from '../crypto/password.js';
import { decryptSecret, encryptSecret, safeEqual } from '../crypto/secrets.js';
import { publicUser } from '../repositories/identity-store.js';
import { createWebAuthn } from '../security/webauthn.js';

const identifier = z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9._@+-]+$/);
const role = z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9:._/-]+$/);
const group = z.string().trim().min(1).max(256).regex(/^\/.+|^[a-zA-Z0-9:._-]+$/);
const password = z.string().min(12).max(1024);
const userId = z.uuid();
const base64url = z.string().min(1).max(2048).regex(/^[A-Za-z0-9_-]+$/);
const encodedWebAuthnData = z.string().min(1).max(32_768).regex(/^[A-Za-z0-9_-]+$/);
const passkeyName = z.string().trim().min(1).max(100).optional().default('Passkey');
const federatedProviderId = z.string().regex(/^[a-z][a-z0-9-]{1,63}$/);
const federatedIssuer = z.string().trim().min(1).max(2048).refine((value) => {
  try {
    const url = new URL(value);
    return Boolean(url.protocol) && !url.username && !url.password && !url.hash;
  } catch { return false; }
}, 'issuer must be an absolute URL without credentials or a fragment');
const federatedSubject = z.string().trim().min(1).max(2048)
  .refine((value) => !/[\u0000-\u001f\u007f]/.test(value), 'externalSubject cannot contain control characters');
const federatedLinkSchema = z.object({
  providerId: federatedProviderId,
  issuer: federatedIssuer,
  externalSubject: federatedSubject,
}).strict();
const federatedUnlinkSchema = federatedLinkSchema.omit({ externalSubject: true });
const registrationResponse = z.object({
  id: base64url,
  rawId: base64url,
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: encodedWebAuthnData,
    attestationObject: encodedWebAuthnData,
    transports: z.array(z.enum(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'])).max(7).optional(),
  }).passthrough(),
}).passthrough();
const clientRoles = z.record(z.string().min(1).max(255), z.array(role).max(200)).default({});
const paginationSchema = z.object({
  limit: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().min(1).max(250)).optional().default(100),
  offset: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().min(0).max(10_000_000)).optional().default(0),
}).passthrough();

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

function page(req, res) {
  const result = paginationSchema.safeParse(req.query);
  if (!result.success) {
    problem(res, 400, 'Invalid pagination', 'limit must be between 1 and 250 and offset must be a non-negative integer.');
    return null;
  }
  return { limit: result.data.limit, offset: result.data.offset };
}

function auditEvent(req, type, subjectId, metadata = {}) {
  return {
    realm: req.params.realm,
    type,
    subjectId,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    metadata,
  };
}

async function audit(store, req, type, subjectId, metadata = {}) {
  await store.writeAudit(auditEvent(req, type, subjectId, metadata));
}

function publicPasskey(credential) {
  const { publicKey, userHandle, counter, realm, userId, ...safe } = credential;
  return safe;
}

export function createAdminRouter({
  config,
  store,
  rateLimits,
  metrics,
  providers,
  data,
  webauthn,
  federatedIdentities,
}) {
  const passkeys = webauthn ?? createWebAuthn(config);
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
  router.param('id', (req, res, next, value) => {
    if (!userId.safeParse(value).success) {
      return problem(res, 400, 'Invalid user identifier', 'User identifiers must be UUIDs.');
    }
    return next();
  });
  router.param('credentialId', (req, res, next, value) => {
    if (!base64url.safeParse(value).success) {
      return problem(res, 400, 'Invalid passkey identifier', 'Passkey identifiers must be base64url values.');
    }
    return next();
  });

  router.get('/v1/realms/:realm/users', async (req, res, next) => {
    try {
      const pagination = page(req, res);
      if (!pagination) return;
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

  router.get('/v1/realms/:realm/users/:id/federated-identities', async (req, res, next) => {
    try {
      const user = await store.findUserById(req.params.realm, req.params.id);
      if (!user) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const identities = await federatedIdentities.list(req.params.realm, user.id);
      return res.json({ identities });
    } catch (error) { return next(error); }
  });

  router.post('/v1/realms/:realm/users/:id/federated-identities', async (req, res, next) => {
    try {
      const input = parse(federatedLinkSchema, req, res);
      if (!input) return;
      const configured = [
        ...(config.ldapProvidersByRealm[req.params.realm] ?? []).map((item) => ({ id: item.id, issuer: item.url })),
        ...(config.oidcProvidersByRealm[req.params.realm] ?? []).map((item) => ({ id: item.id, issuer: item.issuer })),
        ...(config.samlProvidersByRealm[req.params.realm] ?? []).map((item) => ({ id: item.id, issuer: item.idp.entityId })),
      ].some((item) => item.id === input.providerId && item.issuer === input.issuer);
      if (!configured) {
        return problem(res, 400, 'Unknown federation provider', 'The provider and issuer must exactly match an enabled realm provider.');
      }
      const result = await federatedIdentities.link({
        realm: req.params.realm,
        userId: req.params.id,
        ...input,
      });
      if (result.status === 'not_found') return problem(res, 404, 'User not found', 'The requested user does not exist.');
      if (result.status === 'conflict') {
        return problem(res, 409, 'Federated identity conflict', 'The external identity or provider is already linked.');
      }
      await audit(store, req, 'admin.user.federated_identity_linked', req.params.id, {
        providerId: input.providerId,
        issuer: input.issuer,
      });
      return res.status(201).json(result.link);
    } catch (error) { return next(error); }
  });

  router.delete('/v1/realms/:realm/users/:id/federated-identities', async (req, res, next) => {
    try {
      const input = parse(federatedUnlinkSchema, req, res);
      if (!input) return;
      const link = await federatedIdentities.unlink({
        realm: req.params.realm,
        userId: req.params.id,
        ...input,
      });
      if (!link) return problem(res, 404, 'Federated identity not found', 'The requested link does not exist for this user.');
      await audit(store, req, 'admin.user.federated_identity_unlinked', req.params.id, {
        providerId: input.providerId,
        issuer: input.issuer,
      });
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.get('/v1/realms/:realm/users/:id/passkeys', async (req, res, next) => {
    try {
      const user = await store.findUserById(req.params.realm, req.params.id);
      if (!user) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const credentials = await store.listWebAuthnCredentials(req.params.realm, user.id);
      return res.json({ passkeys: credentials.map(publicPasskey) });
    } catch (error) { return next(error); }
  });

  router.post('/v1/realms/:realm/users/:id/passkeys/registration/options', async (req, res, next) => {
    try {
      const user = await store.findUserById(req.params.realm, req.params.id);
      if (!user) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const credentials = await store.listWebAuthnCredentials(req.params.realm, user.id);
      const publicKey = await passkeys.registrationOptions({ realm: req.params.realm, user, credentials });
      const challenge = await store.createWebAuthnChallenge({
        realm: req.params.realm,
        purpose: 'registration',
        userId: user.id,
        userHandle: publicKey.user.id,
        challenge: publicKey.challenge,
        expiresAt: new Date(Date.now() + config.webauthnChallengeTtl * 1000),
      });
      return res.status(201).json({
        challengeId: challenge.id,
        expiresIn: config.webauthnChallengeTtl,
        publicKey,
      });
    } catch (error) { return next(error); }
  });

  router.post('/v1/realms/:realm/users/:id/passkeys/registration/verify', async (req, res, next) => {
    try {
      const input = parse(z.object({
        challengeId: z.uuid(),
        name: passkeyName,
        response: registrationResponse,
      }).strict(), req, res);
      if (!input) return;
      const challenge = await store.consumeWebAuthnChallenge({
        realm: req.params.realm,
        id: input.challengeId,
        purpose: 'registration',
        userId: req.params.id,
      });
      if (!challenge) {
        return problem(res, 409, 'Passkey ceremony unavailable', 'The registration challenge expired, was already used, or does not belong to this user.');
      }

      let verified;
      try {
        verified = await passkeys.verifyRegistration({ response: input.response, challenge: challenge.challenge });
      } catch {
        verified = null;
      }
      if (!verified || verified.id !== input.response.id) {
        await audit(store, req, 'admin.user.passkey_registration_failed', req.params.id);
        return problem(res, 400, 'Passkey registration failed', 'The authenticator response could not be verified. Start a new registration ceremony.');
      }

      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, async (transactionalStore) => {
        const credential = await transactionalStore.createWebAuthnCredential({
          ...verified,
          realm: req.params.realm,
          userId: req.params.id,
          userHandle: challenge.userHandle,
          name: input.name,
        });
        if (!credential) return null;
        await transactionalStore.writeAudit(auditEvent(
          req,
          'admin.user.passkey_registered',
          req.params.id,
          { credentialId: credential.id, deviceType: credential.deviceType, backedUp: credential.backedUp },
        ));
        return credential;
      });
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      if (!mutation.applied) return problem(res, 409, 'Passkey registration changed', 'The user changed during registration. Start again.');
      return res.status(201).json(publicPasskey(mutation.result));
    } catch (error) {
      if (error.code === 'WEBAUTHN_CREDENTIAL_EXISTS') {
        return problem(res, 409, 'Passkey already registered', 'This credential is already registered in the realm.');
      }
      return next(error);
    }
  });

  router.delete('/v1/realms/:realm/users/:id/passkeys/:credentialId', async (req, res, next) => {
    try {
      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, async (transactionalStore) => {
        const credential = await transactionalStore.deleteWebAuthnCredential(
          req.params.realm,
          req.params.id,
          req.params.credentialId,
        );
        if (credential) await transactionalStore.writeAudit(auditEvent(
          req,
          'admin.user.passkey_deleted',
          req.params.id,
          { credentialId: credential.id },
        ));
        return credential;
      });
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      if (!mutation.applied) return problem(res, 404, 'Passkey not found', 'The requested passkey does not exist for this user.');
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.patch('/v1/realms/:realm/users/:id', async (req, res, next) => {
    try {
      const input = parse(updateUserSchema, req, res);
      if (!input) return;
      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, async (transactionalStore) => {
        const updated = await transactionalStore.updateUser(req.params.realm, req.params.id, input);
        if (updated) await transactionalStore.writeAudit(
          auditEvent(req, 'admin.user.updated', updated.id, { fields: Object.keys(input) }),
        );
        return updated;
      });
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      const user = mutation.user;
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
        if (updated) await transactionalStore.writeAudit(auditEvent(req, 'admin.user.password_reset', updated.id));
        return updated;
      });
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
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
      const mutation = await data.mutateAccountSecurity(req.params.realm, user.id, async (transactionalStore) => {
        const applied = await transactionalStore.confirmTotpEnrollment(req.params.realm, user.id, {
          pendingSecret: user.pendingTotpSecret,
          activeSecret,
          step,
          recoveryCodeHashes: recovery.digests,
        });
        if (applied) await transactionalStore.writeAudit(auditEvent(req, 'admin.user.mfa_totp_enabled', user.id));
        return applied;
      });
      if (!mutation.applied) return problem(res, 409, 'TOTP enrollment changed', 'This enrollment was already confirmed or replaced. Start again.');
      res.json({ recoveryCodes: recovery.codes });
    } catch (error) { next(error); }
  });

  router.delete('/v1/realms/:realm/users/:id/mfa/totp', async (req, res, next) => {
    try {
      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, async (transactionalStore) => {
        const updated = await transactionalStore.configureTotp(
          req.params.realm,
          req.params.id,
          { secret: null, confirmed: false, recoveryCodeHashes: [] },
        );
        if (updated) await transactionalStore.writeAudit(auditEvent(req, 'admin.user.mfa_totp_disabled', updated.id));
        return updated;
      });
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      res.status(204).end();
    } catch (error) { next(error); }
  });

  router.post('/v1/realms/:realm/users/:id/sessions/revoke', async (req, res, next) => {
    try {
      const mutation = await data.mutateAccountSecurity(req.params.realm, req.params.id, async (transactionalStore) => {
        await transactionalStore.writeAudit(auditEvent(req, 'admin.user.sessions_revoked', req.params.id));
        return true;
      });
      if (!mutation.found) return problem(res, 404, 'User not found', 'The requested user does not exist.');
      res.status(204).end();
    } catch (error) { next(error); }
  });

  router.delete('/v1/realms/:realm/users/:id', async (req, res, next) => {
    try {
      await data.deleteAccount(
        req.params.realm,
        req.params.id,
        auditEvent(req, 'admin.user.deleted', req.params.id),
      );
      res.status(204).end();
    } catch (error) { next(error); }
  });

  router.get('/v1/realms/:realm/audit', async (req, res, next) => {
    try {
      const pagination = page(req, res);
      if (!pagination) return;
      await audit(store, req, 'admin.audit.read', undefined, pagination);
      res.json({ events: await store.listAudit(req.params.realm, pagination), ...pagination });
    } catch (error) { next(error); }
  });

  return router;
}
