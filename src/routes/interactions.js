import { Router, urlencoded } from 'express';
import { resolveFederatedLogin } from '../authentication/federated-login.js';
import { createCsrfToken, verifyCsrfToken } from '../crypto/csrf.js';
import { decryptSecret, safeEqual } from '../crypto/secrets.js';
import { recoveryCodeDigest, totpStep } from '../crypto/mfa.js';
import { hashPassword, needsPasswordRehash, verifyPassword } from '../crypto/password.js';
import { createWebAuthn } from '../security/webauthn.js';
import { createFederationInitiationCsrfToken } from './federation.js';
import { renderConsent, renderLogin } from '../ui/render.js';

const form = urlencoded({ extended: false, limit: '16kb', parameterLimit: 20 });
const passkeyForm = urlencoded({ extended: false, limit: '64kb', parameterLimit: 10 });
const base64url = /^[A-Za-z0-9_-]+$/;

function noStore(_req, res, next) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
}

function interactionClientName(client) {
  return client.clientName || client.clientId;
}

async function interaction(provider, req, res, expectedPrompt) {
  const details = await provider.interactionDetails(req, res);
  if (details.uid !== req.params.uid || (expectedPrompt && details.prompt.name !== expectedPrompt)) {
    throw Object.assign(new Error('Interaction state does not match this request'), { status: 400 });
  }
  return details;
}

function parseAssertion(value) {
  if (typeof value !== 'string' || value.length < 2 || value.length > 60_000) return null;
  let response;
  try { response = JSON.parse(value); } catch { return null; }
  const fields = [
    response?.id,
    response?.rawId,
    response?.response?.clientDataJSON,
    response?.response?.authenticatorData,
    response?.response?.signature,
    response?.response?.userHandle,
  ];
  if (response?.type !== 'public-key'
    || fields.some((field) => typeof field !== 'string' || !field.length || field.length > 16_384 || !base64url.test(field))) {
    return null;
  }
  return response;
}

export function createInteractionRouter({
  realm,
  provider,
  store,
  config,
  rateLimits,
  dummyPasswordHash,
  logger,
  webauthn,
  identityRuntime,
}) {
  const passkeys = webauthn ?? createWebAuthn(config);
  const router = Router();
  const base = `/realms/${realm}/interaction/:uid`;

  function federationProviders(interactionUid) {
    return (identityRuntime?.federationEntriesFor?.(realm) ?? []).flatMap(({ manifest, implementation }) => (
      (implementation.providersFor?.(realm) ?? []).map(({ id, displayName }) => ({
        extensionId: manifest.id,
        providerId: id,
        displayName,
        csrfToken: createFederationInitiationCsrfToken({
          realm,
          interactionUid,
          extensionId: manifest.id,
          providerId: id,
        }, config.csrfSecret),
      }))
    ));
  }

  function loginView({ uid, clientName, login = '', error = '' }) {
    return renderLogin({
      realm,
      uid,
      csrfToken: createCsrfToken(`${realm}:${uid}:login`, config.csrfSecret),
      clientName,
      login,
      error,
      federationProviders: federationProviders(uid),
    });
  }

  router.get(base, noStore, async (req, res, next) => {
    try {
      const details = await interaction(provider, req, res);
      const client = await provider.Client.find(details.params.client_id);
      if (details.prompt.name === 'login') {
        return res.send(loginView({
          uid: details.uid,
          clientName: interactionClientName(client),
        }));
      }
      if (details.prompt.name === 'consent') {
        const scopes = details.prompt.details.missingOIDCScope ?? String(details.params.scope ?? '').split(' ').filter(Boolean);
        const claims = (details.prompt.details.missingOIDCClaims ?? []).map((claim) => `claim:${claim}`);
        const resourceScopes = Object.entries(details.prompt.details.missingResourceScopes ?? {})
          .flatMap(([resource, values]) => values.map((scope) => `resource:${resource}:${scope}`));
        return res.send(renderConsent({
          realm,
          uid: details.uid,
          csrfToken: createCsrfToken(`${realm}:${details.uid}:consent`, config.csrfSecret),
          clientName: interactionClientName(client),
          scopes: [...new Set([...scopes, ...claims, ...resourceScopes])],
        }));
      }
      return next(Object.assign(new Error(`Unsupported interaction prompt: ${details.prompt.name}`), { status: 400 }));
    } catch (error) {
      return next(error);
    }
  });

  router.post(`${base}/login`, noStore, form, async (req, res, next) => {
    let details;
    try {
      details = await interaction(provider, req, res, 'login');
      if (!verifyCsrfToken(req.body.csrf, `${realm}:${details.uid}:login`, config.csrfSecret)) {
        throw Object.assign(new Error('The sign-in form expired. Please try again.'), { status: 403, safe: true });
      }
      const login = String(req.body.login ?? '').trim().slice(0, 254);
      await rateLimits.consumeLogin(req.ip, `${realm}:${login.toLowerCase()}`);
      let user = await store.findUserByLogin(realm, login);
      const suppliedPassword = String(req.body.password ?? '');
      let passwordOk = await verifyPassword(user?.passwordHash ?? dummyPasswordHash, suppliedPassword, config.passwordPepper);
      let authenticationMethod = 'pwd';
      if (!passwordOk && identityRuntime?.ldap?.implementation.enabledFor?.(realm)) {
        const ldap = await identityRuntime.ldap.implementation.authenticate({
          realm,
          login,
          secret: suppliedPassword,
        });
        if (ldap.status === 'success') {
          try {
            const resolution = await resolveFederatedLogin({
              realm,
              result: ldap,
              repository: identityRuntime.federatedIdentities,
            });
            user = resolution.user;
            passwordOk = true;
            authenticationMethod = 'ldap';
          } catch (error) {
            if (!String(error?.code ?? '').startsWith('AUTHME_FEDERATED_')) throw error;
            user = null;
            passwordOk = false;
          }
        }
      }
      const locked = user?.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now();
      let mfaOk = !user?.totpConfirmed;
      let recoveryUsed = false;
      if (passwordOk && user?.enabled && !locked && user?.totpConfirmed && user.totpSecret) {
        const secret = decryptSecret(user.totpSecret, config.fieldEncryptionKey, `${realm}:${user.id}:totp`);
        const step = totpStep(secret, req.body.otp);
        mfaOk = step !== null && await store.consumeTotpStep(realm, user.id, step);
        if (!mfaOk && req.body.otp) {
          recoveryUsed = await store.consumeRecoveryCode(realm, user.id, recoveryCodeDigest(req.body.otp, config.passwordPepper));
          mfaOk = recoveryUsed;
        }
      }
      if (!user?.enabled || !passwordOk || !mfaOk || locked) {
        if (user && !locked) await store.recordLoginFailure(realm, user.id);
        await store.writeAudit({ realm, type: 'identity.login.failed', subjectId: user?.id, clientId: details.params.client_id, ip: req.ip, userAgent: req.get('user-agent') });
        const client = await provider.Client.find(details.params.client_id);
        return res.status(401).send(loginView({
          uid: details.uid,
          clientName: interactionClientName(client),
          login,
          error: 'Sign-in failed. Check your credentials or wait before trying again.',
        }));
      }

      if (authenticationMethod === 'pwd' && needsPasswordRehash(user.passwordHash)) {
        const replacementHash = await hashPassword(suppliedPassword, config.passwordPepper);
        await store.rehashPasswordIfCurrent(realm, user.id, user.passwordHash, replacementHash);
      }
      await store.recordLoginSuccess(realm, user.id);
      const amr = user.totpConfirmed
        ? [authenticationMethod, recoveryUsed ? 'recovery' : 'otp']
        : [authenticationMethod];
      await store.writeAudit({ realm, type: 'identity.login.succeeded', subjectId: user.id, clientId: details.params.client_id, ip: req.ip, userAgent: req.get('user-agent'), metadata: { amr } });
      return provider.interactionFinished(req, res, {
        login: { accountId: user.id, acr: user.totpConfirmed ? 'urn:authme:loa:2' : 'urn:authme:loa:1', amr, remember: true },
      }, { mergeWithLastSubmission: false });
    } catch (error) {
      if (error?.msBeforeNext) {
        const client = details ? await provider.Client.find(details.params.client_id) : null;
        res.set('Retry-After', String(Math.max(1, Math.ceil(error.msBeforeNext / 1000))));
        return res.status(429).send(loginView({
          uid: details?.uid ?? req.params.uid,
          clientName: client ? interactionClientName(client) : 'this application',
          login: String(req.body.login ?? '').slice(0, 254),
          error: 'Too many sign-in attempts. Please wait and try again.',
        }));
      }
      logger.warn({ error, realm }, 'Login interaction failed');
      return next(error);
    }
  });

  router.post(`${base}/passkey/options`, noStore, form, async (req, res, next) => {
    let details;
    try {
      details = await interaction(provider, req, res, 'login');
      if (!verifyCsrfToken(req.body.csrf, `${realm}:${details.uid}:login`, config.csrfSecret)) {
        throw Object.assign(new Error('The sign-in form expired. Please try again.'), { status: 403, safe: true });
      }
      await rateLimits.consumeLogin(req.ip, `${realm}:passkey:${req.ip}`);
      const publicKey = await passkeys.authenticationOptions();
      const challenge = await store.createWebAuthnChallenge({
        realm,
        purpose: 'authentication',
        interactionUid: details.uid,
        challenge: publicKey.challenge,
        expiresAt: new Date(Date.now() + config.webauthnChallengeTtl * 1000),
      });
      return res.status(201).json({
        challengeId: challenge.id,
        expiresIn: config.webauthnChallengeTtl,
        publicKey,
      });
    } catch (error) {
      if (error?.msBeforeNext) {
        res.set('Retry-After', String(Math.max(1, Math.ceil(error.msBeforeNext / 1000))));
        return res.status(429).json({ error: 'slow_down' });
      }
      return next(error);
    }
  });

  router.post(`${base}/passkey`, noStore, passkeyForm, async (req, res, next) => {
    let details;
    try {
      details = await interaction(provider, req, res, 'login');
      if (!verifyCsrfToken(req.body.csrf, `${realm}:${details.uid}:login`, config.csrfSecret)) {
        throw Object.assign(new Error('The sign-in form expired. Please try again.'), { status: 403, safe: true });
      }
      const challengeId = typeof req.body.challengeId === 'string'
        && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(req.body.challengeId)
        ? req.body.challengeId
        : null;
      const challenge = challengeId && await store.consumeWebAuthnChallenge({
        realm,
        id: challengeId,
        purpose: 'authentication',
        interactionUid: details.uid,
      });
      const assertion = parseAssertion(req.body.credential);
      const credential = assertion && await store.findWebAuthnCredential(realm, assertion.id);
      const user = credential && await store.findUserById(realm, credential.userId);
      const locked = user?.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now();
      let verification = null;
      if (challenge && assertion && credential && user?.enabled && !locked
        && safeEqual(assertion.response.userHandle, credential.userHandle)) {
        try {
          verification = await passkeys.verifyAuthentication({
            response: assertion,
            challenge: challenge.challenge,
            credential,
          });
        } catch {
          verification = null;
        }
      }
      const counterUpdated = verification && await store.updateWebAuthnCredentialCounter(
        realm,
        credential.id,
        {
          expectedCounter: credential.counter,
          newCounter: verification.newCounter,
          deviceType: verification.deviceType,
          backedUp: verification.backedUp,
        },
      );
      if (!counterUpdated) {
        await store.writeAudit({
          realm,
          type: 'identity.login.passkey_failed',
          subjectId: user?.id,
          clientId: details.params.client_id,
          ip: req.ip,
          userAgent: req.get('user-agent'),
        });
        const client = await provider.Client.find(details.params.client_id);
        return res.status(401).send(loginView({
          uid: details.uid,
          clientName: interactionClientName(client),
          error: 'Passkey sign-in failed or expired. Try again or use your password.',
        }));
      }

      await store.recordLoginSuccess(realm, user.id);
      const amr = ['passkey'];
      await store.writeAudit({
        realm,
        type: 'identity.login.succeeded',
        subjectId: user.id,
        clientId: details.params.client_id,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        metadata: { amr, credentialId: credential.id },
      });
      return provider.interactionFinished(req, res, {
        login: { accountId: user.id, acr: 'urn:authme:loa:2', amr, remember: true },
      }, { mergeWithLastSubmission: false });
    } catch (error) {
      logger.warn({ error, realm }, 'Passkey interaction failed');
      return next(error);
    }
  });

  router.post(`${base}/confirm`, noStore, form, async (req, res, next) => {
    try {
      const details = await interaction(provider, req, res, 'consent');
      if (!verifyCsrfToken(req.body.csrf, `${realm}:${details.uid}:consent`, config.csrfSecret)) {
        throw Object.assign(new Error('The consent form expired. Please try again.'), { status: 403, safe: true });
      }
      const { prompt: { details: missing }, params, session: { accountId } } = details;
      let { grantId } = details;
      const grant = grantId ? await provider.Grant.find(grantId) : new provider.Grant({ accountId, clientId: params.client_id });
      if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
      if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
      if (missing.missingResourceScopes) {
        for (const [indicator, scopes] of Object.entries(missing.missingResourceScopes)) grant.addResourceScope(indicator, scopes.join(' '));
      }
      grantId = await grant.save();
      const consent = details.grantId ? {} : { grantId };
      await store.writeAudit({ realm, type: 'identity.consent.granted', subjectId: accountId, clientId: params.client_id, ip: req.ip, metadata: { scope: params.scope } });
      return provider.interactionFinished(req, res, { consent }, { mergeWithLastSubmission: true });
    } catch (error) {
      return next(error);
    }
  });

  router.post(`${base}/abort`, noStore, form, async (req, res, next) => {
    try {
      const details = await interaction(provider, req, res);
      if (!verifyCsrfToken(req.body.csrf, `${realm}:${details.uid}:consent`, config.csrfSecret)) {
        throw Object.assign(new Error('The consent form expired. Please try again.'), { status: 403, safe: true });
      }
      await store.writeAudit({ realm, type: 'identity.consent.denied', subjectId: details.session?.accountId, clientId: details.params.client_id, ip: req.ip });
      return provider.interactionFinished(req, res, { error: 'access_denied', error_description: 'The user denied the authorization request' }, { mergeWithLastSubmission: false });
    } catch (error) {
      return next(error);
    }
  });

  return router;
}
