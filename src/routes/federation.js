import { Router, urlencoded } from 'express';

import { createCsrfToken, verifyCsrfToken } from '../crypto/csrf.js';

const extensionIdPattern = /^[a-z][a-z0-9.-]{1,63}$/;
const providerIdPattern = /^[a-z][a-z0-9-]{1,31}$/;
const interactionUidPattern = /^[A-Za-z0-9_-]{1,256}$/;
const handlePattern = /^[A-Za-z0-9_-]{32,256}$/;
const accountIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const amrPattern = /^[A-Za-z0-9._~:+/-]{1,64}$/;
const oidcCallbackFields = new Set(['code', 'error', 'error_description', 'error_uri', 'iss', 'state']);
const federationAcr = 'urn:authme:loa:federated';

function requestError(message, status = 400, code = 'AUTHME_FEDERATION_REQUEST_INVALID') {
  return Object.assign(new Error(message), { code, status, safe: true });
}

function noStore(_req, res, next) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
}

function exactObject(value, fields) {
  if (!value || Array.isArray(value) || typeof value !== 'object') return false;
  const keys = Object.keys(value);
  return keys.length === fields.length
    && fields.every((field) => keys.includes(field) && typeof value[field] === 'string');
}

function exactAllowedObject(value, fields) {
  if (!value || Array.isArray(value) || typeof value !== 'object') return false;
  return Object.entries(value).every(([key, field]) => fields.has(key) && typeof field === 'string');
}

function loopback(hostname) {
  return ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(hostname);
}

function publicOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Federation publicUrl must be an absolute URL'); }
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback(url.hostname)))
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('Federation publicUrl must be an HTTPS origin (or an HTTP loopback origin)');
  }
  return url.origin;
}

function safeRedirect(value, allowLoopbackHttp) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16_384) {
    throw requestError('The upstream sign-in redirect is invalid', 502, 'AUTHME_FEDERATION_REDIRECT_INVALID');
  }
  let url;
  try { url = new URL(value); } catch {
    throw requestError('The upstream sign-in redirect is invalid', 502, 'AUTHME_FEDERATION_REDIRECT_INVALID');
  }
  if ((url.protocol !== 'https:' && !(allowLoopbackHttp && url.protocol === 'http:' && loopback(url.hostname)))
    || url.username || url.password || url.hash) {
    throw requestError('The upstream sign-in redirect is invalid', 502, 'AUTHME_FEDERATION_REDIRECT_INVALID');
  }
  return url.href;
}

function csrfSubject({ realm, interactionUid, extensionId, providerId }) {
  const binding = Buffer.from(JSON.stringify([realm, interactionUid, extensionId, providerId])).toString('base64url');
  return `federation-${binding}`;
}

export function createFederationInitiationCsrfToken(input, secret) {
  return createCsrfToken(csrfSubject(input), secret);
}

function interactionDetails(provider, req, res, expectedUid) {
  return provider.interactionDetails(req, res).then((details) => {
    if (!details || details.uid !== expectedUid || details.prompt?.name !== 'login') {
      throw requestError('Interaction state does not match this federation request');
    }
    return details;
  });
}

function extensionFor(registry, realm, extensionId, providerId, capability) {
  if (!extensionIdPattern.test(extensionId) || !providerIdPattern.test(providerId)) {
    throw requestError('Federation provider not found', 404, 'AUTHME_FEDERATION_PROVIDER_NOT_FOUND');
  }
  const entry = registry.get(extensionId, 'federation');
  const enabled = entry && (entry.implementation.enabledFor?.(realm) ?? true);
  const providers = enabled && entry.implementation.providersFor?.(realm);
  const providerExists = Array.isArray(providers)
    && providers.some((candidate) => candidate?.id === providerId);
  if (!entry || !enabled || !providerExists || !entry.manifest.capabilities.includes(capability)) {
    throw requestError('Federation provider not found', 404, 'AUTHME_FEDERATION_PROVIDER_NOT_FOUND');
  }
  return entry;
}

function normalizedResult(value, providerId) {
  if (!value || Array.isArray(value) || typeof value !== 'object'
    || value.providerId !== providerId
    || !interactionUidPattern.test(value.interactionUid ?? '')
    || !value.profile || Array.isArray(value.profile) || typeof value.profile !== 'object') {
    throw requestError('The federation response did not match this provider', 400, 'AUTHME_FEDERATION_RESPONSE_INVALID');
  }
  const suppliedAmr = value.amr ?? [];
  if (!Array.isArray(suppliedAmr) || suppliedAmr.length > 16
    || suppliedAmr.some((item) => typeof item !== 'string' || !amrPattern.test(item))) {
    throw requestError('The federation response contained invalid authentication methods', 400, 'AUTHME_FEDERATION_RESPONSE_INVALID');
  }
  if (value.acr !== undefined
    && (typeof value.acr !== 'string' || value.acr.length === 0 || value.acr.length > 256 || /[\u0000-\u001f\u007f]/.test(value.acr))) {
    throw requestError('The federation response contained an invalid assurance level', 400, 'AUTHME_FEDERATION_RESPONSE_INVALID');
  }
  return {
    interactionUid: value.interactionUid,
    providerId,
    profile: value.profile,
    identity: value.identity,
    amr: [...new Set(['federated', ...suppliedAmr])],
    acr: value.acr ?? federationAcr,
  };
}

function completionPayload(value, { realm, interactionUid }) {
  if (!value || Array.isArray(value) || typeof value !== 'object'
    || value.kind !== 'federation-completion'
    || value.realm !== realm
    || value.interactionUid !== interactionUid
    || !extensionIdPattern.test(value.extensionId ?? '')
    || !providerIdPattern.test(value.providerId ?? '')
    || !accountIdPattern.test(value.accountId ?? '')) {
    throw requestError('Federation completion is invalid or expired', 400, 'AUTHME_FEDERATION_COMPLETION_INVALID');
  }
  const authentication = normalizedResult({
    interactionUid: value.interactionUid,
    providerId: value.providerId,
    profile: {},
    amr: value.amr,
    acr: value.acr,
  }, value.providerId);
  return {
    extensionId: value.extensionId,
    providerId: value.providerId,
    accountId: value.accountId,
    amr: authentication.amr,
    acr: authentication.acr,
  };
}

function callbackUrl(origin, realm, extensionId, providerId) {
  return `${origin}/realms/${realm}/federation/${extensionId}/${providerId}/callback`;
}

function completionUrl(realm, interactionUid, handle) {
  return `/realms/${realm}/interaction/${interactionUid}/federation/complete?${new URLSearchParams({ handle })}`;
}

function auditEvent(req, realm, type, extensionId, providerId, extra = {}) {
  return {
    realm,
    type,
    clientId: extra.clientId,
    subjectId: extra.subjectId,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    metadata: { extensionId, providerId, ...extra.metadata },
  };
}

export function createFederationRouter({
  realm,
  provider,
  registry,
  stateStore,
  accountResolver,
  audit,
  publicUrl,
  csrfSecret,
  completionTtlSeconds = 120,
  maxSamlPostBytes = 1_500_000,
  maxOidcCallbackBytes = 16_384,
}) {
  if (typeof realm !== 'string' || !/^[a-z][a-z0-9-]{0,62}$/.test(realm)) throw new TypeError('Federation realm is invalid');
  if (!provider?.interactionDetails || !provider?.interactionFinished) throw new TypeError('Federation OIDC provider is required');
  if (!registry?.get) throw new TypeError('Federation extension registry is required');
  if (!stateStore?.issue || !stateStore?.consume) throw new TypeError('Federation one-use state store is required');
  if (typeof accountResolver !== 'function') throw new TypeError('Federation accountResolver is required');
  if (typeof audit !== 'function') throw new TypeError('Federation audit hook is required');
  if (typeof csrfSecret !== 'string' || csrfSecret.length === 0) throw new TypeError('Federation csrfSecret is required');
  if (!Number.isSafeInteger(completionTtlSeconds) || completionTtlSeconds < 30 || completionTtlSeconds > 600) {
    throw new TypeError('Federation completionTtlSeconds must be between 30 and 600');
  }
  if (!Number.isSafeInteger(maxSamlPostBytes) || maxSamlPostBytes < 1024 || maxSamlPostBytes > 4_000_000) {
    throw new TypeError('Federation maxSamlPostBytes must be between 1024 and 4000000');
  }
  if (!Number.isSafeInteger(maxOidcCallbackBytes) || maxOidcCallbackBytes < 1024 || maxOidcCallbackBytes > 65_536) {
    throw new TypeError('Federation maxOidcCallbackBytes must be between 1024 and 65536');
  }

  const origin = publicOrigin(publicUrl);
  const router = Router();
  const prefix = `/realms/${realm}`;
  const initiationForm = urlencoded({ extended: false, limit: '4kb', parameterLimit: 2 });
  const samlForm = urlencoded({ extended: false, limit: maxSamlPostBytes, parameterLimit: 3 });

  async function completeCallback(req, res, extensionId, providerId, result) {
    const federation = normalizedResult(result, providerId);
    const resolved = await accountResolver({
      realm,
      extensionId,
      providerId,
      profile: federation.profile,
      identity: federation.identity,
    });
    if (!resolved || Array.isArray(resolved) || typeof resolved !== 'object'
      || !accountIdPattern.test(resolved.accountId ?? '')) {
      throw requestError('The federated identity could not be linked to an account', 500, 'AUTHME_FEDERATION_RESOLUTION_INVALID');
    }
    const payload = {
      kind: 'federation-completion',
      realm,
      extensionId,
      providerId,
      interactionUid: federation.interactionUid,
      accountId: resolved.accountId,
      amr: federation.amr,
      acr: federation.acr,
    };
    const handle = await stateStore.issue(realm, payload, completionTtlSeconds);
    if (!handlePattern.test(handle ?? '')) {
      throw requestError('The federation completion handle could not be created', 500, 'AUTHME_FEDERATION_STATE_INVALID');
    }
    await audit(auditEvent(req, realm, 'identity.federation.resolved', extensionId, providerId, {
      subjectId: resolved.accountId,
      metadata: { created: resolved.created === true },
    }));
    res.set('Referrer-Policy', 'no-referrer');
    return res.redirect(303, completionUrl(realm, federation.interactionUid, handle));
  }

  async function callbackFailure(req, extensionId, providerId, error) {
    const code = typeof error?.code === 'string' && /^[A-Z0-9_.-]{1,100}$/i.test(error.code)
      ? error.code : 'AUTHME_FEDERATION_CALLBACK_FAILED';
    try {
      await audit(auditEvent(req, realm, 'identity.federation.failed', extensionId, providerId, {
        metadata: { code },
      }));
    } catch {
      // Preserve the original protocol error. Failure audit sinks must not alter the response.
    }
  }

  router.get(`${prefix}/federation/:extensionId/:providerId/metadata`, async (req, res, next) => {
    try {
      const { extensionId, providerId } = req.params;
      const entry = extensionFor(registry, realm, extensionId, providerId, 'saml2');
      if (typeof entry.implementation.metadataFor !== 'function') {
        throw requestError('Federation provider not found', 404, 'AUTHME_FEDERATION_PROVIDER_NOT_FOUND');
      }
      const metadata = await entry.implementation.metadataFor(realm, providerId);
      if (typeof metadata !== 'string' || metadata.length === 0 || metadata.length > 1_000_000) {
        throw requestError('SAML metadata is unavailable', 502, 'AUTHME_FEDERATION_METADATA_INVALID');
      }
      return res.type('application/samlmetadata+xml').send(metadata);
    } catch (error) {
      return next(error);
    }
  });

  router.post(`${prefix}/interaction/:uid/federation/:extensionId/:providerId`, noStore, initiationForm, async (req, res, next) => {
    try {
      const { uid, extensionId, providerId } = req.params;
      if (!interactionUidPattern.test(uid) || !req.is('application/x-www-form-urlencoded')
        || !exactObject(req.body, ['csrf'])) {
        throw requestError('Federation initiation request is malformed');
      }
      const details = await interactionDetails(provider, req, res, uid);
      if (!verifyCsrfToken(req.body.csrf, csrfSubject({
        realm, interactionUid: uid, extensionId, providerId,
      }), csrfSecret)) {
        throw requestError('The federation sign-in request expired. Please try again.', 403, 'AUTHME_FEDERATION_CSRF_INVALID');
      }
      const entry = extensionFor(registry, realm, extensionId, providerId,
        extensionId === 'builtin.saml-federation' ? 'saml2' : 'oidc');
      const target = callbackUrl(origin, realm, extensionId, providerId);
      const initiated = await entry.implementation.initiate({
        realm,
        providerId,
        interactionUid: uid,
        callbackUrl: target,
      });
      const redirectUrl = safeRedirect(initiated?.redirectUrl, origin.startsWith('http:'));
      await audit(auditEvent(req, realm, 'identity.federation.initiated', extensionId, providerId, {
        clientId: details.params?.client_id,
      }));
      return res.redirect(303, redirectUrl);
    } catch (error) {
      return next(error);
    }
  });

  router.post(`${prefix}/federation/:extensionId/:providerId/acs`, noStore, samlForm, async (req, res, next) => {
    const { extensionId, providerId } = req.params;
    try {
      if (!req.is('application/x-www-form-urlencoded')
        || !exactObject(req.body, ['SAMLResponse', 'RelayState'])
        || req.body.SAMLResponse.length === 0 || req.body.RelayState.length === 0) {
        throw requestError('SAML callback body is malformed');
      }
      const entry = extensionFor(registry, realm, extensionId, providerId, 'saml2');
      const result = await entry.implementation.consume({
        realm,
        providerId,
        params: { SAMLResponse: req.body.SAMLResponse, RelayState: req.body.RelayState },
      });
      return await completeCallback(req, res, extensionId, providerId, result);
    } catch (error) {
      await callbackFailure(req, extensionId, providerId, error);
      return next(error);
    }
  });

  router.get(`${prefix}/federation/:extensionId/:providerId/callback`, noStore, async (req, res, next) => {
    const { extensionId, providerId } = req.params;
    try {
      const hasCode = Object.hasOwn(req.query, 'code');
      const hasError = Object.hasOwn(req.query, 'error');
      if (Buffer.byteLength(req.originalUrl) > maxOidcCallbackBytes
        || !exactAllowedObject(req.query, oidcCallbackFields)
        || typeof req.query.state !== 'string'
        || !handlePattern.test(req.query.state)
        || hasCode === hasError
        || (hasCode && (!req.query.code || Object.hasOwn(req.query, 'error_description')))
        || (hasCode && Object.hasOwn(req.query, 'error_uri'))
        || (hasError && !req.query.error)
        || Object.values(req.query).some((value) => value.length > 8_192)) {
        throw requestError('OIDC callback query is malformed');
      }
      const entry = extensionFor(registry, realm, extensionId, providerId, 'oidc');
      const target = callbackUrl(origin, realm, extensionId, providerId);
      const result = await entry.implementation.consume({
        realm,
        providerId,
        callbackUrl: target,
        params: { ...req.query },
      });
      return await completeCallback(req, res, extensionId, providerId, result);
    } catch (error) {
      await callbackFailure(req, extensionId, providerId, error);
      return next(error);
    }
  });

  router.get(`${prefix}/interaction/:uid/federation/complete`, noStore, async (req, res, next) => {
    try {
      const { uid } = req.params;
      if (!interactionUidPattern.test(uid)
        || !exactObject(req.query, ['handle'])
        || !handlePattern.test(req.query.handle)) {
        throw requestError('Federation completion request is malformed');
      }
      const details = await interactionDetails(provider, req, res, uid);
      const state = await stateStore.consume(realm, req.query.handle);
      const login = completionPayload(state, {
        realm,
        interactionUid: uid,
      });
      const { extensionId, providerId } = login;
      extensionFor(registry, realm, extensionId, providerId,
        extensionId === 'builtin.saml-federation' ? 'saml2' : 'oidc');
      await audit(auditEvent(req, realm, 'identity.federation.login_succeeded', extensionId, providerId, {
        clientId: details.params?.client_id,
        subjectId: login.accountId,
        metadata: { amr: login.amr, acr: login.acr },
      }));
      res.set('Referrer-Policy', 'no-referrer');
      return provider.interactionFinished(req, res, {
        login: {
          accountId: login.accountId,
          acr: login.acr,
          amr: login.amr,
          remember: true,
        },
      }, { mergeWithLastSubmission: false });
    } catch (error) {
      return next(error);
    }
  });

  return router;
}
