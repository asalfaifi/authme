import { randomBytes } from 'node:crypto';
import { Router, urlencoded } from 'express';
import { SAML_IDP_BRIDGE_CLIENT_ID, renderSamlPostForm } from '../federation/saml-idp.js';

const statePattern = /^[A-Za-z0-9_-]{43}$/u;
const codePattern = /^[A-Za-z0-9_-]{20,256}$/u;
const spIdPattern = /^[a-z][a-z0-9-]{1,31}$/u;

function noStore(_req, res, next) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
}

function exactFields(value, required, optional = []) {
  if (!value || Array.isArray(value) || typeof value !== 'object') return false;
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key) && typeof value[key] === 'string')
    && keys.every((key) => allowed.has(key) && typeof value[key] === 'string');
}

function routeError(message, status = 400, code = 'AUTHME_SAML_IDP_REQUEST_INVALID') {
  return Object.assign(new Error(message), { status, code, safe: true });
}

function auditEvent(req, realm, type, extra = {}) {
  return {
    realm,
    type,
    clientId: extra.clientId,
    subjectId: extra.subjectId,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    metadata: extra.metadata,
  };
}

export function createSamlIdentityProviderRouter({ realm, identityProvider, provider, store, audit }) {
  if (typeof realm !== 'string' || !/^[a-z][a-z0-9-]{0,62}$/u.test(realm)) throw new TypeError('SAML IdP realm is invalid');
  if (!identityProvider?.metadata || !identityProvider?.receiveRedirect || !identityProvider?.complete) {
    throw new TypeError('SAML identity provider service is required');
  }
  if (!provider?.AuthorizationCode?.find || !provider?.Session?.get) throw new TypeError('OIDC provider is required');
  if (!store?.findUserById) throw new TypeError('Account store is required');
  if (typeof audit !== 'function') throw new TypeError('SAML IdP audit hook is required');

  const router = Router();
  const base = `/realms/${realm}/protocol/saml`;
  const form = urlencoded({ extended: false, limit: '1mb', parameterLimit: 2 });

  router.get(`${base}/descriptor`, async (_req, res, next) => {
    try {
      const metadata = identityProvider.metadata();
      return res.set('Cache-Control', 'public, max-age=300')
        .type('application/samlmetadata+xml')
        .send(metadata);
    } catch (error) {
      return next(error);
    }
  });

  router.get(`${base}/clients/:spId/login`, noStore, async (req, res, next) => {
    try {
      if (!spIdPattern.test(req.params.spId) || Object.keys(req.query).length !== 0) {
        throw routeError('IdP-initiated SAML request is malformed');
      }
      const started = await identityProvider.initiate(req.params.spId);
      await audit(auditEvent(req, realm, 'identity.saml_idp.initiated', {
        metadata: { serviceProviderId: req.params.spId, initiatedBy: 'idp' },
      }));
      return res.redirect(303, started.authorizationUrl);
    } catch (error) {
      return next(error);
    }
  });

  router.get(`${base}`, noStore, async (req, res, next) => {
    try {
      const separator = req.originalUrl.indexOf('?');
      if (separator < 0) throw routeError('SAML Redirect request is missing');
      const started = await identityProvider.receiveRedirect(req.originalUrl.slice(separator + 1));
      await audit(auditEvent(req, realm, started.kind === 'logout'
        ? 'identity.saml_idp.logout_received' : 'identity.saml_idp.authn_received', {
        metadata: { binding: 'redirect' },
      }));
      if (started.kind === 'logout') {
        const context = await identityProvider.logoutContext(started.state);
        const session = await provider.Session.get({ req, res, secure: req.secure });
        if (session.accountId && session.accountId !== context.accountId) {
          throw routeError('SAML logout does not match the active AuthMe session', 403, 'AUTHME_SAML_IDP_SESSION_MISMATCH');
        }
        return res.redirect(303, started.logoutUrl);
      }
      return res.redirect(303, started.authorizationUrl);
    } catch (error) {
      return next(error);
    }
  });

  router.post(`${base}`, noStore, form, async (req, res, next) => {
    try {
      if (!req.is('application/x-www-form-urlencoded')
        || !exactFields(req.body, ['SAMLRequest'], ['RelayState'])) {
        throw routeError('SAML POST request body is malformed');
      }
      const started = await identityProvider.receivePost({
        SAMLRequest: req.body.SAMLRequest,
        RelayState: req.body.RelayState,
      });
      await audit(auditEvent(req, realm, 'identity.saml_idp.authn_received', {
        metadata: { binding: 'post' },
      }));
      return res.redirect(303, started.authorizationUrl);
    } catch (error) {
      return next(error);
    }
  });

  router.get(`${base}/continue`, noStore, async (req, res, next) => {
    try {
      if (!exactFields(req.query, ['code', 'state'], ['iss'])
        || !codePattern.test(req.query.code) || !statePattern.test(req.query.state)
        || (req.query.iss !== undefined && req.query.iss !== provider.issuer)) {
        throw routeError('SAML authentication continuation is malformed');
      }
      const context = await identityProvider.authenticationContext(req.query.state);
      const code = await provider.AuthorizationCode.find(req.query.code);
      if (!code || !code.isValid
        || code.clientId !== SAML_IDP_BRIDGE_CLIENT_ID
        || code.redirectUri !== context.continuationUrl
        || code.nonce !== context.nonce
        || code.codeChallenge !== context.codeChallenge
        || code.codeChallengeMethod !== 'S256'
        || typeof code.accountId !== 'string') {
        throw routeError('SAML authentication continuation is not bound to this login', 400, 'AUTHME_SAML_IDP_CONTINUATION_INVALID');
      }
      await code.consume();
      const user = await store.findUserById(realm, code.accountId);
      const completed = await identityProvider.complete({
        state: req.query.state,
        user,
        authentication: { acr: code.acr, amr: code.amr, authTime: code.authTime },
      });
      await audit(auditEvent(req, realm, 'identity.saml_idp.login_succeeded', {
        subjectId: code.accountId,
        metadata: {
          requestId: completed.requestId,
          responseId: completed.responseId,
        },
      }));
      const nonce = randomBytes(24).toString('base64url');
      res.set('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; form-action ${new URL(completed.acsUrl).origin}; base-uri 'none'; frame-ancestors 'none'`);
      res.set('Referrer-Policy', 'no-referrer');
      return res.type('html').send(renderSamlPostForm({
        acsUrl: completed.acsUrl,
        samlResponse: completed.samlResponse,
        relayState: completed.relayState,
        nonce,
      }));
    } catch (error) {
      return next(error);
    }
  });

  router.get(`${base}/logout/continue`, noStore, async (req, res, next) => {
    try {
      if (!exactFields(req.query, ['state']) || !statePattern.test(req.query.state)) {
        throw routeError('SAML logout continuation is malformed');
      }
      const completed = await identityProvider.completeLogout(req.query.state);
      await audit(auditEvent(req, realm, 'identity.saml_idp.logout_succeeded'));
      return res.redirect(303, completed.redirectUrl);
    } catch (error) {
      return next(error);
    }
  });

  return router;
}
