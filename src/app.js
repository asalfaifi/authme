import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import pinoHttp from 'pino-http';
import { createDataLayer } from './db.js';
import { resolveFederatedLogin } from './authentication/federated-login.js';
import { createIdentityRuntime } from './authentication/runtime.js';
import { loadRealmJwks } from './crypto/jwks.js';
import { hashPassword } from './crypto/password.js';
import { randomToken } from './crypto/secrets.js';
import { createLogger } from './logging.js';
import { createMetrics } from './observability/metrics.js';
import { createAuditWriter } from './observability/audit-writer.js';
import { createRealmProvider } from './provider.js';
import { createAdminRouter } from './routes/admin.js';
import { createFederationRouter } from './routes/federation.js';
import { createInteractionRouter } from './routes/interactions.js';
import { createRateLimits } from './security/rate-limit.js';
import { createWebAuthn } from './security/webauthn.js';
import { renderError } from './ui/render.js';

const cssPath = fileURLToPath(new URL('./ui/authme.css', import.meta.url));
const passkeyCssPath = fileURLToPath(new URL('./ui/authme-passkeys.css', import.meta.url));
const passkeyScriptPath = fileURLToPath(new URL('./ui/authme-passkeys.js', import.meta.url));

function securityHeaders(req, res, next) {
  const authUi = req.path.startsWith('/realms/')
    && (req.path.includes('/interaction/') || /\/device(?:\/|$)/.test(req.path));
  if (authUi) {
    // oidc-provider appends an exact SHA-256 source when its device-code
    // verification_uri_complete page needs an auto-submitting inline script.
    res.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    res.set('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)');
  }
  next();
}

async function drainMaintenance(data, config, logger) {
  const batchSize = 5000;
  let deleted = 0;
  for (let batch = 0; batch < 20; batch += 1) {
    const count = await data.cleanupExpired(batchSize);
    deleted += count;
    if (count < batchSize) break;
  }
  if (deleted) logger.info({ deleted }, 'Expired OIDC artifacts removed');
  let auditDeleted = 0;
  for (let batch = 0; batch < 20; batch += 1) {
    const count = await data.cleanupAudit(config.auditRetentionDays, batchSize);
    auditDeleted += count;
    if (count < batchSize) break;
  }
  if (auditDeleted) logger.info({ deleted: auditDeleted, retentionDays: config.auditRetentionDays }, 'Expired audit events removed');
}

async function bootstrapDevelopmentUsers(config, store, logger) {
  if (!config.devMode) return;
  for (const realm of config.realms) {
    if (await store.findUserByLogin(realm, 'admin')) continue;
    const user = await store.createUser({
      realm,
      username: 'admin',
      email: `admin@${realm}.authme.local`,
      emailVerified: true,
      name: 'AuthMe Administrator',
      passwordHash: await hashPassword(config.devAdminPassword, config.passwordPepper),
      roles: ['admin'],
      groups: ['/administrators'],
    });
    await store.writeAudit({ realm, type: 'system.development_user.created', subjectId: user.id });
    logger.warn({ realm, username: user.username }, 'Development administrator created; do not use development mode in production');
  }
}

export async function createAuthMeApp(config, overrides = {}) {
  const logger = overrides.logger ?? createLogger(config.logLevel);
  const data = overrides.data ?? await createDataLayer(config);
  const store = overrides.store ?? data.store;
  const rateLimits = overrides.rateLimits ?? createRateLimits(config, logger);
  const metrics = overrides.metrics ?? createMetrics();
  const webauthn = overrides.webauthn ?? createWebAuthn(config);
  const auditWriter = overrides.auditWriter ?? createAuditWriter({
    write: (event) => store.writeAudit(event),
    maxQueue: 1_024,
    concurrency: 4,
    hooks: {
      accepted() { metrics.recordProtocolAudit('accepted'); },
      sampled() { metrics.recordProtocolAudit('sampled'); },
      dropped({ counters }) {
        metrics.recordProtocolAudit('dropped');
        if ((counters.dropped & (counters.dropped - 1)) === 0) {
          logger.warn({ dropped: counters.dropped }, 'Protocol audit queue is full; events are being shed');
        }
      },
      writeFailure({ error, counters }) {
        metrics.recordProtocolAudit('write_failure');
        if ((counters.writeFailures & (counters.writeFailures - 1)) === 0) {
          logger.error({ error, failures: counters.writeFailures }, 'Protocol audit event could not be persisted');
        }
      },
    },
  });
  let ready = false;
  let cleanupTimer;

  try {
    await store.ready();
    await rateLimits.ready();
    await bootstrapDevelopmentUsers(config, store, logger);
    const dummyPasswordHash = await hashPassword(randomToken(32), config.passwordPepper);
    const identityRuntime = overrides.identityRuntime ?? createIdentityRuntime({
      config,
      data,
      store,
      disabledPasswordHash: dummyPasswordHash,
      logger,
      fetch: overrides.fetch,
    });
    const providers = new Map();
    for (const realm of config.realms) {
      const provider = await createRealmProvider({
        realm,
        config,
        store,
        data,
        Adapter: data.adapterFor(realm),
        jwks: await loadRealmJwks(config, realm),
        logger,
        auditWriter,
      });
      providers.set(realm, provider);
    }
    await drainMaintenance(data, config, logger);
    let cleanupRunning = false;
    cleanupTimer = setInterval(() => {
      if (cleanupRunning) return;
      cleanupRunning = true;
      drainMaintenance(data, config, logger)
        .catch((error) => logger.error({ error }, 'Expired OIDC artifact cleanup failed'))
        .finally(() => { cleanupRunning = false; });
    }, 60_000).unref();

    const app = express();
    app.disable('x-powered-by');
    app.set('trust proxy', config.trustProxy ? 1 : false);
    app.use((req, res, next) => {
      if (req.originalUrl.length > 16_384) return res.status(414).end();
      return next();
    });
    app.use((req, res, next) => {
      if (!config.devMode && (req.path.startsWith('/realms/') || req.path.startsWith('/.well-known/') || req.path.startsWith('/scim/'))) {
        let requestOrigin;
        try { requestOrigin = new URL(`${req.protocol}://${req.host}`).origin; } catch { return res.status(400).end(); }
        if (requestOrigin !== config.publicUrl) {
          return res.status(421).type('application/problem+json').json({
            type: 'about:blank', title: 'Misdirected request', status: 421,
            detail: 'The request origin does not match the configured AuthMe issuer origin.',
          });
        }
      }
      return next();
    });
    app.use(pinoHttp({
      logger,
      autoLogging: { ignore: (req) => req.url.startsWith('/health/') },
      serializers: {
        req(req) {
          return {
            id: req.id,
            method: req.method,
            path: String(req.url ?? '').split('?', 1)[0],
            remoteAddress: req.remoteAddress,
          };
        },
      },
    }));
    app.use(helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
      referrerPolicy: { policy: 'no-referrer' },
      strictTransportSecurity: config.devMode ? false : { maxAge: 31_536_000, includeSubDomains: true },
    }));
    app.use(securityHeaders);
    app.use(metrics.middleware);

    app.get('/', (_req, res) => {
      res.set('Cache-Control', 'no-store').json({
        name: 'AuthMe',
        version: '0.2.0',
        issuers: config.realms.map((realm) => `${config.publicUrl}/realms/${realm}`),
        capabilities: Object.fromEntries(config.realms.map((realm) => [
          realm,
          identityRuntime.registry.describe(realm).map(({ id, kind, capabilities }) => ({ id, kind, capabilities })),
        ])),
        documentation: 'https://github.com/asalfaifi/authme',
      });
    });
    app.get('/health/live', (_req, res) => res.json({ status: 'live' }));
    app.get('/health/ready', async (_req, res) => {
      if (!ready) return res.status(503).json({ status: 'starting' });
      try {
        await store.ready();
        return res.json({ status: 'ready' });
      } catch {
        return res.status(503).json({ status: 'unavailable' });
      }
    });
    app.get('/assets/authme.css', async (_req, res, next) => {
      try {
        res.set('Cache-Control', 'public, max-age=3600').type('text/css').send(await readFile(cssPath, 'utf8'));
      } catch (error) { next(error); }
    });
    app.get('/assets/authme-passkeys.css', async (_req, res, next) => {
      try {
        res.set('Cache-Control', 'public, max-age=3600').type('text/css').send(await readFile(passkeyCssPath, 'utf8'));
      } catch (error) { next(error); }
    });
    app.get('/assets/authme-passkeys.js', async (_req, res, next) => {
      try {
        res.set('Cache-Control', 'public, max-age=3600').type('text/javascript').send(await readFile(passkeyScriptPath, 'utf8'));
      } catch (error) { next(error); }
    });
    if (identityRuntime.scimRepository) {
      app.use('/scim/v2/realms', identityRuntime.scim.implementation.createRouter({
        repository: identityRuntime.scimRepository,
        authenticate: identityRuntime.scimAuthenticate,
        realmExists: async (realm) => config.realms.includes(realm),
        baseUrl: `${config.publicUrl}/scim/v2/realms`,
        audit: async ({ realm, actor, type, resourceType, resourceId, changes, request }) => store.writeAudit({
          realm,
          type,
          subjectId: resourceId,
          ip: request.ip,
          userAgent: request.userAgent,
          metadata: { actor, resourceType, changes },
        }),
      }));
    }
    app.use('/admin', createAdminRouter({
      config, store, rateLimits, metrics, providers, data, webauthn,
      federatedIdentities: identityRuntime.federatedIdentities,
    }));

    for (const [realm, provider] of providers) {
      app.use(createFederationRouter({
        realm,
        provider,
        registry: identityRuntime.registry,
        stateStore: identityRuntime.stateStore,
        publicUrl: config.publicUrl,
        csrfSecret: config.csrfSecret,
        audit: (event) => store.writeAudit(event),
        accountResolver: async ({ extensionId, providerId, profile, identity }) => {
          const configured = extensionId === 'builtin.saml-federation'
            ? config.samlProvidersByRealm[realm]?.find((candidate) => candidate.id === providerId)
            : config.oidcProvidersByRealm[realm]?.find((candidate) => candidate.id === providerId);
          if (!configured) {
            throw Object.assign(new Error('Federation provider is not configured'), {
              code: 'AUTHME_FEDERATION_PROVIDER_NOT_FOUND', status: 404, safe: true,
            });
          }
          const issuer = extensionId === 'builtin.saml-federation'
            ? configured.idp.entityId
            : configured.issuer;
          const resolution = await resolveFederatedLogin({
            realm,
            repository: identityRuntime.federatedIdentities,
            result: {
              providerId,
              issuer,
              profile,
              identity,
              allowCreate: configured.jitProvisioning,
            },
          });
          const locked = resolution.user.lockedUntil
            && new Date(resolution.user.lockedUntil).getTime() > Date.now();
          if (locked) {
            throw Object.assign(new Error('This account is temporarily locked.'), {
              code: 'AUTHME_FEDERATED_LOGIN_DENIED', status: 403, safe: true,
            });
          }
          await store.recordLoginSuccess(realm, resolution.user.id);
          return { accountId: resolution.user.id, created: resolution.status === 'created' };
        },
      }));
      app.use(createInteractionRouter({
        realm, provider, store, config, rateLimits, dummyPasswordHash, logger, webauthn,
        identityRuntime,
      }));
      const callback = provider.callback();
      app.use(`/realms/${realm}/device`, async (req, res, next) => {
        if (req.method !== 'POST' || req.path !== '/') return next();
        try {
          await rateLimits.consumeDeviceVerification(req.ip);
          next();
        } catch (error) {
          res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
          res.set('Cache-Control', 'no-store');
          res.status(429).send(renderError({
            realm,
            title: 'Too many verification attempts',
            message: 'Wait a moment before entering another device code.',
          }));
        }
      });
      if (config.enableDynamicRegistration) {
        app.use(`/realms/${realm}/clients-registrations/openid-connect`, async (req, res, next) => {
          if (req.method !== 'POST' || req.path !== '/') return next();
          try {
            await rateLimits.consumeRegistration(req.ip);
            next();
          } catch (error) {
            res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
            res.status(429).json({ error: 'slow_down', error_description: 'Too many client registration requests' });
          }
        });
      }
      app.use(`/realms/${realm}`, callback);
      app.use(`/.well-known/oauth-authorization-server/realms/${realm}`, (req, res) => {
        req.url = '/.well-known/oauth-authorization-server';
        // oidc-provider derives advertised endpoint mount paths from originalUrl.
        // Present the equivalent issuer-mounted metadata request so RFC 8414
        // metadata advertises /realms/{realm}/protocol/... endpoints.
        req.originalUrl = `/realms/${realm}${req.url}`;
        callback(req, res);
      });
    }

    app.use('/admin', (_req, res) => res.status(404).type('application/problem+json').json({
      type: 'about:blank', title: 'Not found', status: 404,
    }));
    app.use((req, res) => {
      res.status(404).send(renderError({ title: 'Not found', message: 'The requested AuthMe endpoint does not exist.' }));
    });
    app.use((error, req, res, _next) => {
      const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
      req.log?.[status >= 500 ? 'error' : 'warn']({ err: error }, 'Request failed');
      if (res.headersSent) return res.end();
      if (req.originalUrl.startsWith('/admin/')) {
        return res.status(status).type('application/problem+json').json({
          type: 'about:blank',
          title: status >= 500 ? 'Internal server error' : 'Request failed',
          status,
          detail: error.safe ? error.message : undefined,
        });
      }
      return res.status(status).send(renderError({
        realm: req.params?.realm,
        title: status >= 500 ? 'Something went wrong' : 'Request failed',
        message: error.safe ? error.message : 'The request could not be completed safely.',
      }));
    });

    ready = true;
    return {
      app,
      config,
      data,
      logger,
      metrics,
      providers,
      auditWriter,
      identityRuntime,
      rateLimits,
      store,
      async close() {
        ready = false;
        clearInterval(cleanupTimer);
        await auditWriter.close();
        await rateLimits.close();
        await data.close();
        metrics.clear();
      },
    };
  } catch (error) {
    clearInterval(cleanupTimer);
    await auditWriter.close().catch(() => {});
    await rateLimits.close().catch(() => {});
    await data.close().catch(() => {});
    throw error;
  }
}
