import { Router, json } from 'express';
import { z } from 'zod';
import { authenticationFlowConfigurationError } from '../authentication/flow-policy.js';
import { createRecoveryCodes, createTotp, totpStep } from '../crypto/mfa.js';
import { hashPassword } from '../crypto/password.js';
import { decryptSecret, encryptSecret, keyedDigest, randomToken, safeEqual } from '../crypto/secrets.js';
import {
  ACCOUNT_CONSOLE_CLIENT_ID,
  ADMIN_CONSOLE_CLIENT_ID,
  configuredClientsForRealm,
  validateClientSecurity,
} from '../provider.js';
import { SAML_IDP_BRIDGE_CLIENT_ID } from '../federation/saml-idp.js';
import { publicUser } from '../repositories/identity-store.js';
import { hasAdminPermission } from '../security/admin-permissions.js';
import { createWebAuthn } from '../security/webauthn.js';
import { createAdminConsole } from './admin-console.js';

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
const RECENT_ADMIN_AUTHENTICATION_MS = 15 * 60 * 1000;
const managementId = z.uuid();
const policyName = z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9:._/-]+$/);
const attributes = z.record(z.string().min(1).max(128), z.union([
  z.string().max(4096), z.number().finite(), z.boolean(), z.array(z.string().max(4096)).max(100),
])).default({});
const realmPatchSchema = z.object({
  displayName: z.string().trim().min(1).max(255).optional(),
  enabled: z.boolean().optional(),
  settings: attributes.optional(),
}).strict().refine((value) => Object.keys(value).length > 0, 'at least one field is required');
const roleSchema = z.object({
  description: z.string().max(4096).optional().default(''),
  composites: z.array(policyName).max(200).optional().default([]),
  attributes: attributes.optional(),
}).strict();
const groupCreateSchema = z.object({
  name: policyName,
  parentId: managementId.nullable().optional().default(null),
  roles: z.array(policyName).max(200).optional().default([]),
  attributes: attributes.optional(),
}).strict();
const groupUpdateSchema = groupCreateSchema.partial().refine((value) => Object.keys(value).length > 0, 'at least one field is required');
const clientScopeCreateSchema = z.object({
  name: policyName,
  description: z.string().max(4096).optional().default(''),
  protocol: z.literal('openid-connect').optional().default('openid-connect'),
  attributes: attributes.optional(),
}).strict();
const clientScopeUpdateSchema = clientScopeCreateSchema.omit({ protocol: true }).partial().refine((value) => Object.keys(value).length > 0, 'at least one field is required');
const claimMapperConfig = z.record(z.string().min(1).max(128), z.unknown());
const claimMapperCreateSchema = z.object({
  ownerType: z.enum(['client', 'client-scope']),
  ownerId: z.string().min(1).max(255),
  name: policyName,
  mapperType: z.enum(['user-attribute', 'hardcoded', 'realm-roles', 'client-roles', 'groups', 'organization']),
  config: claimMapperConfig.refine((value) => typeof value.claim === 'string' && /^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$/.test(value.claim), 'config.claim must be a safe claim name'),
}).strict();
const claimMapperUpdateSchema = claimMapperCreateSchema.omit({ ownerType: true, ownerId: true }).partial().refine((value) => Object.keys(value).length > 0, 'at least one field is required');
const flowStep = z.object({
  type: z.enum(['password', 'totp', 'passkey', 'federated']),
  requirement: z.enum(['required', 'alternative', 'conditional']),
}).strict();
const flowSteps = z.array(flowStep).min(1).max(16).superRefine((value, context) => {
  const message = authenticationFlowConfigurationError(value);
  if (message) context.addIssue({ code: z.ZodIssueCode.custom, message });
});
const authenticationFlowCreateSchema = z.object({
  alias: policyName,
  description: z.string().max(4096).optional().default(''),
  enabled: z.boolean().optional().default(true),
  priority: z.number().int().min(0).max(100_000).optional().default(100),
  clientIds: z.array(identifier).max(200).optional().default([]),
  acr: z.string().trim().min(1).max(255),
  maxAgeSeconds: z.number().int().min(1).max(2_592_000).nullable().optional().default(null),
  steps: flowSteps,
}).strict();
const authenticationFlowUpdateSchema = authenticationFlowCreateSchema.partial().refine((value) => Object.keys(value).length > 0, 'at least one field is required');
const domainSchema = z.object({
  domain: z.string().trim().toLowerCase().min(1).max(253).regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/),
  verified: z.boolean().optional().default(false),
}).strict();
const organizationCreateSchema = z.object({
  name: z.string().trim().min(1).max(255),
  alias: policyName,
  enabled: z.boolean().optional().default(true),
  domains: z.array(domainSchema).max(100).optional().default([]),
  identityProviderIds: z.array(federatedProviderId).max(100).optional().default([]),
  attributes: attributes.optional(),
}).strict();
const organizationUpdateSchema = organizationCreateSchema.partial().refine((value) => Object.keys(value).length > 0, 'at least one field is required');
const organizationMembershipSchema = z.object({ roles: z.array(policyName).max(100).optional().default([]) }).strict();
const organizationInvitationSchema = z.object({
  email: z.email().max(254),
  roles: z.array(policyName).max(100).optional().default([]),
  expiresInSeconds: z.number().int().min(300).max(604_800).optional().default(86_400),
}).strict();
const clientMetadataSchema = z.record(z.string().min(1).max(128), z.unknown())
  .refine((value) => typeof value.client_id === 'string' && /^[a-zA-Z0-9._-]{1,128}$/.test(value.client_id), 'client_id is required and must be safe');

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
    actorId: req.authmeAdmin?.user?.id,
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

function normalizedAdminPath(path) {
  return path.length > 1 ? path.replace(/\/+$/u, '') : path;
}

function requestedAdminRealm(path) {
  const match = /^\/v1\/realms\/([^/]+)(?:\/|$)/iu.exec(path);
  if (!match) return null;
  try { return decodeURIComponent(match[1]); } catch { return ''; }
}

function hasRecentAdminAuthentication(authentication, now = Date.now()) {
  const authenticatedAt = new Date(authentication?.session?.createdAt).getTime();
  const age = now - authenticatedAt;
  return Number.isFinite(authenticatedAt) && age >= -30_000 && age <= RECENT_ADMIN_AUTHENTICATION_MS;
}

function publicClient(metadata, { managed = false } = {}) {
  const secretFields = new Set([
    'client_secret', 'registration_access_token', 'registration_client_uri',
    'tls_client_auth_subject_dn',
  ]);
  return {
    ...Object.fromEntries(Object.entries(metadata).filter(([name]) => !secretFields.has(name))),
    managed,
    hasClientSecret: Boolean(metadata.client_secret),
  };
}

function managementFailure(error, res, next) {
  if (['23505', 'ROLE_COMPOSITE_NOT_FOUND', 'GROUP_EXISTS', 'GROUP_CYCLE', 'GROUP_NOT_EMPTY',
    'CLIENT_SCOPE_EXISTS', 'CLAIM_MAPPER_EXISTS', 'AUTH_FLOW_EXISTS', 'ORGANIZATION_EXISTS',
    'ORGANIZATION_DOMAIN_EXISTS'].includes(error?.code)) {
    return problem(res, 409, 'Configuration conflict', error.message);
  }
  if (['23503', 'GROUP_PARENT_NOT_FOUND'].includes(error?.code)) {
    return problem(res, 400, 'Invalid relationship', error.message);
  }
  return next(error);
}

function requiredAdminPermission(req) {
  const path = normalizedAdminPath(req.path);
  if (/^\/metrics$/iu.test(path)) return 'metrics.read';
  if (/^\/v1\/realms$/iu.test(path)) return 'realms.read';
  if (/^\/v1\/realms\/[^/]+$/iu.test(path)) return req.method === 'GET' ? 'realms.read' : 'realms.manage';
  if (/^\/v1\/realms\/[^/]+\/configuration$/iu.test(path)) return 'configuration.read';
  if (/^\/v1\/realms\/[^/]+\/clients\/[^/]+\/client-scopes(?:\/[^/]+)?$/iu.test(path)) return req.method === 'GET' ? 'configuration.read' : 'client-scopes.manage';
  if (/^\/v1\/realms\/[^/]+\/clients(?:\/[^/]+)?$/iu.test(path)) return req.method === 'GET' ? 'clients.read' : 'clients.manage';
  if (/^\/v1\/realms\/[^/]+\/roles(?:\/[^/]+)?$/iu.test(path)) return req.method === 'GET' ? 'configuration.read' : 'roles.manage';
  if (/^\/v1\/realms\/[^/]+\/groups(?:\/[^/]+)?$/iu.test(path)) return req.method === 'GET' ? 'configuration.read' : 'groups.manage';
  if (/^\/v1\/realms\/[^/]+\/(?:client-scopes|claim-mappers)(?:\/.*)?$/iu.test(path)) return req.method === 'GET' ? 'configuration.read' : 'client-scopes.manage';
  if (/^\/v1\/realms\/[^/]+\/authentication-flows(?:\/[^/]+)?$/iu.test(path)) return req.method === 'GET' ? 'configuration.read' : 'authentication-flows.manage';
  if (/^\/v1\/realms\/[^/]+\/organizations(?:\/.*)?$/iu.test(path)) return req.method === 'GET' ? 'configuration.read' : 'organizations.manage';
  if (/^\/v1\/realms\/[^/]+\/signing-keys(?:\/.*)?$/iu.test(path)) return req.method === 'GET' ? 'configuration.read' : 'signing-keys.manage';
  if (/^\/v1\/realms\/[^/]+\/audit$/iu.test(path)) return 'audit.read';
  if (/^\/v1\/realms\/[^/]+\/client-registration-tokens$/iu.test(path)) return 'clients.register';
  if (/^\/v1\/realms\/[^/]+\/users\/[^/]+\/federated-identities$/iu.test(path)) {
    return req.method === 'GET' ? 'users.read' : 'federation.manage';
  }
  if (/^\/v1\/realms\/[^/]+\/users\/[^/]+\/(?:passkeys(?:\/.*)?|mfa\/totp(?:\/confirm)?|password|unlock)$/iu.test(path)) {
    return 'credentials.manage';
  }
  if (/^\/v1\/realms\/[^/]+\/users\/[^/]+\/sessions\/revoke$/iu.test(path)) return 'sessions.revoke';
  if (/^\/v1\/realms\/[^/]+\/users\/[^/]+$/iu.test(path) && req.method === 'DELETE') return 'users.delete';
  if (/^\/v1\/realms\/[^/]+\/users(?:\/[^/]+)?$/iu.test(path)) {
    return req.method === 'GET' ? 'users.read' : 'users.write';
  }
  return null;
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
  jwksByRealm,
  fetch,
  extensions,
  management,
  signingKeyManagers,
}) {
  const passkeys = webauthn ?? createWebAuthn(config);
  const router = Router();
  const adminConsole = createAdminConsole({ config, store, rateLimits, jwksByRealm, fetch });

  async function clientExists(realm, clientId) {
    return Boolean(await providers.get(realm)?.Client.find(clientId));
  }

  async function synchronizeProviderMetadata(realm) {
    await providers.get(realm)?.authmeManagementMetadata?.synchronize();
  }

  async function validateUserRelationships(realm, input) {
    if (input.roles) {
      const roles = new Set((await management.listRoles(realm)).map((item) => item.name));
      const unknown = input.roles.find((name) => !roles.has(name));
      if (unknown) return `Role ${unknown} is not defined in this realm.`;
    }
    if (input.groups) {
      const groups = new Set((await management.listGroups(realm)).map((item) => item.path));
      const unknown = input.groups.find((path) => !groups.has(path));
      if (unknown) return `Group ${unknown} is not defined in this realm.`;
    }
    return undefined;
  }

  async function mutateRealmUsers(realm, mutation) {
    for (let offset = 0; ; offset += 200) {
      const users = await store.listUsers(realm, { limit: 200, offset });
      for (const user of users) {
        const patch = mutation(user);
        if (!patch) continue;
        await data.mutateAccountSecurity(realm, user.id, (transactionalStore) => (
          transactionalStore.updateUser(realm, user.id, patch)
        ));
      }
      if (users.length < 200) break;
    }
  }

  async function rewriteUserGroupPaths(realm, mappings, revokePaths = new Set()) {
    await mutateRealmUsers(realm, (user) => {
      const groups = user.groups.flatMap((path) => {
        if (!mappings.has(path)) return [path];
        const replacement = mappings.get(path);
        return replacement ? [replacement] : [];
      });
      const changed = groups.length !== user.groups.length || groups.some((path, index) => path !== user.groups[index]);
      return changed || user.groups.some((path) => revokePaths.has(path)) ? { groups } : undefined;
    });
  }
  router.use(adminConsole.router);
  router.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  router.use(async (req, res, next) => {
    try {
      await rateLimits.consumeAdmin(req.ip);
    } catch (error) {
      res.set('Retry-After', String(Math.max(1, Math.ceil((error.msBeforeNext ?? 1000) / 1000))));
      return problem(res, 429, 'Too many requests', 'Wait before retrying the administration API.');
    }
    const match = /^Bearer ([^\s]+)$/.exec(req.get('authorization') ?? '');
    if (match && safeEqual(match[1], config.adminToken)) {
      req.authmeAdmin = { type: 'bearer' };
      return next();
    }
    const authentication = await adminConsole.authenticate(req);
    if (!authentication) {
      res.set('WWW-Authenticate', 'Bearer realm="authme-admin"');
      return problem(res, 401, 'Unauthorized', 'A valid AuthMe administration token or console session is required.');
    }
    const requestedRealm = requestedAdminRealm(req.path);
    if (requestedRealm !== null && requestedRealm !== authentication.realm) {
      return problem(res, 403, 'Realm access denied', 'Switch to this realm before administering it.');
    }
    const permission = requiredAdminPermission(req);
    if (!permission) {
      return problem(res, 403, 'Permission denied', 'This administration route is not available to console sessions.');
    }
    if (!hasAdminPermission(authentication.grant, permission)) {
      return problem(res, 403, 'Permission denied', `This administrator grant does not include ${permission}.`);
    }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      if (!req.is('application/json')) {
        return problem(res, 415, 'Unsupported media type', 'Console mutations require application/json.');
      }
      if (!adminConsole.verifyCsrf(req, authentication)) {
        return problem(res, 403, 'Invalid CSRF token', 'Reload the console and try again.');
      }
      if (!hasRecentAdminAuthentication(authentication)) {
        return problem(
          res,
          403,
          'Recent administrator authentication required',
          'Sign out and complete a fresh administrator sign-in before making security changes.',
        );
      }
    }
    req.authmeAdmin = authentication;
    return next();
  });
  router.use(json({ limit: '64kb', strict: true }));

  router.get('/metrics', async (_req, res, next) => {
    try {
      res.type(metrics.contentType).send(await metrics.render());
    } catch (error) { next(error); }
  });

  router.get('/v1/realms', async (_req, res, next) => {
    try {
      const realms = management ? await management.listRealms() : config.realms.map((name) => ({ name, enabled: true }));
      res.json({ realms: realms.map((realm) => ({ ...realm, issuer: `${config.publicUrl}/realms/${realm.name}` })) });
    } catch (error) { next(error); }
  });

  router.get('/v1/realms/:realm/configuration', async (req, res, next) => {
    try {
    const realm = req.params.realm;
    if (!config.realms.includes(realm)) return problem(res, 404, 'Realm not found', 'The requested realm does not exist.');
    const clientFields = [
      'client_id', 'client_name', 'application_type', 'subject_type', 'token_endpoint_auth_method',
      'redirect_uris', 'post_logout_redirect_uris', 'web_origins', 'response_types', 'grant_types', 'scope',
    ];
    const staticClients = configuredClientsForRealm(config, realm).map((client) => Object.fromEntries(
      clientFields.filter((field) => client[field] !== undefined).map((field) => [field, structuredClone(client[field])]),
    ));
    const managedClients = data.listManagedClients ? await data.listManagedClients(realm) : [];
    const clients = [
      ...staticClients.map((client) => publicClient(client)),
      ...managedClients.map(({ metadata }) => publicClient(metadata, { managed: true })),
    ];
    const ldap = (config.ldapProvidersByRealm[realm] ?? []).map((provider) => ({
      id: provider.id,
      displayName: provider.displayName,
      url: provider.url,
      startTls: provider.startTls,
      userBaseDn: provider.userBaseDn,
      usernameAttribute: provider.usernameAttribute,
      emailAttribute: provider.emailAttribute,
      jitProvisioning: provider.jitProvisioning,
      serviceAccountConfigured: Boolean(provider.bindDn),
    }));
    const oidc = (config.oidcProvidersByRealm[realm] ?? []).map((provider) => ({
      id: provider.id,
      displayName: provider.displayName,
      issuer: provider.issuer,
      clientId: provider.clientId,
      scopes: provider.scopes,
      tokenEndpointAuthMethod: provider.tokenEndpointAuthMethod,
      jitProvisioning: provider.jitProvisioning,
    }));
    const saml = (config.samlProvidersByRealm[realm] ?? []).map((provider) => ({
      id: provider.id,
      displayName: provider.displayName,
      idpEntityId: provider.idp.entityId,
      idpSsoUrl: provider.idp.ssoUrl,
      spEntityId: provider.sp.entityId,
      assertionConsumerServiceUrl: provider.sp.assertionConsumerServiceUrl,
      signedMetadata: provider.sp.signMetadata,
      jitProvisioning: provider.jitProvisioning,
    }));
    return res.json({
      realm,
      issuer: `${config.publicUrl}/realms/${realm}`,
      mode: config.devMode ? 'development' : 'production',
      storage: config.databaseUrl ? 'postgresql' : 'memory',
      redis: Boolean(config.redisUrl),
      dynamicRegistration: config.enableDynamicRegistration,
      ttls: {
        accessToken: config.accessTokenTtl,
        authorizationCode: config.authorizationCodeTtl,
        session: config.sessionTtl,
        webauthnChallenge: config.webauthnChallengeTtl,
        auditRetentionDays: config.auditRetentionDays,
      },
      clients,
      resourceServers: structuredClone(config.resourceServersByRealm[realm] ?? []),
      federation: { ldap, oidc, saml },
      scim: (config.scimTokensByRealm[realm] ?? []).map(({ id }) => ({ id })),
      extensions: extensions?.describe?.(realm) ?? [],
    });
    } catch (error) { return next(error); }
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

  router.get('/v1/realms/:realm', async (req, res, next) => {
    try {
      const realm = await management.findRealm(req.params.realm);
      if (!realm) return problem(res, 404, 'Realm not found', 'The requested realm does not exist.');
      return res.json({ ...realm, issuer: `${config.publicUrl}/realms/${realm.name}` });
    } catch (error) { return next(error); }
  });

  router.patch('/v1/realms/:realm', async (req, res, next) => {
    try {
      const input = parse(realmPatchSchema, req, res);
      if (!input) return undefined;
      const realm = await management.updateRealm(req.params.realm, input);
      if (!realm) return problem(res, 404, 'Realm not found', 'The requested realm does not exist.');
      await audit(store, req, 'admin.realm.updated', undefined, { fields: Object.keys(input) });
      return res.json({ ...realm, issuer: `${config.publicUrl}/realms/${realm.name}` });
    } catch (error) { return managementFailure(error, res, next); }
  });

  router.get('/v1/realms/:realm/clients', async (req, res, next) => {
    try {
      const managed = await data.listManagedClients(req.params.realm);
      const staticClients = configuredClientsForRealm(config, req.params.realm);
      return res.json({
        clients: [
          ...staticClients.map((metadata) => publicClient(metadata)),
          ...managed.map(({ metadata }) => publicClient(metadata, { managed: true })),
        ],
      });
    } catch (error) { return next(error); }
  });

  router.get('/v1/realms/:realm/clients/:clientId', async (req, res, next) => {
    try {
      const managed = (await data.listManagedClients(req.params.realm)).find(({ id }) => id === req.params.clientId);
      const staticClient = configuredClientsForRealm(config, req.params.realm).find((client) => client.client_id === req.params.clientId);
      const metadata = managed?.metadata ?? staticClient;
      if (!metadata) return problem(res, 404, 'Client not found', 'The requested client does not exist.');
      return res.json(publicClient(metadata, { managed: Boolean(managed) }));
    } catch (error) { return next(error); }
  });

  router.post('/v1/realms/:realm/clients', async (req, res, next) => {
    try {
      const input = parse(clientMetadataSchema, req, res);
      if (!input) return undefined;
      if (configuredClientsForRealm(config, req.params.realm).some((client) => client.client_id === input.client_id)) {
        return problem(res, 409, 'Reserved or deployment client', 'This client identifier is owned by deployment configuration or an AuthMe built-in.');
      }
      if ((await data.listManagedClients(req.params.realm)).some(({ id }) => id === input.client_id)) {
        return problem(res, 409, 'Client already exists', 'Use PUT to replace an existing managed client.');
      }
      const metadata = structuredClone(input);
      validateClientSecurity(metadata, { development: config.devMode, mtlsEnabled: config.mtls.enabled });
      await providers.get(req.params.realm).Client.validate(metadata);
      await data.upsertManagedClient(req.params.realm, metadata);
      await audit(store, req, 'admin.client.created', undefined, { clientId: metadata.client_id });
      return res.status(201)
        .location(`/admin/v1/realms/${encodeURIComponent(req.params.realm)}/clients/${encodeURIComponent(metadata.client_id)}`)
        .json(publicClient(metadata, { managed: true }));
    } catch (error) {
      if (/client|redirect|grant|jwks|FAPI|CIBA|origin|secret|subject/iu.test(error?.message ?? '')) {
        return problem(res, 400, 'Invalid client metadata', error.message);
      }
      return managementFailure(error, res, next);
    }
  });

  router.put('/v1/realms/:realm/clients/:clientId', async (req, res, next) => {
    try {
      const input = parse(clientMetadataSchema, req, res);
      if (!input) return undefined;
      if (input.client_id !== req.params.clientId) return problem(res, 400, 'Client identifier mismatch', 'client_id cannot be renamed.');
      const existing = (await data.listManagedClients(req.params.realm)).find(({ id }) => id === req.params.clientId);
      if (!existing) return problem(res, 404, 'Managed client not found', 'Deployment and built-in clients cannot be changed through this API.');
      const metadata = structuredClone(input);
      validateClientSecurity(metadata, { development: config.devMode, mtlsEnabled: config.mtls.enabled });
      await providers.get(req.params.realm).Client.validate(metadata);
      await data.upsertManagedClient(req.params.realm, metadata);
      await audit(store, req, 'admin.client.updated', undefined, { clientId: metadata.client_id });
      return res.json(publicClient(metadata, { managed: true }));
    } catch (error) {
      if (/client|redirect|grant|jwks|FAPI|CIBA|origin|secret|subject/iu.test(error?.message ?? '')) {
        return problem(res, 400, 'Invalid client metadata', error.message);
      }
      return managementFailure(error, res, next);
    }
  });

  router.delete('/v1/realms/:realm/clients/:clientId', async (req, res, next) => {
    try {
      if ([ADMIN_CONSOLE_CLIENT_ID, ACCOUNT_CONSOLE_CLIENT_ID, SAML_IDP_BRIDGE_CLIENT_ID].includes(req.params.clientId)) {
        return problem(res, 409, 'Reserved client', 'Built-in AuthMe clients cannot be removed.');
      }
      if (!await data.deleteManagedClient(req.params.realm, req.params.clientId)) {
        return problem(res, 404, 'Managed client not found', 'Deployment clients cannot be removed through this API.');
      }
      await audit(store, req, 'admin.client.deleted', undefined, { clientId: req.params.clientId });
      return res.status(204).end();
    } catch (error) { return next(error); }
  });

  router.get('/v1/realms/:realm/roles', async (req, res, next) => {
    try { return res.json({ roles: await management.listRoles(req.params.realm) }); } catch (error) { return next(error); }
  });
  router.put('/v1/realms/:realm/roles/:roleName', async (req, res, next) => {
    try {
      if (!policyName.safeParse(req.params.roleName).success) return problem(res, 400, 'Invalid role name', 'The role name is invalid.');
      const input = parse(roleSchema, req, res);
      if (!input) return undefined;
      const previous = (await management.listRoles(req.params.realm)).find((item) => item.name === req.params.roleName);
      const result = await management.putRole(req.params.realm, { name: req.params.roleName, ...input });
      if (previous && JSON.stringify(previous.composites) !== JSON.stringify(result.composites)) {
        await mutateRealmUsers(req.params.realm, (user) => ({ roles: user.roles }));
      }
      await audit(store, req, 'admin.role.upserted', undefined, { role: req.params.roleName });
      return res.status(201).json(result);
    } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/roles/:roleName', async (req, res, next) => {
    try {
      if (!await management.deleteRole(req.params.realm, req.params.roleName)) return problem(res, 404, 'Role not found', 'The requested role does not exist.');
      await mutateRealmUsers(req.params.realm, (user) => (
        user.roles.includes(req.params.roleName) ? { roles: user.roles.filter((name) => name !== req.params.roleName) } : { roles: user.roles }
      ));
      await audit(store, req, 'admin.role.deleted', undefined, { role: req.params.roleName });
      return res.status(204).end();
    } catch (error) { return managementFailure(error, res, next); }
  });

  router.get('/v1/realms/:realm/groups', async (req, res, next) => {
    try { return res.json({ groups: await management.listGroups(req.params.realm) }); } catch (error) { return next(error); }
  });
  router.post('/v1/realms/:realm/groups', async (req, res, next) => {
    try {
      const input = parse(groupCreateSchema, req, res);
      if (!input) return undefined;
      const definedRoles = new Set((await management.listRoles(req.params.realm)).map((roleDefinition) => roleDefinition.name));
      const unknown = input.roles.find((roleName) => !definedRoles.has(roleName));
      if (unknown) return problem(res, 400, 'Unknown role', `Group role ${unknown} is not defined in this realm.`);
      const result = await management.createGroup(req.params.realm, input);
      await audit(store, req, 'admin.group.created', undefined, { groupId: result.id, path: result.path });
      return res.status(201).json(result);
    } catch (error) { return managementFailure(error, res, next); }
  });
  router.patch('/v1/realms/:realm/groups/:groupId', async (req, res, next) => {
    try {
      if (!managementId.safeParse(req.params.groupId).success) return problem(res, 400, 'Invalid group identifier', 'Group identifiers must be UUIDs.');
      const input = parse(groupUpdateSchema, req, res);
      if (!input) return undefined;
      if (input.roles) {
        const definedRoles = new Set((await management.listRoles(req.params.realm)).map((item) => item.name));
        const unknown = input.roles.find((name) => !definedRoles.has(name));
        if (unknown) return problem(res, 400, 'Unknown role', `Group role ${unknown} is not defined in this realm.`);
      }
      const before = await management.listGroups(req.params.realm);
      const result = await management.updateGroup(req.params.realm, req.params.groupId, input);
      if (!result) return problem(res, 404, 'Group not found', 'The requested group does not exist.');
      const after = await management.listGroups(req.params.realm);
      const afterById = new Map(after.map((item) => [item.id, item]));
      const pathChanges = new Map(before.flatMap((item) => {
        const nextGroup = afterById.get(item.id);
        return nextGroup && nextGroup.path !== item.path ? [[item.path, nextGroup.path]] : [];
      }));
      if (pathChanges.size || input.roles) {
        const changedRolePaths = input.roles ? new Set([before.find((item) => item.id === result.id)?.path].filter(Boolean)) : new Set();
        await rewriteUserGroupPaths(req.params.realm, pathChanges, changedRolePaths);
      }
      await audit(store, req, 'admin.group.updated', undefined, { groupId: result.id, fields: Object.keys(input) });
      return res.json(result);
    } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/groups/:groupId', async (req, res, next) => {
    try {
      const existing = (await management.listGroups(req.params.realm)).find((item) => item.id === req.params.groupId);
      if (!await management.deleteGroup(req.params.realm, req.params.groupId)) return problem(res, 404, 'Group not found', 'The requested group does not exist.');
      if (existing) await rewriteUserGroupPaths(req.params.realm, new Map([[existing.path, null]]));
      await audit(store, req, 'admin.group.deleted', undefined, { groupId: req.params.groupId });
      return res.status(204).end();
    } catch (error) { return managementFailure(error, res, next); }
  });

  router.get('/v1/realms/:realm/client-scopes', async (req, res, next) => {
    try { return res.json({ clientScopes: await management.listClientScopes(req.params.realm) }); } catch (error) { return next(error); }
  });
  router.post('/v1/realms/:realm/client-scopes', async (req, res, next) => {
    try { const input = parse(clientScopeCreateSchema, req, res); if (!input) return undefined; const scope = await management.createClientScope(req.params.realm, input); await synchronizeProviderMetadata(req.params.realm); await audit(store, req, 'admin.client_scope.created', undefined, { scopeId: scope.id }); return res.status(201).json(scope); } catch (error) { return managementFailure(error, res, next); }
  });
  router.patch('/v1/realms/:realm/client-scopes/:scopeId', async (req, res, next) => {
    try { const input = parse(clientScopeUpdateSchema, req, res); if (!input) return undefined; const scope = await management.updateClientScope(req.params.realm, req.params.scopeId, input); if (!scope) return problem(res, 404, 'Client scope not found', 'The requested client scope does not exist.'); await synchronizeProviderMetadata(req.params.realm); await audit(store, req, 'admin.client_scope.updated', undefined, { scopeId: scope.id }); return res.json(scope); } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/client-scopes/:scopeId', async (req, res, next) => {
    try { if (!await management.deleteClientScope(req.params.realm, req.params.scopeId)) return problem(res, 404, 'Client scope not found', 'The requested client scope does not exist.'); await synchronizeProviderMetadata(req.params.realm); await audit(store, req, 'admin.client_scope.deleted', undefined, { scopeId: req.params.scopeId }); return res.status(204).end(); } catch (error) { return next(error); }
  });
  router.get('/v1/realms/:realm/clients/:clientId/client-scopes', async (req, res, next) => {
    try { return res.json({ assignments: await management.listClientScopeAssignments(req.params.realm, req.params.clientId) }); } catch (error) { return next(error); }
  });
  router.put('/v1/realms/:realm/clients/:clientId/client-scopes/:scopeId', async (req, res, next) => {
    try { const input = parse(z.object({ assignmentType: z.enum(['default', 'optional']) }).strict(), req, res); if (!input) return undefined; if (!await clientExists(req.params.realm, req.params.clientId)) return problem(res, 404, 'Client not found', 'The requested client does not exist.'); if (!await management.setClientScopeAssignment(req.params.realm, req.params.clientId, req.params.scopeId, input.assignmentType)) return problem(res, 404, 'Client scope not found', 'The requested client scope does not exist.'); await audit(store, req, 'admin.client_scope.assigned', undefined, { clientId: req.params.clientId, scopeId: req.params.scopeId, assignmentType: input.assignmentType }); return res.status(204).end(); } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/clients/:clientId/client-scopes/:scopeId', async (req, res, next) => {
    try { if (!await management.deleteClientScopeAssignment(req.params.realm, req.params.clientId, req.params.scopeId)) return problem(res, 404, 'Client-scope assignment not found', 'The requested assignment does not exist.'); await audit(store, req, 'admin.client_scope.unassigned', undefined, { clientId: req.params.clientId, scopeId: req.params.scopeId }); return res.status(204).end(); } catch (error) { return next(error); }
  });
  router.get('/v1/realms/:realm/claim-mappers', async (req, res, next) => {
    try { const ownerType = req.query.ownerType; const ownerId = req.query.ownerId; if ((ownerType || ownerId) && (!['client', 'client-scope'].includes(ownerType) || typeof ownerId !== 'string')) return problem(res, 400, 'Invalid mapper filter', 'ownerType and ownerId must be provided together.'); return res.json({ claimMappers: await management.listClaimMappers(req.params.realm, ownerType, ownerId) }); } catch (error) { return next(error); }
  });
  router.post('/v1/realms/:realm/claim-mappers', async (req, res, next) => {
    try { const input = parse(claimMapperCreateSchema, req, res); if (!input) return undefined; const ownerExists = input.ownerType === 'client' ? await clientExists(req.params.realm, input.ownerId) : (await management.listClientScopes(req.params.realm)).some((scope) => scope.id === input.ownerId); if (!ownerExists) return problem(res, 404, 'Mapper owner not found', 'The requested client or client scope does not exist.'); const mapper = await management.createClaimMapper(req.params.realm, input); await audit(store, req, 'admin.claim_mapper.created', undefined, { mapperId: mapper.id, ownerType: mapper.ownerType, ownerId: mapper.ownerId }); return res.status(201).json(mapper); } catch (error) { return managementFailure(error, res, next); }
  });
  router.patch('/v1/realms/:realm/claim-mappers/:mapperId', async (req, res, next) => {
    try { const input = parse(claimMapperUpdateSchema, req, res); if (!input) return undefined; const mapper = await management.updateClaimMapper(req.params.realm, req.params.mapperId, input); if (!mapper) return problem(res, 404, 'Claim mapper not found', 'The requested claim mapper does not exist.'); await audit(store, req, 'admin.claim_mapper.updated', undefined, { mapperId: mapper.id }); return res.json(mapper); } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/claim-mappers/:mapperId', async (req, res, next) => {
    try { if (!await management.deleteClaimMapper(req.params.realm, req.params.mapperId)) return problem(res, 404, 'Claim mapper not found', 'The requested claim mapper does not exist.'); await audit(store, req, 'admin.claim_mapper.deleted', undefined, { mapperId: req.params.mapperId }); return res.status(204).end(); } catch (error) { return next(error); }
  });

  router.get('/v1/realms/:realm/authentication-flows', async (req, res, next) => {
    try { return res.json({ authenticationFlows: await management.listAuthenticationFlows(req.params.realm) }); } catch (error) { return next(error); }
  });
  router.post('/v1/realms/:realm/authentication-flows', async (req, res, next) => {
    try { const input = parse(authenticationFlowCreateSchema, req, res); if (!input) return undefined; for (const clientId of input.clientIds) if (!await clientExists(req.params.realm, clientId)) return problem(res, 404, 'Flow client not found', `Client ${clientId} does not exist.`); const flow = await management.createAuthenticationFlow(req.params.realm, input); await synchronizeProviderMetadata(req.params.realm); await audit(store, req, 'admin.authentication_flow.created', undefined, { flowId: flow.id, alias: flow.alias }); return res.status(201).json(flow); } catch (error) { return managementFailure(error, res, next); }
  });
  router.patch('/v1/realms/:realm/authentication-flows/:flowId', async (req, res, next) => {
    try { const input = parse(authenticationFlowUpdateSchema, req, res); if (!input) return undefined; for (const clientId of input.clientIds ?? []) if (!await clientExists(req.params.realm, clientId)) return problem(res, 404, 'Flow client not found', `Client ${clientId} does not exist.`); const flow = await management.updateAuthenticationFlow(req.params.realm, req.params.flowId, input); if (!flow) return problem(res, 404, 'Authentication flow not found', 'The requested authentication flow does not exist.'); await synchronizeProviderMetadata(req.params.realm); await audit(store, req, 'admin.authentication_flow.updated', undefined, { flowId: flow.id }); return res.json(flow); } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/authentication-flows/:flowId', async (req, res, next) => {
    try { if (!await management.deleteAuthenticationFlow(req.params.realm, req.params.flowId)) return problem(res, 404, 'Authentication flow not found', 'The requested authentication flow does not exist.'); await synchronizeProviderMetadata(req.params.realm); await audit(store, req, 'admin.authentication_flow.deleted', undefined, { flowId: req.params.flowId }); return res.status(204).end(); } catch (error) { return next(error); }
  });

  router.get('/v1/realms/:realm/organizations', async (req, res, next) => {
    try { return res.json({ organizations: await management.listOrganizations(req.params.realm) }); } catch (error) { return next(error); }
  });
  router.post('/v1/realms/:realm/organizations', async (req, res, next) => {
    try {
      const input = parse(organizationCreateSchema, req, res); if (!input) return undefined;
      const providerIds = new Set([...(config.ldapProvidersByRealm[req.params.realm] ?? []), ...(config.oidcProvidersByRealm[req.params.realm] ?? []), ...(config.samlProvidersByRealm[req.params.realm] ?? [])].map((provider) => provider.id));
      const unknown = input.identityProviderIds.find((id) => !providerIds.has(id));
      if (unknown) return problem(res, 400, 'Unknown identity provider', `Identity provider ${unknown} is not configured in this realm.`);
      const organization = await management.createOrganization(req.params.realm, input); await audit(store, req, 'admin.organization.created', undefined, { organizationId: organization.id }); return res.status(201).json(organization);
    } catch (error) { return managementFailure(error, res, next); }
  });
  router.get('/v1/realms/:realm/organizations/:organizationId', async (req, res, next) => {
    try { const organization = await management.findOrganization(req.params.realm, req.params.organizationId); if (!organization) return problem(res, 404, 'Organization not found', 'The requested organization does not exist.'); return res.json(organization); } catch (error) { return next(error); }
  });
  router.patch('/v1/realms/:realm/organizations/:organizationId', async (req, res, next) => {
    try {
      const input = parse(organizationUpdateSchema, req, res); if (!input) return undefined;
      if (input.identityProviderIds) {
        const providerIds = new Set([...(config.ldapProvidersByRealm[req.params.realm] ?? []), ...(config.oidcProvidersByRealm[req.params.realm] ?? []), ...(config.samlProvidersByRealm[req.params.realm] ?? [])].map((provider) => provider.id));
        const unknown = input.identityProviderIds.find((id) => !providerIds.has(id));
        if (unknown) return problem(res, 400, 'Unknown identity provider', `Identity provider ${unknown} is not configured in this realm.`);
      }
      const organization = await management.updateOrganization(req.params.realm, req.params.organizationId, input);
      if (!organization) return problem(res, 404, 'Organization not found', 'The requested organization does not exist.');
      await audit(store, req, 'admin.organization.updated', undefined, { organizationId: organization.id, fields: Object.keys(input) });
      return res.json(organization);
    } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/organizations/:organizationId', async (req, res, next) => {
    try { if (!await management.deleteOrganization(req.params.realm, req.params.organizationId)) return problem(res, 404, 'Organization not found', 'The requested organization does not exist.'); await audit(store, req, 'admin.organization.deleted', undefined, { organizationId: req.params.organizationId }); return res.status(204).end(); } catch (error) { return next(error); }
  });
  router.get('/v1/realms/:realm/organizations/:organizationId/members', async (req, res, next) => {
    try { return res.json({ memberships: await management.listOrganizationMemberships(req.params.realm, req.params.organizationId) }); } catch (error) { return next(error); }
  });
  router.put('/v1/realms/:realm/organizations/:organizationId/members/:userId', async (req, res, next) => {
    try { if (!userId.safeParse(req.params.userId).success) return problem(res, 400, 'Invalid user identifier', 'User identifiers must be UUIDs.'); const input = parse(organizationMembershipSchema, req, res); if (!input) return undefined; if (!await store.findUserById(req.params.realm, req.params.userId)) return problem(res, 404, 'User not found', 'The requested user does not exist.'); const membership = await management.upsertOrganizationMembership(req.params.realm, req.params.organizationId, req.params.userId, input.roles); if (!membership) return problem(res, 404, 'Organization not found', 'The requested organization does not exist.'); await audit(store, req, 'admin.organization.member_upserted', req.params.userId, { organizationId: req.params.organizationId, roles: input.roles }); return res.json(membership); } catch (error) { return managementFailure(error, res, next); }
  });
  router.delete('/v1/realms/:realm/organizations/:organizationId/members/:userId', async (req, res, next) => {
    try { if (!await management.deleteOrganizationMembership(req.params.realm, req.params.organizationId, req.params.userId)) return problem(res, 404, 'Organization membership not found', 'The requested membership does not exist.'); await audit(store, req, 'admin.organization.member_removed', req.params.userId, { organizationId: req.params.organizationId }); return res.status(204).end(); } catch (error) { return next(error); }
  });
  router.get('/v1/realms/:realm/organizations/:organizationId/invitations', async (req, res, next) => {
    try { return res.json({ invitations: await management.listOrganizationInvitations(req.params.realm, req.params.organizationId) }); } catch (error) { return next(error); }
  });
  router.post('/v1/realms/:realm/organizations/:organizationId/invitations', async (req, res, next) => {
    try { const input = parse(organizationInvitationSchema, req, res); if (!input) return undefined; if (!await management.findOrganization(req.params.realm, req.params.organizationId)) return problem(res, 404, 'Organization not found', 'The requested organization does not exist.'); const token = randomToken(); const invitation = await management.createOrganizationInvitation(req.params.realm, { organizationId: req.params.organizationId, email: input.email, roles: input.roles, tokenDigest: keyedDigest(`organization-invitation:${req.params.realm}:${token}`, config.passwordPepper), expiresAt: new Date(Date.now() + input.expiresInSeconds * 1000) }); await audit(store, req, 'admin.organization.invitation_created', undefined, { organizationId: req.params.organizationId, invitationId: invitation.id, email: input.email }); return res.status(201).json({ ...invitation, token }); } catch (error) { return managementFailure(error, res, next); }
  });

  router.get('/v1/realms/:realm/signing-keys', async (req, res, next) => {
    try { return res.json({ signingKeys: await management.listSigningKeys(req.params.realm) }); } catch (error) { return next(error); }
  });
  router.post('/v1/realms/:realm/signing-keys/rotate', async (req, res, next) => {
    try {
      const input = parse(z.object({ force: z.boolean().optional().default(false) }).strict(), req, res);
      if (!input) return undefined;
      const manager = signingKeyManagers?.get(req.params.realm);
      if (!manager) return problem(res, 409, 'Signing-key manager unavailable', 'No signing-key manager is active for this realm.');
      const result = await manager.rotate(input);
      await audit(store, req, result.rotated ? 'admin.signing_key.rotated' : 'admin.signing_key.rotation_checked', undefined, {
        keyId: result.keyId,
        dueAt: result.dueAt,
      });
      return res.json({
        rotated: result.rotated,
        keyId: result.keyId,
        dueAt: result.dueAt,
        activation: result.rotated ? 'rolling-restart-required' : 'not-due',
      });
    } catch (error) {
      if (error.code === 'SIGNING_KEY_FILE_ROTATION_REQUIRED') return problem(res, 409, 'External file rotation required', error.message);
      return next(error);
    }
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
  router.use('/v1/realms/:realm/users/:id', async (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || req.authmeAdmin?.type === 'bearer') return next();
    try {
      const targetGrant = await store.findAdminGrant(req.params.realm, req.params.id);
      if (!targetGrant || hasAdminPermission(req.authmeAdmin?.grant, 'administrators.manage')) return next();
      return problem(
        res,
        403,
        'Administrator account protection',
        'Changing an account with an administrator grant requires administrators.manage.',
      );
    } catch (error) {
      return next(error);
    }
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
      const invalidRelationship = await validateUserRelationships(req.params.realm, input);
      if (invalidRelationship) return problem(res, 400, 'Unknown user relationship', invalidRelationship);
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
      const invalidRelationship = await validateUserRelationships(req.params.realm, input);
      if (invalidRelationship) return problem(res, 400, 'Unknown user relationship', invalidRelationship);
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
