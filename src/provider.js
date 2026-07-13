import { createHmac } from 'node:crypto';
import Provider, { errors } from 'oidc-provider';
import { issuerFor } from './config.js';
import {
  renderDeviceConfirmation,
  renderDeviceInput,
  renderDeviceSuccess,
  renderError as renderUiError,
  renderLogoutConfirmation,
  renderLogoutSuccess,
} from './ui/render.js';

const keycloakRoutes = Object.freeze({
  authorization: '/protocol/openid-connect/auth',
  backchannel_authentication: '/protocol/openid-connect/ext/ciba/auth',
  challenge: '/protocol/openid-connect/challenge',
  code_verification: '/device',
  device_authorization: '/protocol/openid-connect/auth/device',
  end_session: '/protocol/openid-connect/logout',
  introspection: '/protocol/openid-connect/token/introspect',
  jwks: '/protocol/openid-connect/certs',
  pushed_authorization_request: '/protocol/openid-connect/ext/par/request',
  registration: '/clients-registrations/openid-connect',
  revocation: '/protocol/openid-connect/revoke',
  token: '/protocol/openid-connect/token',
  userinfo: '/protocol/openid-connect/userinfo',
});

function developmentClients(realm) {
  return [{
    client_id: 'authme-dev',
    client_name: 'AuthMe development client',
    client_secret: 'authme-dev-secret-change-me',
    token_endpoint_auth_method: 'client_secret_basic',
    redirect_uris: ['http://127.0.0.1:3001/callback'],
    post_logout_redirect_uris: ['http://127.0.0.1:3001/'],
    response_types: ['code'],
    grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
    application_type: 'web',
    scope: 'openid profile email roles groups offline_access',
  }, {
    client_id: 'authme-dev-service',
    client_name: 'AuthMe development service',
    client_secret: 'authme-dev-service-secret-change-me',
    token_endpoint_auth_method: 'client_secret_basic',
    redirect_uris: [],
    response_types: [],
    grant_types: ['client_credentials'],
  }];
}

function corsAllowed(origin, client) {
  try {
    return [...(client.redirectUris ?? []), ...(client.postLogoutRedirectUris ?? [])]
      .some((uri) => new URL(uri).origin === origin);
  } catch {
    return false;
  }
}

function accountClaims(user) {
  return {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    preferred_username: user.username,
    name: user.name,
    given_name: user.givenName,
    family_name: user.familyName,
    groups: user.groups,
    realm_access: { roles: user.roles },
    resource_access: user.clientRoles,
  };
}

function secureUiResponse(ctx) {
  ctx.type = 'html';
  ctx.set('Cache-Control', 'no-store');
  ctx.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  ctx.set('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()');
}

function isLoopback(hostname) {
  return hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

function validateClientSecurity(metadata, { development = false } = {}) {
  const grantTypes = metadata.grant_types ?? ['authorization_code'];
  if (grantTypes.some((type) => type === 'implicit' || type === 'password')) {
    throw new Error('Implicit and password grants are not supported');
  }
  if (!development) {
    for (const field of ['redirect_uris', 'post_logout_redirect_uris']) {
      for (const value of metadata[field] ?? []) {
        const url = new URL(value);
        const nativeLoopback = metadata.application_type === 'native' && url.protocol === 'http:' && isLoopback(url.hostname);
        if (url.protocol !== 'https:' && !nativeLoopback) throw new Error(`${field} must use HTTPS except for native loopback clients`);
        if (url.username || url.password || url.hash) throw new Error(`${field} entries cannot contain credentials or fragments`);
      }
    }
    for (const field of ['jwks_uri', 'sector_identifier_uri', 'backchannel_logout_uri', 'frontchannel_logout_uri']) {
      if (!metadata[field]) continue;
      const url = new URL(metadata[field]);
      if (url.protocol !== 'https:') throw new Error(`${field} must use HTTPS`);
      if (url.username || url.password || url.hash) throw new Error(`${field} cannot contain credentials or a fragment`);
    }
    const method = metadata.token_endpoint_auth_method ?? 'client_secret_basic';
    if (method.startsWith('client_secret') && Buffer.byteLength(metadata.client_secret ?? '') < 32) {
      throw new Error('Confidential client secrets must contain at least 32 bytes');
    }
  }
}

export async function createRealmProvider({ realm, config, store, data, Adapter, jwks, logger, auditWriter }) {
  const issuer = issuerFor(config, realm);
  const clients = [...config.clientsByRealm[realm]];
  if (config.devMode && clients.length === 0) clients.push(...developmentClients(realm));
  for (const client of clients) validateClientSecurity(client, { development: config.devMode });

  async function secureRegistrationPolicy(ctx, properties) {
    try {
      validateClientSecurity(properties, { development: config.devMode });
    } catch (error) {
      throw new errors.InvalidClientMetadata(error.message);
    }
    const initialToken = ctx.oidc.entities.InitialAccessToken;
    if (initialToken) {
      const claimed = await data.claimInitialAccessToken(realm, initialToken.jti);
      if (!claimed) throw new errors.InvalidToken('initial access token was already used');
      await initialToken.destroy();
    }
  }

  const provider = new Provider(issuer, {
    adapter: Adapter,
    clients,
    jwks,
    routes: keycloakRoutes,
    scopes: ['openid', 'offline_access', 'profile', 'email', 'phone', 'address', 'roles', 'groups'],
    responseTypes: ['code'],
    claims: {
      address: ['address'],
      email: ['email', 'email_verified'],
      phone: ['phone_number', 'phone_number_verified'],
      profile: ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'],
      roles: ['realm_access', 'resource_access'],
      groups: ['groups'],
    },
    cookies: {
      keys: [...config.cookieKeys],
      long: { httpOnly: true, sameSite: 'lax', secure: !config.devMode, overwrite: true },
      short: { httpOnly: true, sameSite: 'lax', secure: !config.devMode, overwrite: true },
      names: {
        session: `authme_${realm}_session`,
        interaction: `authme_${realm}_interaction`,
        resume: `authme_${realm}_resume`,
      },
    },
    interactions: {
      url(_ctx, interaction) {
        return `/realms/${realm}/interaction/${interaction.uid}`;
      },
    },
    features: {
      backchannelLogout: { enabled: true },
      claimsParameter: {
        enabled: true,
        async assertClaimsParameter(_ctx, requestedClaims) {
          const supported = new Set([
            'sub', 'sid', 'auth_time', 'acr', 'amr', 'iss', 'address', 'email', 'email_verified',
            'phone_number', 'phone_number_verified', 'name', 'family_name', 'given_name',
            'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website',
            'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at', 'groups',
            'realm_access', 'resource_access',
          ]);
          for (const section of ['id_token', 'userinfo']) {
            for (const claim of Object.keys(requestedClaims?.[section] ?? {})) {
              if (!supported.has(claim)) throw new errors.InvalidRequest(`unsupported requested claim: ${claim}`);
            }
          }
        },
      },
      clientCredentials: { enabled: true },
      devInteractions: { enabled: false },
      deviceFlow: {
        enabled: true,
        async userCodeInputSource(ctx, form, _out, error) {
          const message = error
            ? 'The device code is invalid, expired, or already used. Check the code and try again.'
            : '';
          secureUiResponse(ctx);
          ctx.body = renderDeviceInput({ realm, form, error: message });
        },
        async userCodeConfirmSource(ctx, form, client, _deviceInfo, userCode) {
          secureUiResponse(ctx);
          ctx.body = renderDeviceConfirmation({
            realm,
            form,
            clientName: client.clientName || client.clientId,
            userCode,
          });
        },
        async successSource(ctx) {
          secureUiResponse(ctx);
          ctx.body = renderDeviceSuccess({
            realm,
            clientName: ctx.oidc.client?.clientName || ctx.oidc.client?.clientId || 'your application',
          });
        },
      },
      dPoP: { enabled: true },
      introspection: {
        enabled: true,
        async allowedPolicy(_ctx, client, token) {
          return token.clientId === client.clientId;
        },
      },
      pushedAuthorizationRequests: { enabled: true },
      registration: {
        enabled: config.enableDynamicRegistration,
        initialAccessToken: config.enableDynamicRegistration,
        policies: config.enableDynamicRegistration ? { 'authme-secure-client': secureRegistrationPolicy } : undefined,
      },
      registrationManagement: { enabled: config.enableDynamicRegistration },
      requestObjects: { enabled: false },
      resourceIndicators: { enabled: false },
      revocation: {
        enabled: true,
        async allowedPolicy(_ctx, client, token) {
          return token.clientId === client.clientId;
        },
      },
      rpInitiatedLogout: {
        enabled: true,
        async logoutSource(ctx, form) {
          secureUiResponse(ctx);
          const client = ctx.oidc.client;
          ctx.body = renderLogoutConfirmation({
            realm,
            form,
            clientName: client?.clientName || client?.clientId || '',
          });
        },
        async postLogoutSuccessSource(ctx) {
          secureUiResponse(ctx);
          const client = ctx.oidc.client;
          ctx.body = renderLogoutSuccess({
            realm,
            clientName: client?.clientName || client?.clientId || '',
          });
        },
      },
      userinfo: { enabled: true },
    },
    ttl: {
      AccessToken: config.accessTokenTtl,
      AuthorizationCode: config.authorizationCodeTtl,
      ClientCredentials: config.accessTokenTtl,
      DeviceCode: 600,
      Grant: 14 * 24 * 60 * 60,
      IdToken: config.accessTokenTtl,
      Interaction: 600,
      RefreshToken: 14 * 24 * 60 * 60,
      Session: config.sessionTtl,
    },
    pkce: { required: () => true },
    rotateRefreshToken: true,
    issueRefreshToken(_ctx, client, code) {
      return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
    },
    async findAccount(_ctx, id) {
      const user = await store.findUserById(realm, id);
      if (!user?.enabled) return undefined;
      return {
        accountId: user.id,
        async claims() {
          return accountClaims(user);
        },
      };
    },
    async pairwiseIdentifier(_ctx, accountId, client) {
      const sector = client.sectorIdentifierUri ?? client.clientId;
      return createHmac('sha256', config.subjectSalt).update(`${realm}\u0000${accountId}\u0000${sector}`).digest('base64url');
    },
    clientBasedCORS(_ctx, origin, client) {
      return corsAllowed(origin, client);
    },
    discovery: {
      service_documentation: 'https://github.com/asalfaifi/authme',
      op_policy_uri: 'https://github.com/asalfaifi/authme/blob/main/SECURITY.md',
    },
    fetchResponseBodyLimits: {
      'client_id metadata document': 5 * 1024,
      jwks_uri: 1024 * 1024,
      sector_identifier_uri: 64 * 1024,
    },
    async fetch(url, options) {
      const target = new URL(url);
      if (target.protocol !== 'https:') throw new Error('External OIDC metadata must use HTTPS');
      // Redirects are rejected so an accepted HTTPS metadata URI cannot
      // downgrade transport or escape the provider's per-request SSRF checks.
      return globalThis.fetch(target, { ...options, redirect: 'manual' });
    },
    async renderError(ctx, out) {
      secureUiResponse(ctx);
      ctx.body = renderUiError({
        realm,
        title: 'Authorization request failed',
        message: out.error_description || out.error || 'The authorization request could not be completed safely.',
      });
    },
  });

  provider.proxy = config.trustProxy;
  if (config.trustProxy) provider.maxIpsCount = 1;
  function writeProviderAudit(eventName, { artifact, ctx, error } = {}) {
    const event = {
      realm,
      type: `oidc.${eventName}`,
      subjectId: artifact?.accountId ?? ctx?.oidc?.session?.accountId,
      clientId: artifact?.clientId ?? ctx?.oidc?.client?.clientId,
      ip: ctx?.ip,
      userAgent: ctx?.get?.('user-agent'),
      metadata: error ? { error: error.error ?? error.name ?? 'Error' } : {},
    };
    const options = error ? {
      sampleKey: createHmac('sha256', config.passwordPepper)
        .update(`${realm}\u0000${eventName}\u0000${event.ip ?? 'unknown'}\u0000${event.clientId ?? 'none'}\u0000${event.metadata.error}`)
        .digest('base64url'),
      sampleWindowMs: 10_000,
    } : undefined;
    const outcome = auditWriter.enqueue(event, options);
    logger[error && outcome === 'accepted' ? 'warn' : 'debug'](
      { realm, event: eventName, clientId: event.clientId, err: error, auditOutcome: outcome },
      'OIDC event',
    );
  }

  for (const eventName of [
    'access_token.issued', 'access_token.saved', 'access_token.destroyed',
    'authorization_code.saved', 'authorization_code.consumed',
    'client_credentials.issued', 'client_credentials.saved', 'client_credentials.destroyed',
    'device_code.saved', 'device_code.consumed', 'device_code.destroyed',
    'initial_access_token.saved', 'initial_access_token.destroyed',
    'refresh_token.saved', 'refresh_token.consumed', 'refresh_token.destroyed',
    'registration_access_token.saved', 'registration_access_token.destroyed',
    'session.destroyed',
  ]) provider.on(eventName, (artifact) => writeProviderAudit(eventName, { artifact }));

  for (const eventName of [
    'authorization.accepted', 'authorization.success', 'backchannel.success',
    'device_authorization.success', 'end_session.success', 'grant.revoked', 'grant.success', 'interaction.ended', 'interaction.started',
    'pushed_authorization_request.success', 'registration_create.success',
    'registration_delete.success', 'registration_update.success',
  ]) {
    provider.on(eventName, (ctx) => writeProviderAudit(eventName, { ctx }));
  }

  for (const eventName of [
    'authorization.error', 'backchannel.error', 'grant.error', 'introspection.error',
    'registration_create.error', 'registration_delete.error', 'registration_read.error',
    'registration_update.error', 'revocation.error', 'server_error', 'userinfo.error',
  ]) provider.on(eventName, (ctx, error) => writeProviderAudit(eventName, { ctx, error }));

  return provider;
}

export { keycloakRoutes };
export { validateClientSecurity };
