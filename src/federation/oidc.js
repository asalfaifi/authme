import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';

import { AUTHME_EXTENSION_API_VERSION } from '../authentication/registry.js';

const providerSchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
  display_name: z.string().trim().min(1).max(100),
  issuer: z.string().url(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  jwks_uri: z.string().url(),
  userinfo_endpoint: z.string().url().optional(),
  client_id: z.string().min(1).max(256),
  client_secret: z.string().min(1).max(4096),
  token_endpoint_auth_method: z.enum(['client_secret_basic', 'client_secret_post']).optional().default('client_secret_basic'),
  scopes: z.array(z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/)).min(1).max(30).optional().default(['openid', 'profile', 'email']),
  signing_algorithms: z.array(z.enum(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'])).min(1).optional().default(['RS256', 'PS256', 'ES256', 'EdDSA']),
  username_claim: z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/).optional().default('preferred_username'),
  groups_claim: z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/).optional().default('groups'),
  roles_claim: z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/).optional().default('roles'),
  require_email: z.boolean().optional().default(true),
  jit_provisioning: z.boolean().optional().default(false),
  require_issuer_parameter: z.boolean().optional().default(false),
  timeout_ms: z.number().int().min(500).max(20_000).optional().default(5_000),
}).strict();

function configurationError(message, cause) {
  return Object.assign(new Error(`Invalid upstream OIDC configuration: ${message}`, cause ? { cause } : undefined), {
    code: 'AUTHME_OIDC_CONFIGURATION_INVALID',
  });
}

function endpoint(value, name, devMode) {
  if (value !== value.trim()) throw configurationError(`${name} cannot contain surrounding whitespace`);
  const url = new URL(value);
  const loopback = ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(devMode && loopback && url.protocol === 'http:')) {
    throw configurationError(`${name} must use HTTPS except for development loopback`);
  }
  if (url.username || url.password || url.hash) throw configurationError(`${name} cannot contain credentials or a fragment`);
  return url.toString();
}

function issuerIdentifier(value, name, devMode) {
  endpoint(value, name, devMode);
  const url = new URL(value);
  if (url.search) throw configurationError(`${name} cannot contain a query`);
  // OIDC issuer comparison is an exact string comparison. Preserve the
  // configured spelling, including a significant trailing slash.
  return value;
}

function callbackUri(value) {
  if (typeof value !== 'string' || value !== value.trim()) throw protocolError('OIDC callback URI is invalid');
  let url;
  try { url = new URL(value); } catch { throw protocolError('OIDC callback URI is invalid'); }
  const loopback = ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
    || url.username || url.password || url.search || url.hash) {
    throw protocolError('OIDC callback URI is invalid');
  }
  return url.toString();
}

function freezeProviders(value) {
  for (const providers of Object.values(value)) {
    for (const provider of providers) {
      Object.freeze(provider.scopes);
      Object.freeze(provider.signingAlgorithms);
      Object.freeze(provider);
    }
    Object.freeze(providers);
  }
  return Object.freeze(value);
}

export function parseOidcProviders(value, { realms, devMode }) {
  if (!value) return freezeProviders(Object.fromEntries(realms.map((realm) => [realm, []])));
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) {
    throw configurationError('AUTHME_OIDC_PROVIDERS_JSON must contain valid JSON', error);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw configurationError('AUTHME_OIDC_PROVIDERS_JSON must be an object keyed by realm');
  }
  const unknownRealms = Object.keys(parsed).filter((realm) => !realms.includes(realm));
  if (unknownRealms.length) throw configurationError(`unknown realms: ${unknownRealms.join(', ')}`);
  const result = {};
  for (const realm of realms) {
    if (!Array.isArray(parsed[realm] ?? [])) throw configurationError(`${realm} must be an array`);
    const ids = new Set();
    result[realm] = (parsed[realm] ?? []).map((input, index) => {
      const validation = providerSchema.safeParse(input);
      if (!validation.success) {
        const issue = validation.error.issues[0];
        throw configurationError(`${realm}[${index}].${issue.path.join('.') || 'provider'}: ${issue.message}`);
      }
      const item = validation.data;
      if (ids.has(item.id)) throw configurationError(`${realm} contains duplicate provider id ${item.id}`);
      ids.add(item.id);
      if (!item.scopes.includes('openid') || new Set(item.scopes).size !== item.scopes.length) {
        throw configurationError(`${realm}.${item.id}.scopes must uniquely include openid`);
      }
      const issuer = issuerIdentifier(item.issuer, `${realm}.${item.id}.issuer`, devMode);
      return {
        id: item.id,
        displayName: item.display_name,
        issuer,
        authorizationEndpoint: endpoint(item.authorization_endpoint, `${realm}.${item.id}.authorization_endpoint`, devMode),
        tokenEndpoint: endpoint(item.token_endpoint, `${realm}.${item.id}.token_endpoint`, devMode),
        jwksUri: endpoint(item.jwks_uri, `${realm}.${item.id}.jwks_uri`, devMode),
        userinfoEndpoint: item.userinfo_endpoint
          ? endpoint(item.userinfo_endpoint, `${realm}.${item.id}.userinfo_endpoint`, devMode) : undefined,
        clientId: item.client_id,
        clientSecret: item.client_secret,
        tokenEndpointAuthMethod: item.token_endpoint_auth_method,
        scopes: [...item.scopes],
        signingAlgorithms: [...new Set(item.signing_algorithms)],
        usernameClaim: item.username_claim,
        groupsClaim: item.groups_claim,
        rolesClaim: item.roles_claim,
        requireEmail: item.require_email,
        jitProvisioning: item.jit_provisioning,
        requireIssuerParameter: item.require_issuer_parameter,
        timeoutMs: item.timeout_ms,
      };
    });
  }
  return freezeProviders(result);
}

function protocolError(message, code = 'AUTHME_OIDC_RESPONSE_INVALID') {
  return Object.assign(new Error(message), { code, status: 400, safe: true });
}

function randomValue(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

function formEncoded(value) {
  return new URLSearchParams({ value }).toString().slice('value='.length);
}

async function jsonResponse(response, context) {
  const length = Number(response.headers?.get?.('content-length') ?? 0);
  if (Number.isFinite(length) && length > 1_048_576) throw protocolError(`${context} response is too large`);
  const text = await response.text();
  if (Buffer.byteLength(text) > 1_048_576) throw protocolError(`${context} response is too large`);
  let body;
  try { body = JSON.parse(text); } catch { throw protocolError(`${context} did not return JSON`); }
  if (!response.ok) throw protocolError(`${context} request failed`, 'AUTHME_OIDC_UPSTREAM_ERROR');
  if (!body || Array.isArray(body) || typeof body !== 'object') throw protocolError(`${context} returned an invalid object`);
  return body;
}

function stringList(value) {
  if (Array.isArray(value)) return value.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim());
  return typeof value === 'string' ? value.split(/[ ,]+/).map((item) => item.trim()).filter(Boolean) : [];
}

function claim(claims, path) {
  return path.split('.').reduce((value, name) => (
    value && !Array.isArray(value) && typeof value === 'object' ? value[name] : undefined
  ), claims);
}

function profileFor(provider, claims) {
  if (typeof claims.sub !== 'string' || !claims.sub) throw protocolError('ID Token subject is missing');
  const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
  if (provider.requireEmail && !email) throw protocolError('The upstream identity did not supply a required email address');
  const usernameClaim = claim(claims, provider.usernameClaim);
  const username = (typeof usernameClaim === 'string' && usernameClaim.trim()) || email || claims.sub;
  return {
    externalSubject: claims.sub,
    username,
    email,
    emailVerified: claims.email_verified === true,
    name: typeof claims.name === 'string' && claims.name.trim() ? claims.name.trim() : username,
    givenName: typeof claims.given_name === 'string' ? claims.given_name.trim() : '',
    familyName: typeof claims.family_name === 'string' ? claims.family_name.trim() : '',
    groups: [...new Set(stringList(claim(claims, provider.groupsClaim)))],
    roles: [...new Set(stringList(claim(claims, provider.rolesClaim)))],
  };
}

function validateAccessTokenHash(tokens, verified) {
  if (verified.payload.at_hash === undefined) return;
  if (typeof verified.payload.at_hash !== 'string' || typeof tokens.access_token !== 'string' || !tokens.access_token) {
    throw protocolError('ID Token access token hash is invalid');
  }
  const bits = /(?:256|384|512)$/.exec(verified.protectedHeader.alg ?? '')?.[0];
  if (!bits) throw protocolError('ID Token access token hash uses an unsupported signing algorithm');
  const digest = createHash(`sha${bits}`).update(tokens.access_token, 'ascii').digest();
  const expected = digest.subarray(0, digest.length / 2).toString('base64url');
  const actualBytes = Buffer.from(verified.payload.at_hash);
  const expectedBytes = Buffer.from(expected);
  if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) {
    throw protocolError('ID Token access token hash is invalid');
  }
}

export function createOidcBroker(provider, {
  stateStore,
  fetch: fetchImplementation = globalThis.fetch,
  jwks = createRemoteJWKSet(new URL(provider.jwksUri), { timeoutDuration: provider.timeoutMs }),
}) {
  if (!stateStore?.issue || !stateStore?.consume) throw new TypeError('OIDC federation requires a one-use state store');
  return {
    async initiate({ realm, interactionUid, callbackUrl }) {
      const redirectUri = callbackUri(callbackUrl);
      const nonce = randomValue();
      const codeVerifier = randomValue(48);
      const state = await stateStore.issue(realm, {
        kind: 'oidc', providerId: provider.id, interactionUid, callbackUrl: redirectUri, nonce, codeVerifier,
      }, 300);
      const url = new URL(provider.authorizationEndpoint);
      url.searchParams.set('client_id', provider.clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('response_mode', 'query');
      url.searchParams.set('scope', provider.scopes.join(' '));
      url.searchParams.set('state', state);
      url.searchParams.set('nonce', nonce);
      url.searchParams.set('code_challenge', createHash('sha256').update(codeVerifier).digest('base64url'));
      url.searchParams.set('code_challenge_method', 'S256');
      return { redirectUrl: url.toString(), state };
    },

    async consume({ realm, callbackUrl, params }) {
      if (!params || typeof params.state !== 'string') throw protocolError('OIDC state is missing');
      const transaction = await stateStore.consume(realm, params.state);
      const redirectUri = callbackUri(callbackUrl);
      if (transaction.kind !== 'oidc' || transaction.providerId !== provider.id || transaction.callbackUrl !== redirectUri) {
        throw protocolError('OIDC state does not match this provider callback');
      }
      if (params.error) throw protocolError('The upstream identity provider denied authentication', 'AUTHME_OIDC_UPSTREAM_ERROR');
      if (typeof params.code !== 'string' || !params.code) throw protocolError('OIDC authorization code is missing');
      if ((provider.requireIssuerParameter || params.iss !== undefined) && params.iss !== provider.issuer) {
        throw protocolError('OIDC authorization response issuer is invalid');
      }
      const tokenBody = new URLSearchParams({
        grant_type: 'authorization_code', code: params.code, redirect_uri: redirectUri,
        code_verifier: transaction.codeVerifier, client_id: provider.clientId,
      });
      const headers = { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' };
      if (provider.tokenEndpointAuthMethod === 'client_secret_basic') {
        headers.authorization = `Basic ${Buffer.from(`${formEncoded(provider.clientId)}:${formEncoded(provider.clientSecret)}`).toString('base64')}`;
      } else {
        tokenBody.set('client_secret', provider.clientSecret);
      }
      const tokenResponse = await fetchImplementation(provider.tokenEndpoint, {
        method: 'POST', headers, body: tokenBody, redirect: 'error', signal: AbortSignal.timeout(provider.timeoutMs),
      });
      const tokens = await jsonResponse(tokenResponse, 'OIDC token endpoint');
      if (typeof tokens.id_token !== 'string') throw protocolError('OIDC token response is missing an ID Token');
      const verified = await jwtVerify(tokens.id_token, jwks, {
        issuer: provider.issuer,
        audience: provider.clientId,
        algorithms: provider.signingAlgorithms,
        clockTolerance: 5,
      });
      if (verified.payload.nonce !== transaction.nonce) throw protocolError('ID Token nonce is invalid');
      if (Array.isArray(verified.payload.aud) && verified.payload.aud.length > 1 && verified.payload.azp !== provider.clientId) {
        throw protocolError('ID Token authorized party is invalid');
      }
      validateAccessTokenHash(tokens, verified);
      let claims = verified.payload;
      if (provider.userinfoEndpoint && typeof tokens.access_token === 'string') {
        if (typeof tokens.token_type !== 'string' || tokens.token_type.toLowerCase() !== 'bearer') {
          throw protocolError('OIDC token response has an invalid token type');
        }
        const response = await fetchImplementation(provider.userinfoEndpoint, {
          headers: { accept: 'application/json', authorization: `Bearer ${tokens.access_token}` },
          redirect: 'error', signal: AbortSignal.timeout(provider.timeoutMs),
        });
        const userinfo = await jsonResponse(response, 'OIDC UserInfo endpoint');
        if (userinfo.sub !== verified.payload.sub) throw protocolError('UserInfo subject does not match the ID Token');
        claims = { ...verified.payload, ...userinfo, sub: verified.payload.sub };
      }
      return {
        interactionUid: transaction.interactionUid,
        protocol: 'oidc',
        providerId: provider.id,
        issuer: provider.issuer,
        allowCreate: provider.jitProvisioning,
        profile: profileFor(provider, claims),
        amr: Array.isArray(verified.payload.amr) ? verified.payload.amr.filter((item) => typeof item === 'string') : ['federated'],
        acr: typeof verified.payload.acr === 'string' ? verified.payload.acr : undefined,
      };
    },
  };
}

export function createOidcFederationExtension({ providersByRealm, stateStore, fetch, jwksForProvider }) {
  const brokers = new Map();
  const provider = (realm, id) => providersByRealm[realm]?.find((candidate) => candidate.id === id);
  const broker = (realm, id) => {
    const configuration = provider(realm, id);
    if (!configuration) throw protocolError('Unknown upstream OIDC provider');
    const key = `${realm}\0${id}`;
    if (!brokers.has(key)) brokers.set(key, createOidcBroker(configuration, {
      stateStore, fetch, jwks: jwksForProvider?.(configuration),
    }));
    return brokers.get(key);
  };
  return {
    manifest: {
      apiVersion: AUTHME_EXTENSION_API_VERSION,
      id: 'builtin.oidc-federation',
      kind: 'federation',
      displayName: 'OpenID Connect federation',
      capabilities: ['oauth2', 'oidc', 'pkce'],
    },
    implementation: {
      enabledFor: (realm) => (providersByRealm[realm]?.length ?? 0) > 0,
      initiate: ({ realm, providerId, ...input }) => broker(realm, providerId).initiate({ realm, ...input }),
      consume: ({ realm, providerId, ...input }) => broker(realm, providerId).consume({ realm, ...input }),
      providersFor: (realm) => (providersByRealm[realm] ?? []).map(({ id, displayName }) => ({ id, displayName })),
    },
  };
}
