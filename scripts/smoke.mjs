import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import * as OTPAuth from 'otpauth';
import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const port = Number(process.env.AUTHME_SMOKE_PORT ?? 33179);
const base = `http://127.0.0.1:${port}`;
const resourceAudience = `${base}/resources/orders`;
const opaqueResourceAudience = `${base}/resources/metrics`;
const adminToken = 'authme-smoke-administration-token-0001';
const databaseUrl = process.env.AUTHME_SMOKE_DATABASE_URL;
const scimToken = 'authme-smoke-scim-token-0000000000000001';
const scimSuffix = randomBytes(6).toString('hex');
const config = loadConfig({
  AUTHME_DEV_MODE: 'true',
  AUTHME_PUBLIC_URL: base,
  AUTHME_PORT: String(port),
  AUTHME_REALMS: 'master',
  AUTHME_LOG_LEVEL: 'silent',
  AUTHME_ADMIN_TOKEN: adminToken,
  AUTHME_PASSWORD_PEPPER: 'authme-smoke-password-pepper-000001',
  AUTHME_CSRF_SECRET: 'authme-smoke-csrf-secret-0000000001',
  AUTHME_SUBJECT_SALT: 'authme-smoke-subject-salt-00000001',
  AUTHME_COOKIE_KEYS: 'authme-smoke-cookie-key-000000000001',
  AUTHME_FIELD_ENCRYPTION_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  AUTHME_DEV_ADMIN_PASSWORD: 'AuthMe-Change-Me-Now-2026!',
  AUTHME_ENABLE_DYNAMIC_REGISTRATION: 'true',
  AUTHME_RESOURCE_SERVERS_JSON: JSON.stringify({
    master: [{
      audience: resourceAudience,
      scopes: ['orders.read', 'roles', 'groups'],
      authorized_client_ids: ['authme-dev'],
      role_client_ids: ['orders-api'],
      include_realm_roles: true,
      include_groups: true,
    }, {
      audience: opaqueResourceAudience,
      scopes: ['metrics.read'],
      authorized_client_ids: ['authme-dev-service'],
      introspection_client_ids: ['authme-dev'],
      access_token_format: 'opaque',
    }],
  }),
  ...(databaseUrl ? {
    DATABASE_URL: databaseUrl,
    AUTHME_SCIM_TOKENS_JSON: JSON.stringify({ master: [{ id: 'smoke-provisioner', token: scimToken }] }),
  } : {}),
});
const runtime = await createAuthMeApp(config);
const server = createServer(runtime.app);
const cookies = new Map();

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function collectCookies(headers) {
  for (const value of headers.getSetCookie()) {
    const [pair] = value.split(';', 1);
    const separator = pair.indexOf('=');
    cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}

async function request(url, options = {}) {
  const headers = new Headers(options.headers);
  if (cookies.size) headers.set('cookie', [...cookies].map(([name, value]) => `${name}=${value}`).join('; '));
  const response = await fetch(url, { ...options, headers, redirect: 'manual' });
  collectCookies(response.headers);
  return response;
}

function csrf(html) {
  const match = /name="csrf" value="([^"]+)"/.exec(html);
  assert(match, 'Interaction page did not contain a CSRF token');
  return match[1];
}

function formValue(html, name) {
  const match = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  assert(match, `Page did not contain the ${name} form value`);
  return match[1];
}

function location(response) {
  const value = response.headers.get('location');
  assert(value, `Expected redirect, got ${response.status}`);
  return new URL(value, base).toString();
}

async function form(url, values, headers = {}) {
  return request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(values),
  });
}

try {
  await new Promise((resolve, reject) => server.listen(port, '127.0.0.1', resolve).once('error', reject));
  const ready = await request(`${base}/health/ready`);
  assert(ready.status === 200, 'Readiness check failed');

  if (databaseUrl) {
    const scimBase = `${base}/scim/v2/realms/master`;
    const scimHeaders = { authorization: `Bearer ${scimToken}`, 'content-type': 'application/scim+json' };
    const scimDiscovery = await request(`${scimBase}/ServiceProviderConfig`, { headers: scimHeaders });
    assert(scimDiscovery.status === 200, 'SCIM discovery failed');
    const scimCreate = await request(`${scimBase}/Users`, {
      method: 'POST',
      headers: scimHeaders,
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: `smoke-scim-${scimSuffix}`,
        externalId: `smoke-scim-${scimSuffix}`,
        displayName: 'SCIM Smoke User',
        emails: [{ value: `smoke-scim-${scimSuffix}@example.test`, primary: true }],
        active: true,
      }),
    });
    const scimUser = await scimCreate.json();
    assert(scimCreate.status === 201 && scimUser.id && scimUser.meta?.version, 'SCIM User creation failed');
    const scimAudit = await runtime.store.listAudit('master', { limit: 20 });
    assert(scimAudit.some(({ type, subjectId }) => type === 'scim.user.created' && subjectId === scimUser.id), 'SCIM mutation audit failed');
  }

  const discoveryResponse = await request(`${base}/realms/master/.well-known/openid-configuration`);
  assert(discoveryResponse.status === 200, 'Discovery failed');
  const discovery = await discoveryResponse.json();
  assert(discovery.issuer === `${base}/realms/master`, 'Issuer mismatch');
  assert(!discovery.grant_types_supported.includes('implicit'), 'Implicit grant must not be advertised');
  assert(discovery.code_challenge_methods_supported.includes('S256'), 'S256 PKCE is not advertised');
  assert(discovery.token_endpoint_auth_methods_supported.join(' ') === 'client_secret_basic none', 'Unsupported client authentication methods are advertised');
  assert(discovery.subject_types_supported.includes('pairwise'), 'Pairwise subject identifiers are not advertised');
  const oauthMetadataResponse = await request(`${base}/.well-known/oauth-authorization-server/realms/master`);
  const oauthMetadata = await oauthMetadataResponse.json();
  assert(oauthMetadataResponse.status === 200, 'RFC 8414 metadata failed');
  for (const endpoint of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'introspection_endpoint']) {
    assert(oauthMetadata[endpoint] === discovery[endpoint], `RFC 8414 ${endpoint} does not use the realm mount`);
  }
  const basic = `Basic ${Buffer.from('authme-dev:authme-dev-secret-change-me').toString('base64')}`;

  const malformedAuthorization = new URL(discovery.authorization_endpoint);
  malformedAuthorization.search = new URLSearchParams({
    client_id: 'missing-client', response_type: 'code', scope: 'openid',
    redirect_uri: 'http://127.0.0.1:3999/callback',
  });
  const auditBefore = (await runtime.store.listAudit('master', { limit: 250 }))
    .filter(({ type }) => type === 'oidc.authorization.error').length;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const rejected = await request(malformedAuthorization);
    assert(rejected.status === 400, 'Malformed authorization request was not rejected');
  }
  await runtime.auditWriter.flush();
  const auditAfter = (await runtime.store.listAudit('master', { limit: 250 }))
    .filter(({ type }) => type === 'oidc.authorization.error').length;
  assert(auditAfter - auditBefore === 1, 'Repeated public protocol errors were not audit-sampled');

  const unauthorized = await request(`${base}/admin/v1/realms`);
  assert(unauthorized.status === 401, 'Admin API accepted a request without credentials');

  let response = await request(`${base}/admin/v1/realms/master/client-registration-tokens`, {
    method: 'POST',
    headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ expiresInSeconds: 300 }),
  });
  const registrationAuthorization = await response.json();
  assert(response.status === 201 && registrationAuthorization.token, 'Initial registration-token issuance failed');
  response = await request(discovery.registration_endpoint, {
    method: 'POST',
    headers: { authorization: `Bearer ${registrationAuthorization.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'AuthMe smoke dynamically registered client',
      redirect_uris: ['http://127.0.0.1:3002/callback'],
      web_origins: ['http://127.0.0.1:3002'],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      token_endpoint_auth_method: 'client_secret_basic',
    }),
  });
  const registeredClient = await response.json();
  assert(response.status === 201 && registeredClient.client_id && registeredClient.client_secret, `Protected dynamic registration failed: ${JSON.stringify(registeredClient)}`);
  assert(registeredClient.web_origins?.[0] === 'http://127.0.0.1:3002', 'Dynamic registration did not retain explicit web origins');
  response = await request(discovery.registration_endpoint, {
    method: 'POST',
    headers: { authorization: `Bearer ${registrationAuthorization.token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'IAT replay attempt',
      redirect_uris: ['http://127.0.0.1:3003/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      token_endpoint_auth_method: 'client_secret_basic',
    }),
  });
  assert(response.status === 401, 'An initial registration access token was accepted more than once');

  const verifier = randomBytes(48).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(16).toString('base64url');
  const authorization = new URL(discovery.authorization_endpoint);
  authorization.search = new URLSearchParams({
    client_id: 'authme-dev',
    redirect_uri: 'http://127.0.0.1:3001/callback',
    response_type: 'code',
    scope: 'openid profile email roles groups offline_access',
    prompt: 'consent',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    claims: JSON.stringify({ userinfo: { phone_number: null } }),
  });

  response = await request(authorization);
  assert([302, 303].includes(response.status), 'Authorization did not start an interaction');
  let interactionUrl = location(response);
  response = await request(interactionUrl);
  let html = await response.text();
  assert(response.status === 200 && html.includes('Welcome back'), 'Login page was not rendered');

  response = await form(`${interactionUrl}/login`, {
    csrf: csrf(html),
    login: 'admin',
    password: 'AuthMe-Change-Me-Now-2026!',
    otp: '',
  });
  assert([302, 303].includes(response.status), 'Valid login was not accepted');

  let callback;
  for (let step = 0; step < 8; step += 1) {
    const target = location(response);
    if (target.startsWith('http://127.0.0.1:3001/callback')) {
      callback = new URL(target);
      break;
    }
    response = await request(target);
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      html = await response.text();
      if (response.status === 200 && html.includes('/confirm')) {
        assert(html.includes('claim:phone_number'), 'Consent page hid an explicitly requested claim');
        response = await form(`${target}/confirm`, { csrf: csrf(html) });
      } else {
        throw new Error(`Unexpected authorization response ${response.status}`);
      }
    }
  }
  assert(callback, 'Authorization did not return to the client');
  assert(callback.searchParams.get('state') === state, 'State was not preserved');
  const code = callback.searchParams.get('code');
  assert(code, 'Authorization response did not include a code');

  response = await form(discovery.token_endpoint, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'http://127.0.0.1:3001/callback',
    code_verifier: verifier,
  }, { authorization: basic });
  const tokens = await response.json();
  assert(response.status === 200 && tokens.access_token && tokens.id_token && tokens.refresh_token, `Token exchange failed: ${JSON.stringify(tokens)}`);

  const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
  const verified = await jwtVerify(tokens.id_token, jwks, { issuer: discovery.issuer, audience: 'authme-dev' });
  assert(verified.payload.sub, 'ID token did not contain a subject');

  response = await request(discovery.userinfo_endpoint, {
    headers: {
      authorization: `Bearer ${tokens.access_token}`,
      origin: 'http://127.0.0.1:3001',
    },
  });
  const userinfo = await response.json();
  assert(response.status === 200 && userinfo.preferred_username === 'admin', 'UserInfo failed');
  assert(response.headers.get('access-control-allow-origin') === 'http://127.0.0.1:3001', 'Explicit client web origin was not allowed by CORS');

  await runtime.store.updateUser('master', verified.payload.sub, {
    roles: ['admin', 'member'],
    groups: ['/administrators', '/engineering'],
    clientRoles: {
      'orders-api': ['orders.read'],
      'payroll-api': ['payroll.read'],
    },
  });
  const resourceVerifier = randomBytes(48).toString('base64url');
  const resourceChallenge = createHash('sha256').update(resourceVerifier).digest('base64url');
  const resourceAuthorization = new URL(discovery.authorization_endpoint);
  resourceAuthorization.search = new URLSearchParams({
    client_id: 'authme-dev',
    redirect_uri: 'http://127.0.0.1:3001/callback',
    response_type: 'code',
    scope: 'openid roles groups orders.read',
    resource: resourceAudience,
    prompt: 'consent',
    code_challenge: resourceChallenge,
    code_challenge_method: 'S256',
    state: `${state}-resource`,
  });
  response = await request(resourceAuthorization);
  let resourceCallback;
  for (let step = 0; step < 8; step += 1) {
    const target = location(response);
    if (target.startsWith('http://127.0.0.1:3001/callback')) {
      resourceCallback = new URL(target);
      break;
    }
    response = await request(target);
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      html = await response.text();
      if (response.status === 200 && html.includes('/confirm')) {
        assert(html.includes('orders.read'), 'Resource-server consent did not disclose the API scope');
        response = await form(`${target}/confirm`, { csrf: csrf(html) });
      } else {
        throw new Error(`Unexpected resource authorization response ${response.status}`);
      }
    }
  }
  assert(resourceCallback, 'Resource authorization did not return to the client');
  response = await form(discovery.token_endpoint, {
    grant_type: 'authorization_code',
    code: resourceCallback.searchParams.get('code'),
    redirect_uri: 'http://127.0.0.1:3001/callback',
    code_verifier: resourceVerifier,
  }, { authorization: basic });
  const resourceTokens = await response.json();
  assert(response.status === 200 && resourceTokens.access_token?.split('.').length === 3, `Resource token was not a JWT: ${JSON.stringify(resourceTokens)}`);
  const resourceVerified = await jwtVerify(resourceTokens.access_token, jwks, {
    issuer: discovery.issuer,
    audience: resourceAudience,
    typ: 'at+jwt',
  });
  assert(resourceVerified.protectedHeader.typ === 'at+jwt', 'Resource access token type is not at+jwt');
  assert(resourceVerified.payload.client_id === 'authme-dev', 'Resource token client_id is incorrect');
  assert(resourceVerified.payload.realm_access?.roles.includes('member'), 'Resource token omitted configured realm roles');
  assert(resourceVerified.payload.resource_access?.['orders-api']?.roles.includes('orders.read'), 'Resource token omitted audience roles');
  assert(!resourceVerified.payload.resource_access?.['payroll-api'], 'Resource token leaked roles for another audience');
  assert(resourceVerified.payload.groups?.includes('/engineering'), 'Resource token omitted configured groups');

  response = await request(discovery.userinfo_endpoint, { headers: { authorization: `Bearer ${resourceTokens.access_token}` } });
  assert(response.status === 401, 'An audience-bound API token was accepted at UserInfo');
  response = await form(discovery.introspection_endpoint, { token: resourceTokens.access_token }, { authorization: basic });
  const jwtIntrospection = await response.json();
  assert(response.status === 400 && jwtIntrospection.error === 'unsupported_token_type', 'JWT introspection did not fail with the provider-defined error');

  const serviceBasic = `Basic ${Buffer.from('authme-dev-service:authme-dev-service-secret-change-me').toString('base64')}`;
  response = await form(discovery.token_endpoint, {
    grant_type: 'client_credentials',
    scope: 'metrics.read',
    resource: opaqueResourceAudience,
  }, { authorization: serviceBasic });
  const opaqueResourceToken = await response.json();
  assert(response.status === 200 && opaqueResourceToken.access_token?.split('.').length !== 3, 'Opaque resource server did not receive an opaque token');
  response = await form(discovery.introspection_endpoint, {
    token: opaqueResourceToken.access_token,
  }, { authorization: basic });
  const delegatedIntrospection = await response.json();
  assert(response.status === 200 && delegatedIntrospection.active === true, 'Authorized resource-server introspection failed');
  assert(delegatedIntrospection.aud === opaqueResourceAudience, 'Introspection returned the wrong resource audience');
  const dynamicBasic = `Basic ${Buffer.from(`${registeredClient.client_id}:${registeredClient.client_secret}`).toString('base64')}`;
  response = await form(discovery.introspection_endpoint, {
    token: opaqueResourceToken.access_token,
  }, { authorization: dynamicBasic });
  const deniedIntrospection = await response.json();
  assert(response.status === 200 && deniedIntrospection.active === false, 'Unauthorized client introspected another resource token');
  response = await form(discovery.token_endpoint, {
    grant_type: 'client_credentials',
    scope: 'orders.read',
    resource: resourceAudience,
  }, { authorization: serviceBasic });
  const deniedResource = await response.json();
  assert(response.status === 400 && deniedResource.error === 'invalid_target', 'Unauthorized client received a token for another resource');

  response = await form(discovery.token_endpoint, {
    grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
  }, { authorization: basic });
  const refreshed = await response.json();
  assert(response.status === 200 && refreshed.refresh_token, 'Refresh-token rotation failed');

  response = await form(discovery.introspection_endpoint, { token: refreshed.access_token }, { authorization: basic });
  let introspection = await response.json();
  assert(response.status === 200 && introspection.active === true, 'Introspection failed');

  response = await form(discovery.token_endpoint, {
    grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
  }, { authorization: basic });
  assert(response.status === 400, 'A consumed refresh token was accepted');

  response = await form(discovery.introspection_endpoint, { token: refreshed.access_token }, { authorization: basic });
  introspection = await response.json();
  assert(response.status === 200 && introspection.active === false, 'Refresh-token replay did not revoke the token family');

  response = await form(discovery.revocation_endpoint, { token: refreshed.refresh_token }, { authorization: basic });
  assert(response.status === 200, 'Revocation failed');

  response = await form(discovery.device_authorization_endpoint, { scope: 'openid profile' }, { authorization: basic });
  const device = await response.json();
  assert(response.status === 200 && device.device_code && device.user_code, 'Device authorization failed');
  assert(device.verification_uri === `${base}/realms/master/device`, 'Device verification URI mismatch');

  response = await request(device.verification_uri_complete);
  html = await response.text();
  assert(response.status === 200 && html.includes('document.forms[0].submit()'), 'Complete device URI did not render its submission bridge');
  assert(/script-src[^;]*'sha256-/.test(response.headers.get('content-security-policy') ?? ''), 'Complete device URI script was not bound by a CSP hash');

  response = await request(device.verification_uri);
  html = await response.text();
  assert(response.status === 200 && html.includes('Enter your device code') && html.includes('/assets/authme.css'), 'AuthMe device-code page was not rendered');
  response = await form(device.verification_uri, {
    xsrf: formValue(html, 'xsrf'),
    user_code: device.user_code,
  });
  html = await response.text();
  assert(response.status === 200 && html.includes('Confirm this device') && html.includes('AuthMe development client'), 'Device confirmation page was not rendered');
  response = await form(device.verification_uri, {
    xsrf: formValue(html, 'xsrf'),
    user_code: formValue(html, 'user_code'),
    confirm: 'yes',
  });
  html = '';
  for (let step = 0; step < 12; step += 1) {
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      response = await request(location(response));
      continue;
    }
    html = await response.text();
    if (response.status === 200 && html.includes('/confirm')) {
      response = await form(`${response.url}/confirm`, { csrf: csrf(html) });
      continue;
    }
    break;
  }
  assert(response.status === 200 && html.includes('Device connected'), `Device authorization was not approved (${response.status}): ${html.slice(0, 300)}`);
  response = await form(discovery.token_endpoint, {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: device.device_code,
  }, { authorization: basic });
  const deviceTokens = await response.json();
  assert(response.status === 200 && deviceTokens.access_token && deviceTokens.id_token, `Device token exchange failed: ${JSON.stringify(deviceTokens)}`);

  const userId = verified.payload.sub;
  const adminHeaders = { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' };
  response = await request(`${base}/admin/v1/realms/master/users/${userId}/mfa/totp`, {
    method: 'POST', headers: adminHeaders, body: '{}',
  });
  const enrollment = await response.json();
  assert(response.status === 201 && enrollment.secret, 'TOTP enrollment did not start');
  const totp = new OTPAuth.TOTP({
    algorithm: 'SHA1', digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });
  const confirmationCode = totp.generate();
  const confirmations = await Promise.all([0, 1].map(() => request(
    `${base}/admin/v1/realms/master/users/${userId}/mfa/totp/confirm`,
    { method: 'POST', headers: adminHeaders, body: JSON.stringify({ token: confirmationCode }) },
  )));
  assert(confirmations.map((item) => item.status).sort().join(',') === '200,409', 'Concurrent TOTP confirmation was not atomic');
  const confirmedResponse = confirmations.find((item) => item.status === 200);
  const { recoveryCodes } = await confirmedResponse.json();
  assert(recoveryCodes?.length === 10, 'TOTP confirmation did not return recovery codes once');
  response = await form(discovery.introspection_endpoint, { token: deviceTokens.access_token }, { authorization: basic });
  introspection = await response.json();
  assert(response.status === 200 && introspection.active === false, 'MFA security mutation did not revoke existing account tokens');

  async function beginForcedLogin(suffix) {
    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: 'authme-dev',
      redirect_uri: 'http://127.0.0.1:3001/callback',
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: `${state}-${suffix}`,
      prompt: 'login',
    });
    let result = await request(url);
    assert([302, 303].includes(result.status), 'Forced MFA login did not start');
    const urlForInteraction = location(result);
    result = await request(urlForInteraction);
    const page = await result.text();
    assert(result.status === 200 && page.includes('Welcome back'), 'Forced MFA login page was not rendered');
    return { url: urlForInteraction, page };
  }

  let forced = await beginForcedLogin('recovery');
  response = await form(`${forced.url}/login`, {
    csrf: csrf(forced.page), login: 'admin', password: 'wrong-password-value', otp: recoveryCodes[0],
  });
  html = await response.text();
  assert(response.status === 401, 'Wrong password was accepted with a recovery code');
  response = await form(`${forced.url}/login`, {
    csrf: csrf(html), login: 'admin', password: 'AuthMe-Change-Me-Now-2026!', otp: recoveryCodes[0],
  });
  assert([302, 303].includes(response.status), 'Recovery code was consumed by the wrong-password attempt');

  forced = await beginForcedLogin('replay');
  response = await form(`${forced.url}/login`, {
    csrf: csrf(forced.page), login: 'admin', password: 'AuthMe-Change-Me-Now-2026!', otp: recoveryCodes[0],
  });
  assert(response.status === 401, 'A consumed recovery code was accepted again');

  console.log(`AuthMe smoke test passed: OIDC/RFC 8414 discovery, protected registration, consent disclosure, PKCE, signed ID and audience-bound access tokens, filtered resource claims, delegated opaque-token introspection, UserInfo, refresh-family replay defense, revocation, device flow, atomic TOTP enrollment, MFA enforcement, one-use recovery${databaseUrl ? ', and authenticated SCIM provisioning/audit' : ''}.`);
} finally {
  await new Promise((resolve) => server.close(resolve));
  await runtime.close();
}
