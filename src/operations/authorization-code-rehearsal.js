import { createHash, randomBytes } from 'node:crypto';

function csrf(html) {
  const match = /name="csrf" value="([^"]+)"/u.exec(html);
  if (!match) throw new Error('Interaction response did not contain a CSRF token');
  return match[1];
}

function action(html, suffix) {
  const match = new RegExp(`action="([^"]+/${suffix})"`, 'u').exec(html);
  if (!match) throw new Error(`Interaction response did not contain a ${suffix} form`);
  return match[1];
}

function updateCookies(response, cookies) {
  const values = response.headers.getSetCookie?.() ?? (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : []);
  for (const value of values) {
    const pair = value.split(';', 1)[0];
    const separator = pair.indexOf('=');
    if (separator > 0) cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}

export async function authorizationCodeRoundTrip({
  baseUrl,
  realm = 'master',
  clientId,
  clientSecret,
  redirectUri,
  username,
  password,
  otp = '',
  scope = 'openid offline_access',
  resource,
  fetch: fetchImplementation = fetch,
}) {
  for (const [name, value] of Object.entries({ baseUrl, clientId, redirectUri, username, password })) {
    if (typeof value !== 'string' || !value) throw new TypeError(`${name} is required for an authorization-code rehearsal`);
  }
  const origin = new URL(baseUrl).origin;
  const callback = new URL(redirectUri);
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('base64url');
  const authorization = new URL(`/realms/${encodeURIComponent(realm)}/protocol/openid-connect/auth`, origin);
  authorization.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callback.href,
    response_type: 'code',
    scope,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state,
    ...(scope.split(' ').includes('offline_access') ? { prompt: 'consent' } : {}),
    ...(resource ? { resource } : {}),
  });
  const cookies = new Map();
  const browserFetch = async (url, options = {}) => {
    const headers = new Headers(options.headers);
    if (cookies.size) headers.set('cookie', [...cookies].map(([name, value]) => `${name}=${value}`).join('; '));
    const response = await fetchImplementation(url, { ...options, headers, redirect: 'manual', signal: AbortSignal.timeout(15_000) });
    updateCookies(response, cookies);
    return response;
  };

  let currentUrl = authorization;
  let response = await browserFetch(currentUrl);
  let returned;
  for (let step = 0; step < 12; step += 1) {
    if ([302, 303].includes(response.status)) {
      const target = new URL(response.headers.get('location'), currentUrl);
      if (target.origin === callback.origin && target.pathname === callback.pathname) {
        returned = target;
        break;
      }
      currentUrl = target;
      response = await browserFetch(currentUrl);
      continue;
    }
    if (response.status !== 200) throw new Error(`Authorization interaction returned HTTP ${response.status}`);
    const html = await response.text();
    const loginAction = /\/login"/u.test(html) ? action(html, 'login') : undefined;
    const confirmAction = /\/confirm"/u.test(html) ? action(html, 'confirm') : undefined;
    if (!loginAction && !confirmAction) throw new Error('Authorization interaction returned an unknown page');
    currentUrl = new URL(loginAction ?? confirmAction, currentUrl);
    const body = loginAction
      ? new URLSearchParams({ csrf: csrf(html), login: username, password, otp })
      : new URLSearchParams({ csrf: csrf(html) });
    response = await browserFetch(currentUrl, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
    });
  }
  if (!returned) throw new Error('Authorization Code flow did not reach the registered callback');
  if (returned.searchParams.get('state') !== state) throw new Error('Authorization response state mismatch');
  const code = returned.searchParams.get('code');
  if (!code) throw new Error(`Authorization failed: ${returned.searchParams.get('error') ?? 'missing code'}`);

  const tokenEndpoint = new URL(`/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`, origin);
  const tokenHeaders = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
  if (clientSecret) tokenHeaders.set('authorization', `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`);
  const tokenResponse = await fetchImplementation(tokenEndpoint, {
    method: 'POST', headers: tokenHeaders, signal: AbortSignal.timeout(15_000),
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: clientId, redirect_uri: callback.href,
      code, code_verifier: verifier, ...(resource ? { resource } : {}),
    }),
  });
  const tokens = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !tokens.access_token) throw new Error(`Token exchange returned HTTP ${tokenResponse.status}`);
  let refreshed = false;
  if (tokens.refresh_token) {
    const refreshResponse = await fetchImplementation(tokenEndpoint, {
      method: 'POST', headers: tokenHeaders, signal: AbortSignal.timeout(15_000),
      body: new URLSearchParams({
        grant_type: 'refresh_token', client_id: clientId, refresh_token: tokens.refresh_token,
        ...(resource ? { resource } : {}),
      }),
    });
    const refreshTokens = await refreshResponse.json().catch(() => ({}));
    if (!refreshResponse.ok || !refreshTokens.access_token) throw new Error(`Refresh exchange returned HTTP ${refreshResponse.status}`);
    refreshed = true;
  }
  return { refreshed };
}
