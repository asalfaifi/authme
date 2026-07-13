function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function shell({ title, realm, body, scripts = '' }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="referrer" content="no-referrer">
  <title>${escapeHtml(title)} · AuthMe</title>
  <link rel="stylesheet" href="/assets/authme.css">
  <link rel="stylesheet" href="/assets/authme-passkeys.css">
</head>
<body>
  <main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
      <header class="brand"><span class="brand-mark" aria-hidden="true">A</span><span>AuthMe</span><span class="realm">${escapeHtml(realm)}</span></header>
      ${body}
    </section>
  </main>
  ${scripts}
</body>
</html>`;
}

function errorBanner(message) {
  return message ? `<div class="alert" role="alert">${escapeHtml(message)}</div>` : '';
}

export function renderLogin({
  realm,
  uid,
  csrfToken,
  clientName,
  login = '',
  error = '',
  federationProviders = [],
}) {
  const federation = federationProviders.map((provider) => `
        <form method="post" action="/realms/${encodeURIComponent(realm)}/interaction/${encodeURIComponent(uid)}/federation/${encodeURIComponent(provider.extensionId)}/${encodeURIComponent(provider.providerId)}">
          <input type="hidden" name="csrf" value="${escapeHtml(provider.csrfToken)}">
          <button class="secondary" type="submit">Continue with ${escapeHtml(provider.displayName)}</button>
        </form>`).join('');
  return shell({
    title: 'Sign in',
    realm,
    body: `<div class="heading"><p class="eyebrow">Secure sign-in</p><h1 id="page-title">Welcome back</h1><p>Continue to <strong>${escapeHtml(clientName)}</strong>.</p></div>
      ${errorBanner(error)}
      <form method="post" action="/realms/${encodeURIComponent(realm)}/interaction/${encodeURIComponent(uid)}/login" autocomplete="on" data-password-login>
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
        <label>Email or username<input name="login" value="${escapeHtml(login)}" autocomplete="username" maxlength="254" required autofocus></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label>
        <label>Authenticator or recovery code <span class="optional">if enabled</span><input name="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="32"></label>
        <button class="primary" type="submit">Sign in securely</button>
      </form>
      <div class="auth-divider" aria-hidden="true"><span>or</span></div>
      <button class="secondary passkey-button" type="button" hidden
        data-passkey-options="/realms/${encodeURIComponent(realm)}/interaction/${encodeURIComponent(uid)}/passkey/options"
        data-passkey-verify="/realms/${encodeURIComponent(realm)}/interaction/${encodeURIComponent(uid)}/passkey">Sign in with a passkey</button>
      <p class="passkey-status" data-passkey-status aria-live="polite"></p>
      ${federation ? `<div class="federation-options" aria-label="Federated sign-in options">${federation}</div>` : ''}
      <p class="fine-print">Protected by PKCE, short-lived sessions, brute-force controls, and auditable access.</p>`,
    scripts: '<script type="module" src="/assets/authme-passkeys.js"></script>',
  });
}

export function renderConsent({ realm, uid, csrfToken, clientName, scopes }) {
  const items = scopes.map((scope) => `<li><span class="scope-icon" aria-hidden="true">✓</span><span><strong>${escapeHtml(scope)}</strong><small>${escapeHtml(scopeDescription(scope))}</small></span></li>`).join('');
  return shell({
    title: 'Authorize application',
    realm,
    body: `<div class="heading"><p class="eyebrow">Authorization request</p><h1 id="page-title">Allow ${escapeHtml(clientName)}?</h1><p>This application is requesting access to:</p></div>
      <ul class="scope-list">${items}</ul>
      <div class="consent-actions">
        <form method="post" action="/realms/${encodeURIComponent(realm)}/interaction/${encodeURIComponent(uid)}/confirm">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}"><button class="primary" type="submit">Allow access</button>
        </form>
        <form method="post" action="/realms/${encodeURIComponent(realm)}/interaction/${encodeURIComponent(uid)}/abort">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}"><button class="secondary" type="submit">Deny</button>
        </form>
      </div>
      <p class="fine-print">You can revoke this consent later. AuthMe never shares your password with applications.</p>`,
  });
}

export function renderError({ realm = 'system', title = 'Request failed', message }) {
  return shell({
    title,
    realm,
    body: `<div class="heading"><p class="eyebrow">AuthMe</p><h1 id="page-title">${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></div><a class="button-link" href="/">Return to AuthMe</a>`,
  });
}

// `form` is trusted markup generated by oidc-provider. All values supplied by
// clients or users are escaped separately before they enter these templates.
export function renderDeviceInput({ realm, form, error = '' }) {
  return shell({
    title: 'Connect a device',
    realm,
    body: `<div class="heading"><p class="eyebrow">Device authorization</p><h1 id="page-title">Enter your device code</h1><p>Use the one-time code shown on the device you are connecting.</p></div>
      ${errorBanner(error)}
      ${form}
      <button class="primary" type="submit" form="op.deviceInputForm">Continue securely</button>
      <p class="fine-print">Only continue if you initiated this request. Device codes expire automatically.</p>`,
  });
}

export function renderDeviceConfirmation({ realm, form, clientName, userCode }) {
  return shell({
    title: 'Confirm device',
    realm,
    body: `<div class="heading"><p class="eyebrow">Device authorization</p><h1 id="page-title">Confirm this device</h1><p><strong>${escapeHtml(clientName)}</strong> is asking you to connect.</p></div>
      <div class="device-code" aria-label="Device code">${escapeHtml(userCode)}</div>
      ${form}
      <div class="consent-actions">
        <button class="primary" type="submit" form="op.deviceConfirmForm">Confirm device</button>
        <button class="secondary" type="submit" form="op.deviceConfirmForm" name="abort" value="yes">Deny</button>
      </div>
      <p class="fine-print">The code must match the one on your device. Deny the request if you do not recognize it.</p>`,
  });
}

export function renderDeviceSuccess({ realm, clientName }) {
  return shell({
    title: 'Device connected',
    realm,
    body: `<div class="heading"><p class="eyebrow">Authorization complete</p><h1 id="page-title">Device connected</h1><p>You approved <strong>${escapeHtml(clientName)}</strong>. You can safely close this page.</p></div>
      <a class="button-link" href="/">Return to AuthMe</a>`,
  });
}

export function renderLogoutConfirmation({ realm, form, clientName }) {
  return shell({
    title: 'Sign out',
    realm,
    body: `<div class="heading"><p class="eyebrow">Session security</p><h1 id="page-title">Sign out now?</h1><p>End your AuthMe session${clientName ? ` for <strong>${escapeHtml(clientName)}</strong>` : ''}.</p></div>
      ${form}
      <div class="consent-actions">
        <button class="primary" type="submit" form="op.logoutForm" name="logout" value="yes">Yes, sign me out</button>
        <button class="secondary" type="submit" form="op.logoutForm">Stay signed in</button>
      </div>
      <p class="fine-print">Signing out prevents this browser session from authorizing new requests.</p>`,
  });
}

export function renderLogoutSuccess({ realm, clientName }) {
  return shell({
    title: 'Signed out',
    realm,
    body: `<div class="heading"><p class="eyebrow">Session ended</p><h1 id="page-title">You are signed out</h1><p>Your AuthMe session${clientName ? ` for <strong>${escapeHtml(clientName)}</strong>` : ''} has ended safely.</p></div>
      <a class="button-link" href="/">Return to AuthMe</a>`,
  });
}

function scopeDescription(scope) {
  if (scope.startsWith('claim:')) return `Share the requested ${scope.slice(6)} identity claim.`;
  if (scope.startsWith('resource:')) return 'Grant this permission for the named protected resource.';
  return {
    openid: 'Confirm your identity with a stable subject identifier.',
    profile: 'Read your name and basic profile information.',
    email: 'Read your email address and verification status.',
    phone: 'Read your phone number and verification status.',
    address: 'Read your saved address information.',
    roles: 'Read your realm and application roles.',
    groups: 'Read your group memberships.',
    offline_access: 'Stay signed in using a rotating refresh token.',
  }[scope] ?? 'Use this delegated permission.';
}

export { escapeHtml };
