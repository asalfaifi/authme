const root = document.body.dataset.accountRoot;
const page = document.body.dataset.accountPage;
const actionToken = ['reset', 'verify'].includes(page)
  ? new URLSearchParams(window.location.search).get('token') ?? ''
  : '';
if (actionToken) window.history.replaceState(null, '', window.location.pathname);
let csrf = '';

async function request(path, { method = 'GET', body, csrfToken = csrf } = {}) {
  const headers = new Headers({ accept: 'application/json' });
  if (body !== undefined) headers.set('content-type', 'application/json');
  if (csrfToken) headers.set('x-authme-csrf', csrfToken);
  const response = await fetch(`${root}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  const contentType = response.headers.get('content-type') ?? '';
  const payload = contentType.includes('json') ? await response.json() : null;
  if (!response.ok) throw Object.assign(new Error(payload?.detail || payload?.title || 'The request failed.'), { status: response.status });
  return payload;
}

function status(id, message) {
  const element = document.getElementById(id);
  if (element) element.textContent = message;
}

function formObject(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function button(label, action) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = 'danger';
  element.textContent = label;
  element.addEventListener('click', action);
  return element;
}

function decodeBase64url(value) {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encodeBase64url(value) {
  let binary = '';
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

if (page === 'login') {
  document.getElementById('forgot-password-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    status('forgot-password-status', 'Submitting…');
    try {
      const result = await request('/password-reset', { method: 'POST', body: formObject(event.currentTarget), csrfToken: '' });
      status('forgot-password-status', result.message);
    } catch (error) { status('forgot-password-status', error.message); }
  });
}

if (page === 'reset') {
  document.getElementById('reset-password-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await request('/password-reset/confirm', { method: 'POST', body: { ...formObject(event.currentTarget), token: actionToken }, csrfToken: '' });
      status('action-status', 'Your password was reset. You can return to the account console and sign in.');
      event.currentTarget.reset();
    } catch (error) { status('action-status', error.message); }
  });
}

if (page === 'verify') {
  document.getElementById('verify-email-button')?.addEventListener('click', async () => {
    try {
      await request('/email-verification/confirm', { method: 'POST', body: { token: actionToken }, csrfToken: '' });
      status('action-status', 'Your email address is verified.');
    } catch (error) { status('action-status', error.message); }
  });
}

async function loadPasskeys() {
  const result = await request('/api/passkeys');
  const list = document.getElementById('passkey-list');
  list.replaceChildren();
  for (const passkey of result.passkeys) {
    const item = document.createElement('li');
    const copy = document.createElement('span');
    const name = document.createElement('strong');
    const detail = document.createElement('small');
    name.textContent = passkey.name;
    detail.textContent = `Created ${new Date(passkey.createdAt).toLocaleString()}${passkey.lastUsedAt ? ` · last used ${new Date(passkey.lastUsedAt).toLocaleString()}` : ''}`;
    copy.append(name, detail);
    item.append(copy, button('Remove', async () => {
      try {
        await request(`/api/passkeys/${encodeURIComponent(passkey.id)}`, { method: 'DELETE', body: {} });
        status('passkey-status', 'Passkey removed. Sign in again to continue managing security settings.');
        setTimeout(() => window.location.reload(), 800);
      } catch (error) { status('passkey-status', error.message); }
    }));
    list.append(item);
  }
  if (!result.passkeys.length) status('passkey-status', 'No passkeys are registered.');
}

async function loadSessions() {
  const result = await request('/api/sessions');
  const list = document.getElementById('session-list');
  list.replaceChildren();
  for (const session of result.sessions) {
    const item = document.createElement('li');
    const copy = document.createElement('span');
    const name = document.createElement('strong');
    const detail = document.createElement('small');
    name.textContent = session.kind === 'account-console' ? 'Account console' : 'AuthMe sign-in session';
    if (session.current) name.textContent += ' (this session)';
    const clients = session.clientIds?.length ? ` · ${session.clientIds.join(', ')}` : '';
    const device = session.userAgent ? ` · ${session.userAgent}` : '';
    const source = session.ip ? ` · ${session.ip}` : '';
    detail.textContent = `Last active ${new Date(session.lastSeenAt || session.createdAt).toLocaleString()}${clients}${device}${source}`;
    copy.append(name, detail);
    item.append(copy, button('Revoke', async () => {
      try {
        await request(`/api/sessions/${encodeURIComponent(session.reference)}`, { method: 'DELETE', body: {} });
        if (session.current) window.location.reload();
        else await loadSessions();
      } catch (error) { status('session-status', error.message); }
    }));
    list.append(item);
  }
}

async function initializeConsole() {
  try {
    const session = await request('/api/session');
    csrf = session.csrf;
    document.getElementById('account-summary').textContent = `Signed in as ${session.user.username} in ${session.realm}.`;
    document.getElementById('profile-username').value = session.user.username;
    document.getElementById('profile-email').value = session.user.email;
    document.getElementById('profile-name').value = session.user.name;
    document.getElementById('profile-given-name').value = session.user.givenName;
    document.getElementById('profile-family-name').value = session.user.familyName;
    status('profile-verification', session.user.emailVerified ? 'Email verified.' : 'Email not verified. Saving will send a one-time verification link.');
    status('mfa-summary', session.user.mfaEnabled
      ? `Authenticator enabled · ${session.user.recoveryCodesRemaining} recovery codes remain.`
      : 'No authenticator is enrolled.');
    document.getElementById('totp-disable').hidden = !session.user.mfaEnabled;
    document.getElementById('recovery-regenerate').hidden = !session.user.mfaEnabled;
    await Promise.all([loadPasskeys(), loadSessions()]);
  } catch (error) {
    if (error.status === 401) window.location.reload();
    else {
      const alert = document.getElementById('account-alert');
      alert.hidden = false;
      alert.textContent = error.message;
    }
  }
}

if (page === 'console') {
  document.getElementById('profile-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      const result = await request('/api/profile', { method: 'PATCH', body: formObject(event.currentTarget) });
      status('profile-status', result.message);
    } catch (error) { status('profile-status', error.message); }
  });

  document.getElementById('password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await request('/api/password', { method: 'PUT', body: formObject(event.currentTarget) });
      status('password-status', 'Password changed. Sign in again to continue.');
      event.currentTarget.reset();
      setTimeout(() => window.location.reload(), 800);
    } catch (error) { status('password-status', error.message); }
  });

  document.getElementById('totp-start').addEventListener('click', async () => {
    try {
      const result = await request('/api/mfa/totp', { method: 'POST', body: {} });
      document.getElementById('totp-secret').textContent = result.secret;
      document.getElementById('totp-uri').value = result.provisioningUri;
      document.getElementById('totp-setup').hidden = false;
      status('mfa-status', 'Confirm a current code to finish enrollment.');
    } catch (error) { status('mfa-status', error.message); }
  });

  document.getElementById('totp-confirm-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      const result = await request('/api/mfa/totp/confirm', { method: 'POST', body: formObject(event.currentTarget) });
      const output = document.getElementById('recovery-codes');
      output.textContent = result.recoveryCodes.join('\n');
      output.hidden = false;
      status('mfa-status', 'Authenticator enabled. Save these recovery codes now; they will not be shown again.');
      setTimeout(() => window.location.reload(), 5000);
    } catch (error) { status('mfa-status', error.message); }
  });

  document.getElementById('totp-disable').addEventListener('click', async () => {
    try {
      await request('/api/mfa/totp', { method: 'DELETE', body: {} });
      status('mfa-status', 'Authenticator disabled. Sign in again to continue.');
      setTimeout(() => window.location.reload(), 800);
    } catch (error) { status('mfa-status', error.message); }
  });

  document.getElementById('recovery-regenerate').addEventListener('click', async () => {
    try {
      const result = await request('/api/mfa/recovery-codes', { method: 'POST', body: {} });
      const output = document.getElementById('recovery-codes');
      output.textContent = result.recoveryCodes.join('\n');
      output.hidden = false;
      status('mfa-status', 'Recovery codes replaced. Save these codes now; old codes no longer work.');
      setTimeout(() => window.location.reload(), 5000);
    } catch (error) { status('mfa-status', error.message); }
  });

  document.getElementById('passkey-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      if (!navigator.credentials?.create) throw new Error('This browser does not support passkey registration.');
      const options = await request('/api/passkeys/registration/options', { method: 'POST', body: {} });
      const publicKey = options.publicKey;
      publicKey.challenge = decodeBase64url(publicKey.challenge);
      publicKey.user.id = decodeBase64url(publicKey.user.id);
      publicKey.excludeCredentials = (publicKey.excludeCredentials ?? []).map((credential) => ({ ...credential, id: decodeBase64url(credential.id) }));
      const credential = await navigator.credentials.create({ publicKey });
      const response = {
        id: credential.id,
        rawId: encodeBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: encodeBase64url(credential.response.clientDataJSON),
          attestationObject: encodeBase64url(credential.response.attestationObject),
          transports: credential.response.getTransports?.(),
        },
      };
      await request('/api/passkeys/registration/verify', {
        method: 'POST',
        body: { challengeId: options.challengeId, name: formObject(event.currentTarget).name, response },
      });
      status('passkey-status', 'Passkey registered. Sign in again to continue.');
      setTimeout(() => window.location.reload(), 800);
    } catch (error) { status('passkey-status', error.message); }
  });

  document.getElementById('sessions-refresh').addEventListener('click', () => loadSessions().catch((error) => status('session-status', error.message)));
  document.getElementById('logout-button').addEventListener('click', async () => {
    try { await request('/api/logout', { method: 'POST', body: {} }); } finally { window.location.reload(); }
  });
  initializeConsole();
}
