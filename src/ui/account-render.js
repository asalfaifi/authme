import { escapeHtml } from './render.js';

function head(title, realm) {
  const root = `/realms/${encodeURIComponent(realm)}/account`;
  return `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="referrer" content="no-referrer">
  <title>${escapeHtml(title)} · AuthMe</title>
  <link rel="stylesheet" href="${root}/assets/account-console.css">`;
}

function shell({ title, realm, body, page = 'account' }) {
  const root = `/realms/${encodeURIComponent(realm)}/account`;
  return `<!doctype html>
<html lang="en">
<head>${head(title, realm)}</head>
<body data-account-page="${escapeHtml(page)}" data-account-root="${root}">
  <main class="account-shell">
    <header class="account-brand"><a href="${root}/"><span aria-hidden="true">A</span> AuthMe</a><small>${escapeHtml(realm)}</small></header>
    ${body}
  </main>
  <script type="module" src="${root}/assets/account-console.js"></script>
</body>
</html>`;
}

export function renderAccountLogin({ realm, error = '' }) {
  const root = `/realms/${encodeURIComponent(realm)}/account`;
  return shell({
    title: 'Your account',
    realm,
    page: 'login',
    body: `<section class="account-card account-login" aria-labelledby="page-title">
      <p class="eyebrow">Account console</p>
      <h1 id="page-title">Manage your AuthMe account</h1>
      <p>Continue through AuthMe's protected sign-in to update your profile and security settings.</p>
      ${error ? `<div class="alert" role="alert">${escapeHtml(error)}</div>` : ''}
      <form method="post" action="${root}/login">
        <button class="primary" type="submit">Continue securely</button>
      </form>
      <details>
        <summary>Forgot your password?</summary>
        <form id="forgot-password-form" class="stack">
          <label>Email address<input name="email" type="email" maxlength="254" autocomplete="email" required></label>
          <button class="secondary" type="submit">Send reset instructions</button>
        </form>
        <p id="forgot-password-status" class="status" role="status"></p>
      </details>
      <p class="fine-print">The response is identical whether or not an account exists. Reset links expire and can be used once.</p>
    </section>`,
  });
}

export function renderAccountConsole({ realm }) {
  const root = `/realms/${encodeURIComponent(realm)}/account`;
  return shell({
    title: 'Your account',
    realm,
    page: 'console',
    body: `<div class="account-layout">
      <nav class="account-nav" aria-label="Account settings">
        <a href="#profile">Profile</a><a href="#password">Password</a><a href="#mfa">MFA</a><a href="#passkeys">Passkeys</a><a href="#sessions">Sessions</a>
        <button id="logout-button" class="link-button" type="button">Sign out</button>
      </nav>
      <div class="account-content">
        <header><p class="eyebrow">Personal settings</p><h1 id="page-title">Your account</h1><p id="account-summary">Loading your protected account…</p></header>
        <div id="account-alert" class="alert" role="alert" hidden></div>

        <section id="profile" class="account-card"><h2>Profile</h2>
          <form id="profile-form" class="form-grid">
            <label>Username<input id="profile-username" disabled></label>
            <label>Email<input id="profile-email" name="email" type="email" maxlength="254" required></label>
            <label>Display name<input id="profile-name" name="name" maxlength="255" required></label>
            <label>Given name<input id="profile-given-name" name="givenName" maxlength="255"></label>
            <label>Family name<input id="profile-family-name" name="familyName" maxlength="255"></label>
            <p id="profile-verification" class="status"></p>
            <button class="primary" type="submit">Save profile</button>
          </form>
          <p id="profile-status" class="status" role="status"></p>
        </section>

        <section id="password" class="account-card"><h2>Change password</h2>
          <form id="password-form" class="stack">
            <label>Current password<input name="currentPassword" type="password" maxlength="1024" autocomplete="current-password" required></label>
            <label>New password<input name="newPassword" type="password" minlength="12" maxlength="1024" autocomplete="new-password" required></label>
            <button class="primary" type="submit">Change password</button>
          </form><p id="password-status" class="status" role="status"></p>
        </section>

        <section id="mfa" class="account-card"><h2>Authenticator and recovery codes</h2>
          <p id="mfa-summary">Loading…</p>
          <div class="button-row"><button id="totp-start" class="secondary" type="button">Enroll or replace authenticator</button><button id="totp-disable" class="danger" type="button">Disable authenticator</button></div>
          <div id="totp-setup" class="secret-panel" hidden><p>Enter this secret or provisioning URI in your authenticator.</p><code id="totp-secret"></code><textarea id="totp-uri" readonly></textarea>
            <form id="totp-confirm-form" class="stack"><label>Six-digit code<input name="token" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label><button class="primary" type="submit">Confirm authenticator</button></form>
          </div>
          <button id="recovery-regenerate" class="secondary" type="button">Regenerate recovery codes</button>
          <pre id="recovery-codes" class="recovery-codes" hidden></pre><p id="mfa-status" class="status" role="status"></p>
        </section>

        <section id="passkeys" class="account-card"><h2>Passkeys</h2><p>Passkeys use user verification and are scoped to this AuthMe origin.</p>
          <form id="passkey-form" class="inline-form"><label>Name<input name="name" maxlength="100" value="My passkey" required></label><button class="primary" type="submit">Register passkey</button></form>
          <ul id="passkey-list" class="item-list"></ul><p id="passkey-status" class="status" role="status"></p>
        </section>

        <section id="sessions" class="account-card"><h2>Active sessions and devices</h2><button id="sessions-refresh" class="secondary" type="button">Refresh</button>
          <ul id="session-list" class="item-list"></ul><p id="session-status" class="status" role="status"></p>
        </section>
      </div>
    </div>`,
  });
}

export function renderAccountAction({ realm, type }) {
  const reset = type === 'password-reset';
  return shell({
    title: reset ? 'Reset password' : 'Verify email',
    realm,
    page: reset ? 'reset' : 'verify',
    body: `<section class="account-card account-login" aria-labelledby="page-title">
      <p class="eyebrow">Account security</p>
      <h1 id="page-title">${reset ? 'Choose a new password' : 'Verify your email address'}</h1>
      ${reset ? `<form id="reset-password-form" class="stack"><label>New password<input name="newPassword" type="password" minlength="12" maxlength="1024" autocomplete="new-password" required></label><button class="primary" type="submit">Reset password</button></form>` : '<button id="verify-email-button" class="primary" type="button">Verify email</button>'}
      <p id="action-status" class="status" role="status"></p>
    </section>`,
  });
}
