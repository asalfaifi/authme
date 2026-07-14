import { escapeHtml } from './render.js';

const icons = Object.freeze({
  overview: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z"/></svg>',
  users: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM8 12a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm8 1c-3.3 0-6 1.7-6 4v3h12v-3c0-2.3-2.7-4-6-4ZM8 14c-3.3 0-6 1.5-6 3.5V20h6v-3c0-1.1.5-2.1 1.4-3H8Z"/></svg>',
  clients: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3a5 5 0 0 0-1 9.9V21h4v-3h3v-3h3v-3.1A5 5 0 1 0 8 3Zm0 3.5a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3Z"/></svg>',
  federation: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a4 4 0 0 0-1 7.9v2.3l-4 2.3a4 4 0 1 0 2 3.5v-.1l4-2.3 4 2.3v.1a4 4 0 1 0 2-3.5l-4-2.3V9.9A4 4 0 0 0 12 2Z"/></svg>',
  audit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5.1 3.4 9.8 8 11 4.6-1.2 8-5.9 8-11V5l-8-3Zm3.7 8.2-4.3 4.3a1 1 0 0 1-1.4 0l-2-2 1.4-1.4 1.3 1.3 3.6-3.6 1.4 1.4Z"/></svg>',
  system: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m19.4 13 .1-1-.1-1 2-1.5-2-3.4-2.4 1a8 8 0 0 0-1.7-1L15 3.5h-4L10.7 6A8 8 0 0 0 9 7.1l-2.4-1-2 3.4 2 1.5-.1 1 .1 1-2 1.5 2 3.4 2.4-1a8 8 0 0 0 1.7 1l.3 2.6h4l.3-2.6a8 8 0 0 0 1.7-1l2.4 1 2-3.4-2-1.5ZM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7Z"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 18 6-6-6-6"/></svg>',
  logout: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 3H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h6v-2H4V5h6V3Zm4.6 4.6L16 9l-2 2H7v2h7l2 2-1.4 1.4L20 12l-5.4-4.4Z"/></svg>',
});

function realmOptions(realms) {
  const names = Array.isArray(realms)
    ? realms.map((realm) => typeof realm === 'string' ? realm : realm?.name).filter(Boolean)
    : [];
  if (!names.length) return '<option value="master">master</option>';
  return names.map((realm) => `<option value="${escapeHtml(realm)}">${escapeHtml(realm)}</option>`).join('');
}

function documentHead(title) {
  return `<meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="referrer" content="no-referrer">
  <title>${escapeHtml(title)} · AuthMe</title>
  <link rel="stylesheet" href="/admin/assets/admin-console.css">`;
}

export function renderAdminLogin({ realms = [], error = '' } = {}) {
  const errorMarkup = error
    ? `<div class="login-alert" role="alert"><span aria-hidden="true">!</span><p>${escapeHtml(error)}</p></div>`
    : '';
  return `<!doctype html>
<html lang="en">
<head>
  ${documentHead('Administration sign in')}
</head>
<body class="admin-login-page">
  <main class="admin-login-shell">
    <section class="admin-login-story" aria-label="AuthMe administration">
      <a class="login-brand" href="/" aria-label="AuthMe home">
        <span class="brand-glyph" aria-hidden="true"><span>A</span></span>
        <span>AuthMe</span>
      </a>
      <div class="login-story-copy">
        <p class="kicker">Identity operations, clearly managed</p>
        <h1>One secure place for your identity infrastructure.</h1>
        <p>Manage people, applications, federation, and security events without exposing deployment credentials to the browser.</p>
      </div>
      <ul class="login-assurances" aria-label="Security protections">
        <li><span aria-hidden="true">✓</span>HttpOnly administrator session</li>
        <li><span aria-hidden="true">✓</span>Realm-scoped access</li>
        <li><span aria-hidden="true">✓</span>Audited security changes</li>
      </ul>
    </section>
    <section class="admin-login-card" aria-labelledby="login-title">
      <div class="login-card-heading">
        <span class="mobile-brand-mark" aria-hidden="true">A</span>
        <p class="kicker">Administration console</p>
        <h2 id="login-title">Welcome back</h2>
        <p>Choose the realm you want to manage, then continue through AuthMe's protected sign-in.</p>
      </div>
      ${errorMarkup}
      <form class="admin-login-form" method="post" action="/admin/ui/login" autocomplete="on">
        <label for="admin-realm">Realm</label>
        <div class="field-control select-control">
          <select id="admin-realm" name="realm" required autofocus>${realmOptions(realms)}</select>
        </div>
        <button class="button button-primary button-large" type="submit">Continue securely</button>
      </form>
      <p class="login-fine-print">Your session stays in a protected, HttpOnly cookie. AuthMe never places administration tokens in browser storage.</p>
    </section>
  </main>
</body>
</html>`;
}

function navItem(page, label, icon, current = false) {
  return `<a class="sidebar-link" href="#${page}" data-nav-page="${page}" aria-label="${escapeHtml(label)}"${current ? ' aria-current="page"' : ''}>
    <span class="sidebar-icon">${icons[icon]}</span><span class="sidebar-label">${escapeHtml(label)}</span>
  </a>`;
}

export function renderAdminConsole() {
  return `<!doctype html>
<html lang="en">
<head>
  ${documentHead('Administration')}
</head>
<body class="admin-console-page">
  <a class="skip-link" href="#console-main">Skip to main content</a>
  <aside class="admin-sidebar" aria-label="Administration navigation">
    <a class="sidebar-brand" href="#overview" aria-label="AuthMe administration home">
      <span class="brand-glyph" aria-hidden="true"><span>A</span></span>
      <span class="brand-copy"><strong>AuthMe</strong><small>Administration</small></span>
    </a>

    <form id="realm-switch-form" class="realm-switcher" method="post" action="/admin/ui/switch-realm">
      <input id="realm-switch-csrf" type="hidden" name="csrf" value="">
      <label for="realm-switch"><span class="sidebar-label">Current realm</span></label>
      <select id="realm-switch" name="realm" aria-label="Current realm"></select>
    </form>

    <nav class="sidebar-nav" aria-label="Console pages">
      <p class="sidebar-section-label">Workspace</p>
      ${navItem('overview', 'Overview', 'overview', true)}
      ${navItem('users', 'Users', 'users')}
      ${navItem('clients', 'Clients & APIs', 'clients')}
      ${navItem('federation', 'Federation', 'federation')}
      <p class="sidebar-section-label sidebar-section-secondary">Operations</p>
      ${navItem('audit', 'Audit trail', 'audit')}
      ${navItem('system', 'System & settings', 'system')}
    </nav>

    <div class="sidebar-operator">
      <span id="operator-avatar" class="operator-avatar" aria-hidden="true">A</span>
      <span class="operator-copy sidebar-label"><strong id="operator-name">Administrator</strong><small id="operator-email">Secure session</small></span>
      <form id="logout-form" method="post" action="/admin/ui/logout">
        <input id="logout-csrf" type="hidden" name="csrf" value="">
        <button class="icon-button sidebar-logout" type="submit" aria-label="Sign out">${icons.logout}</button>
      </form>
    </div>
  </aside>

  <div class="admin-workspace">
    <header class="workspace-header">
      <div>
        <p id="page-eyebrow" class="page-eyebrow">Workspace</p>
        <h1 id="page-title">Overview</h1>
      </div>
      <div id="page-actions" class="page-actions"></div>
    </header>
    <main id="console-main" class="workspace-main" tabindex="-1">
      <div id="page-content" class="page-content" aria-live="polite" aria-busy="true">
        <div class="initial-loader" role="status"><span class="spinner" aria-hidden="true"></span><span>Opening your secure workspace…</span></div>
      </div>
    </main>
    <footer class="workspace-footer"><span>AuthMe identity infrastructure</span><span id="footer-context">Secure administrator session</span></footer>
  </div>

  <div id="toast-region" class="toast-region" role="status" aria-live="polite" aria-atomic="true"></div>

  <dialog id="user-dialog" class="admin-dialog dialog-wide" aria-labelledby="user-dialog-title">
    <form id="user-form" method="dialog">
      <header class="dialog-header">
        <div><p class="dialog-kicker">Directory</p><h2 id="user-dialog-title">Create user</h2><p id="user-dialog-copy">Add an identity to this realm.</p></div>
        <button class="icon-button dialog-close" type="button" data-close-dialog="user-dialog" aria-label="Close">×</button>
      </header>
      <div class="dialog-body form-stack">
        <div class="form-grid two-columns">
          <label id="user-username-field">Username<input id="user-username" name="username" maxlength="128" pattern="[a-zA-Z0-9._@+\-]+" autocomplete="off"></label>
          <label>Email address<input id="user-email" name="email" type="email" maxlength="254" required></label>
          <label id="user-password-field">Temporary password<input id="user-password" name="password" type="password" minlength="12" maxlength="1024" autocomplete="new-password"></label>
          <label>Display name<input id="user-name" name="name" maxlength="255"></label>
          <label>Given name<input id="user-given-name" name="givenName" maxlength="255"></label>
          <label>Family name<input id="user-family-name" name="familyName" maxlength="255"></label>
        </div>
        <div class="check-row">
          <label class="check-control"><input id="user-enabled" name="enabled" type="checkbox"><span>Account enabled</span></label>
          <label class="check-control"><input id="user-email-verified" name="emailVerified" type="checkbox"><span>Email verified</span></label>
        </div>
        <div class="form-grid two-columns">
          <label>Realm roles <span class="field-hint">Comma separated</span><input id="user-roles" name="roles" placeholder="member, analyst"></label>
          <label>Groups <span class="field-hint">Comma separated</span><input id="user-groups" name="groups" placeholder="/engineering, /platform"></label>
        </div>
        <label>Client roles <span class="field-hint">JSON object of client IDs to role arrays</span><textarea id="user-client-roles" name="clientRoles" rows="4" spellcheck="false" placeholder='{"orders-api":["orders.read"]}'></textarea></label>
        <p id="user-form-error" class="form-error" role="alert" hidden></p>
      </div>
      <footer class="dialog-footer">
        <button class="button button-secondary" type="button" data-close-dialog="user-dialog">Cancel</button>
        <button id="user-submit" class="button button-primary" type="submit">Create user</button>
      </footer>
    </form>
  </dialog>

  <dialog id="password-dialog" class="admin-dialog" aria-labelledby="password-dialog-title">
    <form id="password-form" method="dialog">
      <header class="dialog-header">
        <div><p class="dialog-kicker">Account security</p><h2 id="password-dialog-title">Reset password</h2><p>Set a new password and clear current lockout counters.</p></div>
        <button class="icon-button dialog-close" type="button" data-close-dialog="password-dialog" aria-label="Close">×</button>
      </header>
      <div class="dialog-body form-stack">
        <label>New password<input id="reset-password" type="password" minlength="12" maxlength="1024" autocomplete="new-password" required></label>
        <label>Confirm new password<input id="reset-password-confirm" type="password" minlength="12" maxlength="1024" autocomplete="new-password" required></label>
        <p id="password-form-error" class="form-error" role="alert" hidden></p>
      </div>
      <footer class="dialog-footer">
        <button class="button button-secondary" type="button" data-close-dialog="password-dialog">Cancel</button>
        <button class="button button-primary" type="submit">Reset password</button>
      </footer>
    </form>
  </dialog>

  <dialog id="totp-dialog" class="admin-dialog" aria-labelledby="totp-dialog-title">
    <form id="totp-form" method="dialog">
      <header class="dialog-header">
        <div><p class="dialog-kicker">Authenticator app</p><h2 id="totp-dialog-title">Finish TOTP enrollment</h2><p>Enter this secret in the user's authenticator, then confirm a current code.</p></div>
        <button class="icon-button dialog-close" type="button" data-close-dialog="totp-dialog" aria-label="Close">×</button>
      </header>
      <div class="dialog-body form-stack">
        <div class="secret-panel"><span>Setup secret</span><code id="totp-secret"></code><button id="copy-totp-secret" class="button button-small button-secondary" type="button">Copy secret</button></div>
        <label>Provisioning URI<textarea id="totp-uri" rows="3" readonly></textarea></label>
        <label>Six-digit code<input id="totp-token" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>
        <p id="totp-form-error" class="form-error" role="alert" hidden></p>
      </div>
      <footer class="dialog-footer">
        <button class="button button-secondary" type="button" data-close-dialog="totp-dialog">Finish later</button>
        <button class="button button-primary" type="submit">Confirm and enable</button>
      </footer>
    </form>
  </dialog>

  <dialog id="client-dialog" class="admin-dialog dialog-wide" aria-labelledby="client-dialog-title">
    <form id="client-form" method="dialog">
      <header class="dialog-header">
        <div><p class="dialog-kicker">Dynamic registration</p><h2 id="client-dialog-title">Register application</h2><p>AuthMe will use a short-lived, one-use authorization for this registration only.</p></div>
        <button class="icon-button dialog-close" type="button" data-close-dialog="client-dialog" aria-label="Close">×</button>
      </header>
      <div class="dialog-body form-stack">
        <div class="form-grid two-columns">
          <label>Application name<input id="client-name" maxlength="100" required></label>
          <label>Application type<select id="client-type"><option value="web">Web application</option><option value="native">Native application</option></select></label>
        </div>
        <label>Redirect URIs <span class="field-hint">One exact URI per line</span><textarea id="client-redirects" rows="4" required placeholder="https://app.example.com/oidc/callback"></textarea></label>
        <label>Browser origins <span class="field-hint">Optional; one exact origin per line</span><textarea id="client-origins" rows="3" placeholder="https://app.example.com"></textarea></label>
        <label>Requested scopes <span class="field-hint">Space separated</span><input id="client-scopes" value="openid profile email"></label>
        <div class="check-row">
          <label class="check-control"><input id="client-public" type="checkbox"><span>Public client (no secret)</span></label>
          <label class="check-control"><input id="client-refresh" type="checkbox" checked><span>Refresh tokens</span></label>
          <label class="check-control"><input id="client-device" type="checkbox"><span>Device flow</span></label>
        </div>
        <p id="client-form-error" class="form-error" role="alert" hidden></p>
      </div>
      <footer class="dialog-footer">
        <button class="button button-secondary" type="button" data-close-dialog="client-dialog">Cancel</button>
        <button class="button button-primary" type="submit">Register securely</button>
      </footer>
    </form>
  </dialog>

  <dialog id="identity-dialog" class="admin-dialog" aria-labelledby="identity-dialog-title">
    <form id="identity-form" method="dialog">
      <header class="dialog-header">
        <div><p class="dialog-kicker">Federated identity</p><h2 id="identity-dialog-title">Link external identity</h2><p>Use the immutable subject confirmed by the upstream provider.</p></div>
        <button class="icon-button dialog-close" type="button" data-close-dialog="identity-dialog" aria-label="Close">×</button>
      </header>
      <div class="dialog-body form-stack">
        <label>Provider ID<input id="identity-provider" maxlength="64" required></label>
        <label>Exact issuer<input id="identity-issuer" maxlength="2048" required></label>
        <label>External subject<input id="identity-subject" maxlength="2048" required></label>
        <p id="identity-form-error" class="form-error" role="alert" hidden></p>
      </div>
      <footer class="dialog-footer">
        <button class="button button-secondary" type="button" data-close-dialog="identity-dialog">Cancel</button>
        <button class="button button-primary" type="submit">Link identity</button>
      </footer>
    </form>
  </dialog>

  <dialog id="credential-dialog" class="admin-dialog" aria-labelledby="credential-dialog-title">
    <div>
      <header class="dialog-header">
        <div><p class="dialog-kicker">One-time disclosure</p><h2 id="credential-dialog-title">Save these credentials now</h2><p id="credential-dialog-copy">Secrets will be cleared when this window closes.</p></div>
        <button class="icon-button dialog-close" type="button" data-close-dialog="credential-dialog" aria-label="Close">×</button>
      </header>
      <div id="credential-content" class="dialog-body credential-content"></div>
      <footer class="dialog-footer"><button class="button button-primary" type="button" data-close-dialog="credential-dialog">I have saved them</button></footer>
    </div>
  </dialog>

  <dialog id="confirm-dialog" class="admin-dialog dialog-compact" aria-labelledby="confirm-dialog-title">
    <form method="dialog">
      <header class="dialog-header confirm-header">
        <span class="confirm-icon" aria-hidden="true">!</span>
        <div><h2 id="confirm-dialog-title">Confirm change</h2><p id="confirm-dialog-copy">This action affects account security.</p></div>
      </header>
      <footer class="dialog-footer">
        <button class="button button-secondary" value="cancel">Cancel</button>
        <button id="confirm-dialog-action" class="button button-danger" value="confirm">Confirm</button>
      </footer>
    </form>
  </dialog>

  <noscript><div class="noscript-message">The AuthMe administration console requires JavaScript. Your identity services continue to operate normally.</div></noscript>
  <script type="module" src="/admin/assets/admin-console.js"></script>
</body>
</html>`;
}
