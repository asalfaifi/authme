const pageContent = document.getElementById('page-content');
const pageTitle = document.getElementById('page-title');
const pageEyebrow = document.getElementById('page-eyebrow');
const pageActions = document.getElementById('page-actions');
const main = document.getElementById('console-main');

const PAGES = Object.freeze({
  overview: { title: 'Overview', eyebrow: 'Workspace' },
  users: { title: 'Users', eyebrow: 'Directory' },
  clients: { title: 'Clients & APIs', eyebrow: 'Applications' },
  federation: { title: 'Federation & provisioning', eyebrow: 'Identity sources' },
  audit: { title: 'Audit trail', eyebrow: 'Operations' },
  system: { title: 'System & settings', eyebrow: 'Configuration' },
});

const PAGE_PERMISSIONS = Object.freeze({
  users: 'users.read',
  clients: 'configuration.read',
  federation: 'configuration.read',
  audit: 'audit.read',
  system: 'configuration.read',
});

const state = {
  session: null,
  realm: '',
  csrf: '',
  realms: [],
  configuration: null,
  usersOffset: 0,
  usersLimit: 50,
  auditOffset: 0,
  auditLimit: 50,
  editingUser: null,
  actionUserId: null,
  totpUserId: null,
  identityUserId: null,
};

let navigationController;

function element(tagName, options = {}, children = []) {
  const node = document.createElement(tagName);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = String(options.text ?? '');
  if (options.attributes) {
    for (const [name, value] of Object.entries(options.attributes)) {
      if (value !== undefined && value !== null) node.setAttribute(name, String(value));
    }
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child) node.append(child);
  }
  return node;
}

function append(parent, ...children) {
  for (const child of children.flat()) if (child) parent.append(child);
  return parent;
}

function text(value, fallback = '—') {
  if (value === undefined || value === null || value === '') return fallback;
  return String(value);
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function can(permission) {
  const permissions = list(state.session?.permissions);
  return permissions.includes('*') || permissions.includes(permission);
}

function initials(value) {
  const words = String(value ?? '').trim().split(/\s+/).filter(Boolean);
  if (!words.length) return 'A';
  return words.slice(0, 2).map((word) => word[0]).join('').toUpperCase();
}

function formatDate(value, { dateOnly = false } = {}) {
  if (!value) return 'Never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return text(value);
  return new Intl.DateTimeFormat(undefined, dateOnly
    ? { dateStyle: 'medium' }
    : { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function relativeDate(value) {
  if (!value) return 'Never';
  const milliseconds = new Date(value).getTime() - Date.now();
  if (!Number.isFinite(milliseconds)) return formatDate(value);
  const ranges = [
    ['year', 31_536_000_000],
    ['month', 2_592_000_000],
    ['day', 86_400_000],
    ['hour', 3_600_000],
    ['minute', 60_000],
  ];
  for (const [unit, size] of ranges) {
    if (Math.abs(milliseconds) >= size) {
      return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(Math.round(milliseconds / size), unit);
    }
  }
  return 'Just now';
}

function humanError(error) {
  if (error?.name === 'AbortError') return 'The request was cancelled.';
  return error?.detail || error?.message || 'The request could not be completed.';
}

class ApiError extends Error {
  constructor(message, { status, detail, body } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
    this.body = body;
  }
}

async function requestJson(path, {
  method = 'GET',
  body,
  signal,
  ephemeralRegistrationToken,
  redirectOnUnauthorized = true,
} = {}) {
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin) {
    throw new ApiError('AuthMe refused to send credentials to a different origin.');
  }

  const upperMethod = method.toUpperCase();
  const mutating = !['GET', 'HEAD', 'OPTIONS'].includes(upperMethod);
  const headers = new Headers({ accept: 'application/json' });
  if (body !== undefined) headers.set('content-type', 'application/json');
  if (mutating && state.csrf) headers.set('x-authme-csrf', state.csrf);
  if (ephemeralRegistrationToken) {
    // This is a one-use DCR authorization returned by the server. It is kept in
    // this call frame only and is never browser storage or administrator auth.
    headers.set('authorization', `Bearer ${ephemeralRegistrationToken}`);
  }

  const response = await fetch(url, {
    method: upperMethod,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'follow',
    signal,
  });

  if (response.status === 401 && redirectOnUnauthorized && !ephemeralRegistrationToken) {
    window.location.replace('/admin/');
    throw new ApiError('Your administrator session has ended.', { status: 401 });
  }
  if (response.status === 204) return null;

  const contentType = response.headers.get('content-type') ?? '';
  let payload;
  if (contentType.includes('json')) {
    payload = await response.json().catch(() => null);
  } else {
    payload = await response.text().catch(() => '');
  }
  if (!response.ok) {
    const problem = record(payload);
    throw new ApiError(problem.title || `Request failed (${response.status})`, {
      status: response.status,
      detail: problem.detail || problem.error_description || (typeof payload === 'string' ? payload : undefined),
      body: payload,
    });
  }
  return payload;
}

function toast(message, type = 'success') {
  const region = document.getElementById('toast-region');
  const item = element('div', { className: `toast${type === 'error' ? ' error' : ''}`, text: message });
  region.append(item);
  window.setTimeout(() => item.remove(), 5_000);
}

function actionButton(label, handler, variant = 'secondary') {
  const button = element('button', {
    className: `button button-${variant}`,
    text: label,
    attributes: { type: 'button' },
  });
  button.addEventListener('click', () => {
    Promise.resolve(handler(button)).catch((error) => {
      if (error?.name !== 'AbortError') toast(humanError(error), 'error');
    });
  });
  return button;
}

async function busy(button, label, operation) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try {
    return await operation();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function openDialog(id) {
  const dialog = document.getElementById(id);
  if (!dialog) return;
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
}

function closeDialog(id) {
  const dialog = document.getElementById(id);
  if (!dialog) return;
  if (typeof dialog.close === 'function' && dialog.open) dialog.close();
  else dialog.removeAttribute('open');
  if (id === 'credential-dialog') document.getElementById('credential-content').replaceChildren();
}

function askConfirmation({ title, message, action = 'Confirm' }) {
  const dialog = document.getElementById('confirm-dialog');
  document.getElementById('confirm-dialog-title').textContent = title;
  document.getElementById('confirm-dialog-copy').textContent = message;
  document.getElementById('confirm-dialog-action').textContent = action;
  return new Promise((resolve) => {
    const finished = () => {
      dialog.removeEventListener('close', finished);
      dialog.removeEventListener('cancel', cancelled);
      resolve(dialog.returnValue === 'confirm');
    };
    const cancelled = (event) => {
      event.preventDefault();
      dialog.returnValue = 'cancel';
      if (typeof dialog.close === 'function' && dialog.open) dialog.close('cancel');
      else {
        dialog.removeAttribute('open');
        finished();
      }
    };
    // A dialog retains its previous returnValue. Reset it before every open so
    // dismissing a later destructive prompt can never reuse an earlier confirm.
    dialog.returnValue = 'cancel';
    dialog.addEventListener('close', finished);
    dialog.addEventListener('cancel', cancelled);
    openDialog('confirm-dialog');
  });
}

async function copyValue(value) {
  if (!navigator.clipboard?.writeText) throw new Error('Clipboard access is not available in this browser.');
  await navigator.clipboard.writeText(String(value));
  toast('Copied to clipboard.');
}

function showOneTimeValues({ title, description, values }) {
  document.getElementById('credential-dialog-title').textContent = title;
  document.getElementById('credential-dialog-copy').textContent = description;
  const content = document.getElementById('credential-content');
  content.replaceChildren();
  for (const [label, rawValue] of values) {
    if (rawValue === undefined || rawValue === null || rawValue === '') continue;
    const value = String(rawValue);
    const copy = actionButton('Copy', (button) => busy(button, 'Copying…', () => copyValue(value)), 'secondary');
    copy.classList.add('button-small');
    const valueRow = element('div', { className: 'credential-value' }, [
      element('code', { text: value }),
      copy,
    ]);
    content.append(element('div', { className: 'credential-field' }, [
      element('span', { text: label }),
      valueRow,
    ]));
  }
  openDialog('credential-dialog');
}

function badge(label, tone = 'neutral') {
  return element('span', { className: `badge ${tone}`, text: label });
}

function tagList(values, empty = 'None assigned') {
  const container = element('div', { className: 'tag-list' });
  if (!list(values).length) container.append(element('span', { className: 'badge neutral', text: empty }));
  else for (const value of values) container.append(element('span', { className: 'tag', text: value }));
  return container;
}

function setHeader(page, actions = []) {
  const metadata = PAGES[page] ?? PAGES.overview;
  pageTitle.textContent = metadata.title;
  pageEyebrow.textContent = metadata.eyebrow;
  document.title = `${metadata.title} · AuthMe`;
  pageActions.replaceChildren(...actions);
  for (const link of document.querySelectorAll('[data-nav-page]')) {
    if (link.getAttribute('data-nav-page') === page) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

function setPage(node) {
  pageContent.replaceChildren(node);
  pageContent.setAttribute('aria-busy', 'false');
}

function renderLoading() {
  pageContent.setAttribute('aria-busy', 'true');
  setPage(element('div', { className: 'skeleton-stack', attributes: { 'aria-label': 'Loading page' } }, [
    element('div', { className: 'skeleton short' }),
    element('div', { className: 'skeleton' }),
    element('div', { className: 'skeleton' }),
  ]));
  pageContent.setAttribute('aria-busy', 'true');
}

function renderErrorState(error, retry) {
  const retryButton = actionButton('Try again', retry, 'primary');
  setPage(element('section', { className: 'error-state', attributes: { role: 'alert' } }, [
    element('div', {}, [
      element('span', { className: 'error-state-icon', text: '!' }),
      element('h2', { text: 'This page could not be loaded' }),
      element('p', { text: humanError(error) }),
      retryButton,
    ]),
  ]));
}

function renderPermissionDenied(permission) {
  setPage(element('section', { className: 'error-state' }, [
    element('div', {}, [
      element('span', { className: 'error-state-icon', text: '○' }),
      element('h2', { text: 'This page is outside your administrator grant' }),
      element('p', { text: `The current realm grant does not include ${permission}. Ask a realm administrator to review your access if you need this workspace.` }),
      actionButton('Return to overview', () => { window.location.hash = 'overview'; }, 'primary'),
    ]),
  ]));
}

function contentCard(title, subtitle, body, action) {
  const headingCopy = element('div', {}, [element('h2', { text: title })]);
  if (subtitle) headingCopy.append(element('p', { text: subtitle }));
  const header = element('header', { className: 'card-header' }, [headingCopy]);
  if (action) header.append(action);
  return element('section', { className: 'content-card' }, [header, body]);
}

function emptyState(title, message, action) {
  const children = [
    element('span', { className: 'empty-icon', text: 'A' }),
    element('h3', { text: title }),
    element('p', { text: message }),
  ];
  if (action) children.push(action);
  return element('div', { className: 'empty-state' }, children);
}

function callout(title, message, tone = '') {
  return element('div', { className: `callout${tone ? ` ${tone}` : ''}` }, [
    element('span', { className: 'callout-icon', text: tone === 'success' ? '✓' : 'i' }),
    element('div', {}, [element('strong', { text: title }), element('span', { text: message })]),
  ]);
}

function descriptionItem(label, valueNode) {
  return element('div', { className: 'description-item' }, [
    element('dt', { text: label }),
    element('dd', typeof valueNode === 'string' ? { text: valueNode } : {}, typeof valueNode === 'string' ? [] : [valueNode]),
  ]);
}

function parseRoute() {
  const route = window.location.hash.replace(/^#/, '') || 'overview';
  const [page, id] = route.split('/');
  return { page: PAGES[page] ? page : 'overview', id: page === 'users' ? id : undefined };
}

async function loadConfiguration({ signal, refresh = false } = {}) {
  if (state.configuration && !refresh) return state.configuration;
  state.configuration = await requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/configuration`,
    { signal },
  );
  return state.configuration;
}

async function navigate({ focus = true } = {}) {
  navigationController?.abort();
  navigationController = new AbortController();
  const { signal } = navigationController;
  const route = parseRoute();
  setHeader(route.page);
  const permission = PAGE_PERMISSIONS[route.page];
  if (permission && !can(permission)) {
    renderPermissionDenied(permission);
    return;
  }
  renderLoading();
  try {
    if (route.page === 'overview') await renderOverview(signal);
    else if (route.page === 'users' && route.id) await renderUserDetail(route.id, signal);
    else if (route.page === 'users') await renderUsers(signal);
    else if (route.page === 'clients') await renderClients(signal);
    else if (route.page === 'federation') await renderFederation(signal);
    else if (route.page === 'audit') await renderAudit(signal);
    else if (route.page === 'system') await renderSystem(signal);
    if (focus) main.focus({ preventScroll: true });
  } catch (error) {
    if (error?.name !== 'AbortError') renderErrorState(error, () => navigate());
  }
}

function statCard(label, value, detail, tone = '') {
  return element('article', { className: 'stat-card' }, [
    element('div', {}, [
      element('span', { className: 'stat-label', text: label }),
      element('strong', { className: 'stat-value', text: value }),
      element('span', { className: 'stat-detail', text: detail }),
    ]),
    element('span', { className: `stat-icon${tone ? ` ${tone}` : ''}`, text: tone === 'success' ? '✓' : '•' }),
  ]);
}

async function renderOverview(signal) {
  const [configuration, users, audit, health] = await Promise.all([
    can('configuration.read') ? loadConfiguration({ signal }) : Promise.resolve(null),
    can('users.read')
      ? requestJson(`/admin/v1/realms/${encodeURIComponent(state.realm)}/users?limit=5&offset=0`, { signal })
      : Promise.resolve({ users: [] }),
    can('audit.read')
      ? requestJson(`/admin/v1/realms/${encodeURIComponent(state.realm)}/audit?limit=6&offset=0`, { signal })
      : Promise.resolve({ events: [] }),
    requestJson('/health/ready', { signal, redirectOnUnauthorized: false }).catch(() => ({ status: 'unavailable' })),
  ]);

  const user = record(state.session.user);
  const safeConfiguration = record(configuration);
  const providerCount = ['ldap', 'oidc', 'saml']
    .reduce((total, kind) => total + list(record(safeConfiguration.federation)[kind]).length, 0);
  const events = list(audit.events);
  const activities = element('ol', { className: 'activity-list' });
  for (const event of events) {
    activities.append(element('li', { className: 'activity-item' }, [
      element('span', { className: 'activity-dot' }),
      element('div', { className: 'activity-copy' }, [
        element('strong', { text: text(event.type, 'Unknown event') }),
        element('span', { text: event.subjectId ? `Subject ${event.subjectId}` : `Realm ${state.realm}` }),
      ]),
      element('time', { className: 'activity-time', text: relativeDate(event.createdAt) }),
    ]));
  }
  if (!events.length) activities.append(emptyState(
    can('audit.read') ? 'No activity yet' : 'Audit access is not granted',
    can('audit.read') ? 'Security and administration events will appear here.' : 'The current administrator grant cannot read realm audit events.',
  ));

  const createUser = actionButton('Create user', () => openUserDialog(), 'primary');
  setHeader('overview', can('users.write') ? [createUser] : []);
  const root = element('div', { className: 'page-stack' });
  append(root,
    element('section', { className: 'welcome-panel' }, [
      element('div', { className: 'welcome-copy' }, [
        element('p', { className: 'kicker', text: `${state.realm} realm` }),
        element('h2', { text: `Good to see you, ${text(user.givenName || user.name || user.username, 'administrator')}.` }),
        element('p', { text: 'Your identity control plane is ready. Review recent access activity, keep application trust current, and act on account security from one workspace.' }),
      ]),
      element('span', { className: 'welcome-mark', text: 'A' }),
    ]),
    element('section', { className: 'stats-grid', attributes: { 'aria-label': 'Realm summary' } }, [
      statCard('Users loaded', can('users.read') ? list(users.users).length : '—', can('users.read') ? 'First directory page' : 'Permission not granted', 'cyan'),
      statCard('Configured clients', can('configuration.read') ? list(safeConfiguration.clients).length : '—', can('configuration.read') ? 'Safe configuration view' : 'Permission not granted'),
      statCard('Identity sources', can('configuration.read') ? providerCount : '—', can('configuration.read') ? 'LDAP, OIDC, and SAML' : 'Permission not granted'),
      statCard('System status', health.status === 'ready' ? 'Ready' : 'Attention', 'Readiness probe', health.status === 'ready' ? 'success' : 'warning'),
    ]),
    element('section', { className: 'content-grid' }, [
      contentCard('Recent activity', 'Latest realm audit events', activities,
        can('audit.read') ? actionButton('View all', () => { window.location.hash = 'audit'; }, 'quiet') : null),
      contentCard('Security posture', 'Deployment-level safeguards', element('div', { className: 'card-body' }, [
        element('ul', { className: 'check-list' }, [
          element('li', {}, [element('span', { text: '✓' }), element('div', { text: 'Administrator authentication is held in an HttpOnly session.' })]),
          element('li', {}, [element('span', { text: '✓' }), element('div', { text: can('configuration.read') ? (safeConfiguration.storage === 'postgresql' ? 'Durable PostgreSQL storage is active.' : 'Review storage mode before production use.') : 'Configuration details are limited by this administrator grant.' })]),
          element('li', {}, [element('span', { text: '✓' }), element('div', { text: can('configuration.read') ? (safeConfiguration.dynamicRegistration ? 'Protected dynamic registration is available.' : 'Dynamic client registration is disabled.') : 'Client policy is available to configuration readers.' })]),
          element('li', {}, [element('span', { text: '✓' }), element('div', { text: 'Security mutations are CSRF-protected and audited.' })]),
        ]),
      ])),
    ]),
  );
  setPage(root);
}

function userRow(user) {
  const row = element('tr');
  const identity = element('td', { attributes: { 'data-label': 'User' } }, [
    element('div', { className: 'table-primary' }, [
      element('span', { className: 'table-avatar', text: initials(user.name || user.username) }),
      element('span', { className: 'table-primary-copy' }, [
        element('button', { className: 'table-link', text: text(user.name || user.username), attributes: { type: 'button' } }),
        element('span', { text: text(user.email) }),
      ]),
    ]),
  ]);
  identity.querySelector('button').addEventListener('click', () => { window.location.hash = `users/${encodeURIComponent(user.id)}`; });
  append(row,
    identity,
    element('td', { attributes: { 'data-label': 'Username' }, text: text(user.username) }),
    element('td', { attributes: { 'data-label': 'Status' } }, [badge(user.enabled ? 'Enabled' : 'Disabled', user.enabled ? 'success' : 'danger')]),
    element('td', { attributes: { 'data-label': 'MFA' } }, [badge(user.mfaEnabled ? 'Protected' : 'Not enabled', user.mfaEnabled ? 'info' : 'neutral')]),
    element('td', { attributes: { 'data-label': 'Last login' }, text: relativeDate(user.lastLoginAt) }),
    element('td', { attributes: { 'data-label': 'Actions' } }, [
      element('div', { className: 'table-actions' }, [
        actionButton('View', () => { window.location.hash = `users/${encodeURIComponent(user.id)}`; }, 'quiet'),
      ]),
    ]),
  );
  return row;
}

function usersTable(users) {
  const body = element('tbody');
  for (const user of users) body.append(userRow(user));
  return element('table', { className: 'data-table' }, [
    element('thead', {}, [element('tr', {}, [
      element('th', { text: 'User' }), element('th', { text: 'Username' }), element('th', { text: 'Status' }),
      element('th', { text: 'MFA' }), element('th', { text: 'Last login' }), element('th', { text: 'Actions' }),
    ])]),
    body,
  ]);
}

async function renderUsers(signal) {
  const response = await requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/users?limit=${state.usersLimit}&offset=${state.usersOffset}`,
    { signal },
  );
  const users = list(response.users);
  const create = actionButton('Create user', () => openUserDialog(), 'primary');
  setHeader('users', can('users.write') ? [create] : []);

  const search = element('input', { attributes: { type: 'search', placeholder: 'Filter this page by name or email', 'aria-label': 'Filter loaded users' } });
  const results = element('div', { className: 'card-body flush' });
  const renderResults = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = users.filter((user) => [user.name, user.username, user.email]
      .some((value) => String(value ?? '').toLowerCase().includes(query)));
    results.replaceChildren(filtered.length
      ? usersTable(filtered)
      : emptyState(
        'No users found',
        query ? 'No loaded user matches this filter.' : 'Create the first account for this realm.',
        query || !can('users.write') ? null : actionButton('Create user', () => openUserDialog(), 'primary'),
      ));
  };
  search.addEventListener('input', renderResults);
  renderResults();

  const previous = actionButton('Previous', () => {
    state.usersOffset = Math.max(0, state.usersOffset - state.usersLimit);
    return navigate({ focus: false });
  }, 'secondary');
  previous.disabled = state.usersOffset === 0;
  const next = actionButton('Next', () => {
    state.usersOffset += state.usersLimit;
    return navigate({ focus: false });
  }, 'secondary');
  next.disabled = users.length < state.usersLimit;

  const card = contentCard('Realm directory', `${users.length} users loaded from offset ${state.usersOffset}`, results);
  card.append(element('footer', { className: 'pagination' }, [
    element('span', { text: `Showing ${users.length ? state.usersOffset + 1 : 0}–${state.usersOffset + users.length}. The API does not expose a total.` }),
    element('div', { className: 'pagination-actions' }, [previous, next]),
  ]));
  setPage(element('div', { className: 'page-stack' }, [
    element('div', { className: 'toolbar' }, [
      element('div', { className: 'search-control' }, [search]),
      element('div', { className: 'toolbar-group' }, [badge(`${state.realm} realm`, 'info')]),
    ]),
    card,
  ]));
}

function securityAction(title, detail, label, handler, variant = 'secondary') {
  return element('div', { className: 'security-action' }, [
    element('div', {}, [element('strong', { text: title }), element('span', { text: detail })]),
    actionButton(label, handler, variant),
  ]);
}

function passkeyItem(passkey, userId) {
  return element('div', { className: 'resource-item' }, [
    element('div', {}, [
      element('strong', { text: text(passkey.name, 'Passkey') }),
      element('p', { text: `${text(passkey.deviceType, 'Authenticator')} · Added ${formatDate(passkey.createdAt, { dateOnly: true })}${passkey.lastUsedAt ? ` · Used ${relativeDate(passkey.lastUsedAt)}` : ''}` }),
    ]),
    actionButton('Remove', async (button) => {
      const confirmed = await askConfirmation({
        title: 'Remove passkey?',
        message: `The credential “${text(passkey.name, 'Passkey')}” will no longer authenticate this user.`,
        action: 'Remove passkey',
      });
      if (!confirmed) return;
      await busy(button, 'Removing…', () => requestJson(
        `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}/passkeys/${encodeURIComponent(passkey.id)}`,
        { method: 'DELETE', body: {} },
      ));
      toast('Passkey removed.');
      await navigate({ focus: false });
    }, 'danger-quiet'),
  ]);
}

function identityItem(identity, userId) {
  const item = element('div', { className: 'resource-item' }, [
    element('div', {}, [
      element('strong', { text: `${text(identity.providerId)} · ${text(identity.externalSubject)}` }),
      element('p', { text: `${text(identity.issuer)}${identity.lastLoginAt ? ` · Used ${relativeDate(identity.lastLoginAt)}` : ''}` }),
    ]),
  ]);
  if (can('federation.manage')) item.append(actionButton('Unlink', async (button) => {
      const confirmed = await askConfirmation({
        title: 'Unlink external identity?',
        message: 'The user will no longer be able to sign in with this upstream identity.',
        action: 'Unlink identity',
      });
      if (!confirmed) return;
      await busy(button, 'Unlinking…', () => requestJson(
        `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}/federated-identities`,
        { method: 'DELETE', body: { providerId: identity.providerId, issuer: identity.issuer } },
      ));
      toast('External identity unlinked.');
      await navigate({ focus: false });
    }, 'danger-quiet'));
  return item;
}

async function renderUserDetail(userId, signal) {
  const base = `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}`;
  const [user, passkeys, identities] = await Promise.all([
    requestJson(base, { signal }),
    can('credentials.manage') ? requestJson(`${base}/passkeys`, { signal }) : Promise.resolve({ passkeys: [] }),
    requestJson(`${base}/federated-identities`, { signal }),
  ]);

  const headerActions = [actionButton('Back to users', () => { window.location.hash = 'users'; }, 'secondary')];
  if (can('users.write')) headerActions.push(actionButton('Edit user', () => openUserDialog(user), 'primary'));
  setHeader('users', headerActions);

  const details = element('dl', { className: 'description-grid' }, [
    descriptionItem('Username', text(user.username)),
    descriptionItem('Email', `${text(user.email)}${user.emailVerified ? ' · Verified' : ' · Unverified'}`),
    descriptionItem('Given name', text(user.givenName)),
    descriptionItem('Family name', text(user.familyName)),
    descriptionItem('Created', formatDate(user.createdAt)),
    descriptionItem('Last sign-in', formatDate(user.lastLoginAt)),
    descriptionItem('Realm roles', tagList(user.roles)),
    descriptionItem('Groups', tagList(user.groups)),
  ]);

  const security = element('div', { className: 'card-body security-actions' });
  if (can('credentials.manage')) {
    append(security,
      securityAction('Password', 'Reset credentials and clear lockout', 'Reset', () => openPasswordDialog(user.id)),
      securityAction('Account lock', user.lockedUntil ? `Locked until ${formatDate(user.lockedUntil)}` : 'No active lockout', 'Unlock', (button) => unlockUser(user.id, button)),
      user.mfaEnabled
        ? securityAction('Authenticator app', `${user.recoveryCodesRemaining ?? 0} recovery codes remain`, 'Disable', (button) => disableTotp(user.id, button), 'danger-quiet')
        : securityAction('Authenticator app', 'TOTP is not configured', 'Enroll', (button) => startTotp(user.id, button), 'primary'));
  }
  if (can('sessions.revoke')) {
    security.append(securityAction('Sessions', 'Revoke all sessions, grants, and tokens', 'Revoke all', (button) => revokeSessions(user.id, button), 'danger-quiet'));
  }
  if (!security.childElementCount) {
    security.append(callout('Read-only user access', 'This administrator grant cannot manage credentials or revoke sessions.'));
  }

  const passkeyBody = element('div', { className: 'card-body resource-list' });
  if (can('credentials.manage')) {
    for (const passkey of list(passkeys.passkeys)) passkeyBody.append(passkeyItem(passkey, user.id));
    if (!list(passkeys.passkeys).length) passkeyBody.append(emptyState('No passkeys', 'Register a phishing-resistant credential for this user.'));
  } else {
    passkeyBody.append(emptyState('Credential access is limited', 'This administrator grant cannot view or manage passkeys.'));
  }

  const identityBody = element('div', { className: 'card-body resource-list' });
  for (const identity of list(identities.identities)) identityBody.append(identityItem(identity, user.id));
  if (!list(identities.identities).length) identityBody.append(emptyState('No external identities', 'This account is not explicitly linked to an upstream identity.'));

  const root = element('div', { className: 'page-stack' }, [
    element('section', { className: 'detail-hero' }, [
      element('span', { className: 'detail-avatar', text: initials(user.name || user.username) }),
      element('div', { className: 'detail-title' }, [
        element('h2', { text: text(user.name || user.username) }),
        element('p', { text: `${text(user.email)} · ${state.realm}` }),
      ]),
      element('div', { className: 'detail-actions' }, [
        badge(user.enabled ? 'Enabled' : 'Disabled', user.enabled ? 'success' : 'danger'),
        badge(user.mfaEnabled ? 'MFA enabled' : 'MFA not enabled', user.mfaEnabled ? 'info' : 'warning'),
      ]),
    ]),
    element('section', { className: 'content-grid equal' }, [
      contentCard('Profile & access', 'Public identity attributes and assignments', element('div', { className: 'card-body' }, [details])),
      contentCard('Account security', 'Actions revoke current account state', security),
    ]),
    element('section', { className: 'content-grid equal' }, [
      contentCard('Passkeys', 'Phishing-resistant authenticators', passkeyBody,
        can('credentials.manage') ? actionButton('Register passkey', (button) => registerPasskey(user.id, button), 'primary') : null),
      contentCard('Federated identities', 'Explicit immutable-subject links', identityBody,
        can('federation.manage') ? actionButton('Link identity', () => openIdentityDialog(user.id), 'secondary') : null),
    ]),
  ]);
  if (can('users.delete')) {
    append(root,
      callout('Destructive account action', 'Deleting a user is permanent and revokes all account-bound protocol state.', 'warning'),
      element('div', {}, [actionButton('Delete user', (button) => deleteUser(user, button), 'danger')]),
    );
  }
  setPage(root);
}

function commaValues(value) {
  return [...new Set(String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean))];
}

function clientRolesValue(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return {};
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Client roles must be a valid JSON object.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Client roles must be a JSON object keyed by client ID.');
  }
  for (const [clientId, roles] of Object.entries(parsed)) {
    if (!clientId || !Array.isArray(roles) || roles.some((role) => typeof role !== 'string' || !role.trim())) {
      throw new Error('Each client role entry must be an array of non-empty strings.');
    }
    parsed[clientId] = [...new Set(roles.map((role) => role.trim()))];
  }
  return parsed;
}

function sameValue(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function openUserDialog(user = null) {
  state.editingUser = user;
  const creating = !user;
  document.getElementById('user-dialog-title').textContent = creating ? 'Create user' : `Edit ${text(user.name || user.username)}`;
  document.getElementById('user-dialog-copy').textContent = creating
    ? 'Add an identity to this realm.'
    : 'Profile and access changes revoke the user’s current account state.';
  document.getElementById('user-submit').textContent = creating ? 'Create user' : 'Save changes';
  document.getElementById('user-username-field').hidden = !creating;
  document.getElementById('user-password-field').hidden = !creating;
  const username = document.getElementById('user-username');
  const password = document.getElementById('user-password');
  username.required = creating;
  password.required = creating;
  username.value = creating ? '' : text(user.username, '');
  password.value = '';
  document.getElementById('user-email').value = text(user?.email, '');
  document.getElementById('user-name').value = text(user?.name, '');
  document.getElementById('user-given-name').value = text(user?.givenName, '');
  document.getElementById('user-family-name').value = text(user?.familyName, '');
  document.getElementById('user-enabled').checked = creating ? true : Boolean(user.enabled);
  document.getElementById('user-email-verified').checked = Boolean(user?.emailVerified);
  document.getElementById('user-roles').value = list(user?.roles).join(', ');
  document.getElementById('user-groups').value = list(user?.groups).join(', ');
  document.getElementById('user-client-roles').value = Object.keys(record(user?.clientRoles)).length
    ? JSON.stringify(user.clientRoles, null, 2)
    : '';
  document.getElementById('user-form-error').hidden = true;
  openDialog('user-dialog');
}

async function submitUserForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = document.getElementById('user-submit');
  const error = document.getElementById('user-form-error');
  error.hidden = true;
  try {
    const values = {
      email: document.getElementById('user-email').value.trim(),
      emailVerified: document.getElementById('user-email-verified').checked,
      name: document.getElementById('user-name').value.trim(),
      givenName: document.getElementById('user-given-name').value.trim(),
      familyName: document.getElementById('user-family-name').value.trim(),
      enabled: document.getElementById('user-enabled').checked,
      roles: commaValues(document.getElementById('user-roles').value),
      groups: commaValues(document.getElementById('user-groups').value),
      clientRoles: clientRolesValue(document.getElementById('user-client-roles').value),
    };

    let saved;
    if (!state.editingUser) {
      const body = {
        ...values,
        username: document.getElementById('user-username').value.trim(),
        password: document.getElementById('user-password').value,
      };
      if (!body.name) delete body.name;
      await busy(submit, 'Creating…', async () => {
        saved = await requestJson(`/admin/v1/realms/${encodeURIComponent(state.realm)}/users`, { method: 'POST', body });
      });
      toast('User created.');
    } else {
      const patch = {};
      for (const [key, value] of Object.entries(values)) {
        if (!sameValue(value, state.editingUser[key])) patch[key] = value;
      }
      if (!Object.keys(patch).length) {
        closeDialog('user-dialog');
        toast('No changes to save.');
        return;
      }
      await busy(submit, 'Saving…', async () => {
        saved = await requestJson(
          `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(state.editingUser.id)}`,
          { method: 'PATCH', body: patch },
        );
      });
      toast('User updated and existing sessions revoked.');
    }
    closeDialog('user-dialog');
    form.reset();
    const nextHash = `#users/${encodeURIComponent(saved.id)}`;
    if (window.location.hash === nextHash) await navigate({ focus: false });
    else window.location.hash = nextHash;
  } catch (caught) {
    error.textContent = humanError(caught);
    error.hidden = false;
  }
}

function openPasswordDialog(userId) {
  state.actionUserId = userId;
  document.getElementById('password-form').reset();
  document.getElementById('password-form-error').hidden = true;
  openDialog('password-dialog');
}

async function submitPasswordForm(event) {
  event.preventDefault();
  const password = document.getElementById('reset-password').value;
  const confirmation = document.getElementById('reset-password-confirm').value;
  const error = document.getElementById('password-form-error');
  const submit = event.currentTarget.querySelector('[type="submit"]');
  error.hidden = true;
  if (password !== confirmation) {
    error.textContent = 'The password confirmation does not match.';
    error.hidden = false;
    return;
  }
  try {
    await busy(submit, 'Resetting…', () => requestJson(
      `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(state.actionUserId)}/password`,
      { method: 'PUT', body: { password } },
    ));
    event.currentTarget.reset();
    closeDialog('password-dialog');
    toast('Password reset. Account lockout and existing sessions were cleared.');
    await navigate({ focus: false });
  } catch (caught) {
    error.textContent = humanError(caught);
    error.hidden = false;
  }
}

async function unlockUser(userId, button) {
  await busy(button, 'Unlocking…', () => requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}/unlock`,
    { method: 'POST', body: {} },
  ));
  toast('Account lockout cleared.');
  await navigate({ focus: false });
}

async function revokeSessions(userId, button) {
  const confirmed = await askConfirmation({
    title: 'Revoke every session?',
    message: 'All active sessions, grants, and grant-linked artifacts for this user will be invalidated.',
    action: 'Revoke sessions',
  });
  if (!confirmed) return;
  await busy(button, 'Revoking…', () => requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}/sessions/revoke`,
    { method: 'POST', body: {} },
  ));
  toast('All user sessions revoked.');
  await navigate({ focus: false });
}

async function deleteUser(user, button) {
  const confirmed = await askConfirmation({
    title: `Delete ${text(user.name || user.username)}?`,
    message: 'This permanently removes the user, credentials, identity links, sessions, and grants. This cannot be undone.',
    action: 'Delete user',
  });
  if (!confirmed) return;
  await busy(button, 'Deleting…', () => requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(user.id)}`,
    { method: 'DELETE', body: {} },
  ));
  toast('User deleted.');
  state.usersOffset = 0;
  window.location.hash = 'users';
}

async function startTotp(userId, button) {
  const setup = await busy(button, 'Starting…', () => requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}/mfa/totp`,
    { method: 'POST', body: {} },
  ));
  state.totpUserId = userId;
  document.getElementById('totp-secret').textContent = text(setup.secret, '');
  document.getElementById('totp-uri').value = text(setup.provisioningUri, '');
  document.getElementById('totp-token').value = '';
  document.getElementById('totp-form-error').hidden = true;
  openDialog('totp-dialog');
}

async function submitTotpForm(event) {
  event.preventDefault();
  const error = document.getElementById('totp-form-error');
  const submit = event.currentTarget.querySelector('[type="submit"]');
  error.hidden = true;
  try {
    const result = await busy(submit, 'Confirming…', () => requestJson(
      `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(state.totpUserId)}/mfa/totp/confirm`,
      { method: 'POST', body: { token: document.getElementById('totp-token').value.trim() } },
    ));
    closeDialog('totp-dialog');
    document.getElementById('totp-secret').textContent = '';
    document.getElementById('totp-uri').value = '';
    showOneTimeValues({
      title: 'Save the recovery codes now',
      description: 'Each code works once. AuthMe will not show these values again.',
      values: list(result.recoveryCodes).map((code, index) => [`Recovery code ${index + 1}`, code]),
    });
    toast('Authenticator app enabled.');
    await navigate({ focus: false });
  } catch (caught) {
    error.textContent = humanError(caught);
    error.hidden = false;
  }
}

async function disableTotp(userId, button) {
  const confirmed = await askConfirmation({
    title: 'Disable authenticator app?',
    message: 'TOTP and all remaining recovery codes will be removed. Existing sessions will be revoked.',
    action: 'Disable TOTP',
  });
  if (!confirmed) return;
  await busy(button, 'Disabling…', () => requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}/mfa/totp`,
    { method: 'DELETE', body: {} },
  ));
  toast('Authenticator app disabled.');
  await navigate({ focus: false });
}

function bytesFromBase64url(value) {
  const normalized = String(value).replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = window.atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function base64urlFromBytes(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return window.btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function creationOptionsFromJson(input) {
  const publicKey = structuredClone(input);
  publicKey.challenge = bytesFromBase64url(publicKey.challenge);
  publicKey.user.id = bytesFromBase64url(publicKey.user.id);
  publicKey.excludeCredentials = list(publicKey.excludeCredentials).map((credential) => ({
    ...credential,
    id: bytesFromBase64url(credential.id),
  }));
  return publicKey;
}

function registrationResponseToJson(credential) {
  return {
    id: credential.id,
    rawId: base64urlFromBytes(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: base64urlFromBytes(credential.response.clientDataJSON),
      attestationObject: base64urlFromBytes(credential.response.attestationObject),
      transports: typeof credential.response.getTransports === 'function' ? credential.response.getTransports() : undefined,
    },
  };
}

async function registerPasskey(userId, button) {
  if (!window.PublicKeyCredential || !navigator.credentials?.create) {
    throw new Error('This browser does not support passkey registration.');
  }
  await busy(button, 'Waiting for passkey…', async () => {
    const base = `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(userId)}/passkeys/registration`;
    const setup = await requestJson(`${base}/options`, { method: 'POST', body: {} });
    const credential = await navigator.credentials.create({ publicKey: creationOptionsFromJson(setup.publicKey) });
    if (!credential) throw new Error('The authenticator did not return a credential.');
    await requestJson(`${base}/verify`, {
      method: 'POST',
      body: {
        challengeId: setup.challengeId,
        name: 'Passkey',
        response: registrationResponseToJson(credential),
      },
    });
  });
  toast('Passkey registered.');
  await navigate({ focus: false });
}

function openIdentityDialog(userId) {
  state.identityUserId = userId;
  document.getElementById('identity-form').reset();
  document.getElementById('identity-form-error').hidden = true;
  openDialog('identity-dialog');
}

async function submitIdentityForm(event) {
  event.preventDefault();
  const error = document.getElementById('identity-form-error');
  const submit = event.currentTarget.querySelector('[type="submit"]');
  error.hidden = true;
  try {
    await busy(submit, 'Linking…', () => requestJson(
      `/admin/v1/realms/${encodeURIComponent(state.realm)}/users/${encodeURIComponent(state.identityUserId)}/federated-identities`,
      {
        method: 'POST',
        body: {
          providerId: document.getElementById('identity-provider').value.trim(),
          issuer: document.getElementById('identity-issuer').value.trim(),
          externalSubject: document.getElementById('identity-subject').value.trim(),
        },
      },
    ));
    closeDialog('identity-dialog');
    toast('External identity linked.');
    await navigate({ focus: false });
  } catch (caught) {
    error.textContent = humanError(caught);
    error.hidden = false;
  }
}

function clientIdentifier(client) {
  return text(client.clientId ?? client.client_id, 'Unnamed client');
}

function clientCard(client) {
  const grants = list(client.grantTypes ?? client.grant_types);
  const redirects = list(client.redirectUris ?? client.redirect_uris);
  const method = client.tokenEndpointAuthMethod ?? client.token_endpoint_auth_method ?? 'client_secret_basic';
  return element('article', { className: 'catalog-card' }, [
    element('div', { className: 'catalog-card-header' }, [
      element('span', { className: 'catalog-card-icon', text: 'C' }),
      badge(method === 'none' ? 'Public' : 'Confidential', method === 'none' ? 'info' : 'success'),
    ]),
    element('h3', { text: text(client.clientName ?? client.client_name, clientIdentifier(client)) }),
    element('p', { text: clientIdentifier(client) }),
    element('ul', { className: 'mini-list' }, [
      element('li', {}, [element('span', { text: 'Grant types' }), element('strong', { text: grants.length ? grants.join(', ') : 'Default' })]),
      element('li', {}, [element('span', { text: 'Redirect URIs' }), element('strong', { text: redirects.length })]),
      element('li', {}, [element('span', { text: 'Authentication' }), element('strong', { text: method })]),
    ]),
  ]);
}

function resourceServerItem(server) {
  const audience = server.audience;
  const scopes = list(server.scopes);
  return element('div', { className: 'resource-item' }, [
    element('div', {}, [
      element('strong', { text: text(audience, 'Unnamed resource') }),
      element('p', { text: scopes.length ? scopes.join(' · ') : 'No delegated scopes' }),
    ]),
    badge(text(server.accessTokenFormat ?? server.access_token_format, 'jwt').toUpperCase(), 'info'),
  ]);
}

function openClientDialog() {
  document.getElementById('client-form').reset();
  document.getElementById('client-scopes').value = 'openid profile email';
  document.getElementById('client-refresh').checked = true;
  document.getElementById('client-form-error').hidden = true;
  openDialog('client-dialog');
}

function uriLines(id) {
  return [...new Set(document.getElementById(id).value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean))];
}

function validateUris(values, label) {
  for (const value of values) {
    try {
      new URL(value);
    } catch {
      throw new Error(`${label} contains an invalid URI: ${value}`);
    }
  }
}

async function submitClientForm(event) {
  event.preventDefault();
  const error = document.getElementById('client-form-error');
  const submit = event.currentTarget.querySelector('[type="submit"]');
  error.hidden = true;
  let initialAccessToken;
  try {
    const redirectUris = uriLines('client-redirects');
    const webOrigins = uriLines('client-origins');
    validateUris(redirectUris, 'Redirect URIs');
    validateUris(webOrigins, 'Browser origins');
    const grants = ['authorization_code'];
    if (document.getElementById('client-refresh').checked) grants.push('refresh_token');
    if (document.getElementById('client-device').checked) grants.push('urn:ietf:params:oauth:grant-type:device_code');
    const metadata = {
      client_name: document.getElementById('client-name').value.trim(),
      application_type: document.getElementById('client-type').value,
      redirect_uris: redirectUris,
      web_origins: webOrigins,
      response_types: ['code'],
      grant_types: grants,
      token_endpoint_auth_method: document.getElementById('client-public').checked ? 'none' : 'client_secret_basic',
      scope: document.getElementById('client-scopes').value.trim(),
    };

    let registered;
    await busy(submit, 'Registering…', async () => {
      const authorization = await requestJson(
        `/admin/v1/realms/${encodeURIComponent(state.realm)}/client-registration-tokens`,
        { method: 'POST', body: { expiresInSeconds: 300 } },
      );
      initialAccessToken = authorization.token;
      const discovery = await requestJson(`/realms/${encodeURIComponent(state.realm)}/.well-known/openid-configuration`);
      if (!discovery.registration_endpoint) throw new Error('This realm does not advertise dynamic client registration.');
      const endpoint = new URL(discovery.registration_endpoint, window.location.origin);
      if (endpoint.origin !== window.location.origin) throw new Error('The registration endpoint is not on the AuthMe origin.');
      registered = await requestJson(endpoint, {
        method: 'POST',
        body: metadata,
        ephemeralRegistrationToken: initialAccessToken,
        redirectOnUnauthorized: false,
      });
      initialAccessToken = undefined;
    });
    closeDialog('client-dialog');
    showOneTimeValues({
      title: 'Application registered',
      description: 'Copy the generated credentials now. They exist only in this temporary view and are cleared when it closes.',
      values: [
        ['Client ID', registered.client_id],
        ['Client secret', registered.client_secret],
        ['Registration access token', registered.registration_access_token],
        ['Registration client URI', registered.registration_client_uri],
      ],
    });
    toast('Application registered.');
    await loadConfiguration({ refresh: true }).catch(() => null);
    if (parseRoute().page === 'clients') await navigate({ focus: false });
  } catch (caught) {
    initialAccessToken = undefined;
    error.textContent = humanError(caught);
    error.hidden = false;
  }
}

async function renderClients(signal) {
  const configuration = await loadConfiguration({ signal });
  const clients = list(configuration.clients);
  const resources = list(configuration.resourceServers);
  const register = actionButton('Register application', () => openClientDialog(), 'primary');
  register.disabled = !configuration.dynamicRegistration || !can('clients.register');
  setHeader('clients', can('clients.register') ? [register] : []);

  const clientGrid = element('div', { className: 'card-body catalog-grid' });
  for (const client of clients) clientGrid.append(clientCard(client));
  if (!clients.length) clientGrid.append(emptyState('No configured clients', 'Add a reviewed static client through deployment configuration, or enable protected dynamic registration.'));
  const resourceList = element('div', { className: 'card-body resource-list' });
  for (const server of resources) resourceList.append(resourceServerItem(server));
  if (!resources.length) resourceList.append(emptyState('No protected resources', 'API audiences and authorization policy are deployment-managed.'));

  setPage(element('div', { className: 'page-stack' }, [
    callout(
      configuration.dynamicRegistration ? 'Protected registration is available' : 'Dynamic registration is disabled',
      configuration.dynamicRegistration
        ? 'New applications use a short-lived, one-use authorization. Save generated credentials immediately.'
        : 'Existing safe client configuration is read-only here. Enable dynamic registration through reviewed deployment configuration to create clients at runtime.',
      configuration.dynamicRegistration ? 'success' : 'warning',
    ),
    contentCard('Applications', `${clients.length} clients exposed by the safe realm configuration`, clientGrid),
    contentCard('Resource servers', 'Explicit audiences, scopes, and access-token formats', resourceList),
    callout('Configuration boundary', 'Static clients and API policy remain immutable deployment input. Dynamic registration management is per-client and does not provide a realm-wide inventory.'),
  ]));
}

function providerSummary(kind, provider) {
  if (kind === 'ldap') return text(provider.url ?? provider.host, 'Directory endpoint protected');
  if (kind === 'oidc') return text(provider.issuer, 'Upstream OpenID Provider');
  if (kind === 'saml') return text(
    provider.entityId ?? provider.idpEntityId ?? record(provider.idp).entityId ?? provider.issuer,
    'SAML identity provider',
  );
  return 'Provisioning integration';
}

function providerCard(kind, provider) {
  const id = text(provider.id ?? provider.providerId, 'provider');
  const displayName = text(provider.displayName ?? provider.display_name, id);
  const enabled = provider.enabled !== false;
  const capabilities = list(provider.capabilities);
  return element('article', { className: 'catalog-card' }, [
    element('div', { className: 'catalog-card-header' }, [
      element('span', { className: 'catalog-card-icon', text: kind.slice(0, 1).toUpperCase() }),
      badge(enabled ? 'Enabled' : 'Disabled', enabled ? 'success' : 'neutral'),
    ]),
    element('h3', { text: displayName }),
    element('p', { text: providerSummary(kind, provider) }),
    element('ul', { className: 'mini-list' }, [
      element('li', {}, [element('span', { text: 'Provider ID' }), element('strong', { text: id })]),
      element('li', {}, [element('span', { text: 'JIT provisioning' }), element('strong', { text: provider.jitProvisioning ? 'Enabled' : 'Disabled' })]),
      element('li', {}, [element('span', { text: 'Capabilities' }), element('strong', { text: capabilities.length ? capabilities.join(', ') : kind.toUpperCase() })]),
    ]),
  ]);
}

function integrationSection(title, subtitle, kind, providers) {
  const grid = element('div', { className: 'card-body catalog-grid' });
  for (const provider of providers) grid.append(providerCard(kind, provider));
  if (!providers.length) grid.append(emptyState(`No ${title.toLowerCase()} configured`, 'This integration is disabled until reviewed deployment configuration enables it.'));
  return contentCard(title, subtitle, grid);
}

function scimCards(scim) {
  const grid = element('div', { className: 'card-body catalog-grid' });
  const safeScim = record(scim);
  const entries = Array.isArray(scim) ? [...scim] : [...list(safeScim.tokens ?? safeScim.clients)];
  if (!entries.length && safeScim.enabled) {
    entries.push({ id: safeScim.id ?? 'realm-provisioning', enabled: true });
  }
  for (const entry of entries) {
    grid.append(element('article', { className: 'catalog-card' }, [
      element('div', { className: 'catalog-card-header' }, [
        element('span', { className: 'catalog-card-icon', text: 'S' }),
        badge(entry.enabled === false ? 'Disabled' : 'Enabled', entry.enabled === false ? 'neutral' : 'success'),
      ]),
      element('h3', { text: text(entry.id ?? entry.name, 'SCIM integration') }),
      element('p', { text: 'Bearer credential is redacted by the safe configuration API.' }),
      element('ul', { className: 'mini-list' }, [
        element('li', {}, [element('span', { text: 'Protocol' }), element('strong', { text: 'SCIM 2.0' })]),
        element('li', {}, [element('span', { text: 'Resources' }), element('strong', { text: 'Users and groups' })]),
      ]),
    ]));
  }
  if (!entries.length) grid.append(emptyState('SCIM is not configured', 'Provisioning credentials are managed as secret deployment input.'));
  return grid;
}

async function renderFederation(signal) {
  const configuration = await loadConfiguration({ signal });
  const federation = record(configuration.federation);
  const extensions = list(configuration.extensions);
  const extensionGrid = element('div', { className: 'card-body catalog-grid' });
  for (const extension of extensions) {
    extensionGrid.append(element('article', { className: 'catalog-card' }, [
      element('div', { className: 'catalog-card-header' }, [
        element('span', { className: 'catalog-card-icon', text: 'E' }),
        badge(text(extension.kind, 'extension'), 'info'),
      ]),
      element('h3', { text: text(extension.id, 'Extension') }),
      element('p', { text: list(extension.capabilities).length ? list(extension.capabilities).join(' · ') : 'No capabilities advertised' }),
    ]));
  }
  if (!extensions.length) extensionGrid.append(emptyState('No extension manifests', 'Enabled authentication and provisioning capabilities will appear here.'));

  setHeader('federation');
  setPage(element('div', { className: 'page-stack' }, [
    callout('Safe catalog view', 'Provider passwords, OAuth secrets, signing keys, certificates, and SCIM tokens are never rendered. Integration changes remain reviewed deployment operations.'),
    integrationSection('LDAP & Active Directory', 'Directory authentication and optional just-in-time accounts', 'ldap', list(federation.ldap)),
    integrationSection('Upstream OpenID Connect', 'Authorization Code and PKCE federation', 'oidc', list(federation.oidc)),
    integrationSection('SAML identity providers', 'Signed SAML 2.0 service-provider trust', 'saml', list(federation.saml)),
    contentCard('SCIM provisioning', 'Realm-scoped user and group synchronization', scimCards(configuration.scim)),
    contentCard('Loaded extensions', 'Runtime capability manifests for this realm', extensionGrid),
  ]));
}

function auditTable(events) {
  const body = element('tbody');
  for (const event of events) {
    const metadata = element('details', { className: 'audit-details' }, [
      element('summary', { text: Object.keys(record(event.metadata)).length ? 'View metadata' : 'No metadata' }),
      element('pre', { className: 'code-block', text: JSON.stringify(record(event.metadata), null, 2) }),
    ]);
    body.append(element('tr', {}, [
      element('td', { attributes: { 'data-label': 'Event' } }, [
        element('span', { className: 'table-primary-copy' }, [
          element('strong', { text: text(event.type, 'Unknown event') }),
          element('span', { text: text(event.id) }),
        ]),
      ]),
      element('td', { attributes: { 'data-label': 'Subject' }, text: text(event.subjectId) }),
      element('td', { attributes: { 'data-label': 'Client' }, text: text(event.clientId) }),
      element('td', { attributes: { 'data-label': 'Source' }, text: text(event.ip, 'Server') }),
      element('td', { attributes: { 'data-label': 'Time' }, text: formatDate(event.createdAt) }),
      element('td', { attributes: { 'data-label': 'Details' } }, [metadata]),
    ]));
  }
  return element('table', { className: 'data-table' }, [
    element('thead', {}, [element('tr', {}, [
      element('th', { text: 'Event' }), element('th', { text: 'Subject' }), element('th', { text: 'Client' }),
      element('th', { text: 'Source' }), element('th', { text: 'Time' }), element('th', { text: 'Details' }),
    ])]),
    body,
  ]);
}

async function renderAudit(signal) {
  const response = await requestJson(
    `/admin/v1/realms/${encodeURIComponent(state.realm)}/audit?limit=${state.auditLimit}&offset=${state.auditOffset}`,
    { signal },
  );
  const events = list(response.events);
  setHeader('audit', [actionButton('Refresh', () => navigate({ focus: false }), 'secondary')]);

  const search = element('input', { attributes: { type: 'search', placeholder: 'Filter loaded event types', 'aria-label': 'Filter loaded audit events' } });
  const results = element('div', { className: 'card-body flush' });
  const renderResults = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = events.filter((event) => [event.type, event.subjectId, event.clientId, event.ip]
      .some((value) => String(value ?? '').toLowerCase().includes(query)));
    results.replaceChildren(filtered.length
      ? auditTable(filtered)
      : emptyState('No matching events', query ? 'No loaded event matches this filter.' : 'Audit events will appear after realm activity.'));
  };
  search.addEventListener('input', renderResults);
  renderResults();

  const previous = actionButton('Previous', () => {
    state.auditOffset = Math.max(0, state.auditOffset - state.auditLimit);
    return navigate({ focus: false });
  }, 'secondary');
  previous.disabled = state.auditOffset === 0;
  const next = actionButton('Next', () => {
    state.auditOffset += state.auditLimit;
    return navigate({ focus: false });
  }, 'secondary');
  next.disabled = events.length < state.auditLimit;
  const card = contentCard('Realm event stream', `${events.length} events loaded from offset ${state.auditOffset}`, results);
  card.append(element('footer', { className: 'pagination' }, [
    element('span', { text: 'Newest events first. Filtering applies to the loaded page.' }),
    element('div', { className: 'pagination-actions' }, [previous, next]),
  ]));

  setPage(element('div', { className: 'page-stack' }, [
    callout('Audited access', 'Opening this page records an admin.audit.read event in the selected realm.'),
    element('div', { className: 'toolbar' }, [
      element('div', { className: 'search-control' }, [search]),
      element('div', { className: 'toolbar-group' }, [badge(`${state.realm} realm`, 'info')]),
    ]),
    card,
  ]));
}

function healthRow(title, detail, status, tone = 'success') {
  return element('div', { className: 'health-row' }, [
    element('div', {}, [element('strong', { text: title }), element('span', { text: detail })]),
    badge(status, tone),
  ]);
}

function settingLink(title, detail, href) {
  return element('a', { className: 'settings-link', attributes: { href } }, [
    element('div', {}, [element('strong', { text: title }), element('span', { text: detail })]),
    element('span', { text: '›' }),
  ]);
}

async function renderSystem(signal) {
  const [configuration, health] = await Promise.all([
    loadConfiguration({ signal }),
    requestJson('/health/ready', { signal, redirectOnUnauthorized: false }).catch(() => ({ status: 'unavailable' })),
  ]);
  setHeader('system', [actionButton('Refresh configuration', async (button) => {
    await busy(button, 'Refreshing…', () => loadConfiguration({ refresh: true }));
    toast('Safe configuration refreshed.');
    await navigate({ focus: false });
  }, 'secondary')]);

  const ttlGrid = element('dl', { className: 'description-grid' });
  const ttlEntries = Object.entries(record(configuration.ttls));
  if (ttlEntries.length) {
    for (const [name, value] of ttlEntries) {
      const unit = name === 'auditRetentionDays' ? 'days' : 'seconds';
      ttlGrid.append(descriptionItem(name.replaceAll(/([A-Z_])/g, ' $1').trim(), `${value} ${unit}`));
    }
  } else {
    ttlGrid.append(descriptionItem('Token lifetimes', 'Not exposed'));
  }
  const resources = element('div', { className: 'card-body resource-list' });
  for (const server of list(configuration.resourceServers)) resources.append(resourceServerItem(server));
  if (!list(configuration.resourceServers).length) resources.append(emptyState('No API audiences', 'No resource servers are configured in this realm.'));

  const user = record(state.session.user);
  const discoveryPath = `/realms/${encodeURIComponent(state.realm)}/.well-known/openid-configuration`;
  setPage(element('div', { className: 'page-stack' }, [
    element('section', { className: 'stats-grid' }, [
      statCard('Runtime mode', text(configuration.mode, 'Unknown'), 'Fixed startup mode'),
      statCard('Storage', text(configuration.storage, 'Unknown'), 'Identity and protocol state', configuration.storage === 'postgresql' ? 'success' : 'warning'),
      statCard('Shared limiter', configuration.redis ? 'Redis' : 'Local', configuration.redis ? 'Distributed rate limits' : 'Process-local fallback', configuration.redis ? 'success' : 'warning'),
      statCard('Registration', configuration.dynamicRegistration ? 'Enabled' : 'Disabled', 'Protected dynamic clients', configuration.dynamicRegistration ? 'cyan' : ''),
    ]),
    element('section', { className: 'content-grid equal' }, [
      contentCard('Service health', 'Live runtime signals', element('div', { className: 'card-body' }, [
        healthRow('Readiness', 'Storage and realm providers', text(health.status), health.status === 'ready' ? 'success' : 'danger'),
        healthRow('Issuer', text(configuration.issuer), 'Fixed', 'info'),
        healthRow('Administrator session', text(user.email || user.username), 'Active', 'success'),
      ])),
      contentCard('Protocol references', 'Public metadata and operational probes', element('div', { className: 'card-body settings-links' }, [
        settingLink('OpenID configuration', 'Discovery metadata for this realm', discoveryPath),
        settingLink('Signing keys', 'Public realm JSON Web Key Set', `/realms/${encodeURIComponent(state.realm)}/protocol/openid-connect/certs`),
        settingLink('Liveness probe', 'Process health without sensitive details', '/health/live'),
        settingLink('Readiness probe', 'Dependency readiness', '/health/ready'),
      ])),
    ]),
    contentCard('Token & session lifetimes', 'Values exposed by the safe configuration API', element('div', { className: 'card-body' }, [ttlGrid])),
    contentCard('Resource-server policy', 'Explicit protected audiences in this realm', resources),
    callout('Deployment-managed settings', 'Realm issuers, signing material, static clients, identity-provider trust, SCIM credentials, secrets, storage, and token policy are changed through reviewed deployment configuration and a controlled rollout.', 'warning'),
  ]));
}

function populateSessionShell() {
  const user = record(state.session.user);
  const name = text(user.name || user.username || user.email, 'Administrator');
  document.getElementById('operator-name').textContent = name;
  document.getElementById('operator-email').textContent = text(user.email, `${state.realm} realm`);
  document.getElementById('operator-avatar').textContent = initials(name);
  document.getElementById('footer-context').textContent = `${state.realm} realm · Cookie-protected session`;
  document.getElementById('realm-switch-csrf').value = state.csrf;
  document.getElementById('logout-csrf').value = state.csrf;

  const select = document.getElementById('realm-switch');
  select.replaceChildren();
  for (const realm of state.realms) {
    const option = element('option', { text: realm.name, attributes: { value: realm.name } });
    option.selected = realm.name === state.realm;
    select.append(option);
  }
  select.disabled = state.realms.length < 2;
  for (const link of document.querySelectorAll('[data-nav-page]')) {
    const page = link.getAttribute('data-nav-page');
    const permission = PAGE_PERMISSIONS[page];
    link.hidden = Boolean(permission && !can(permission));
  }
}

async function switchRealm(event) {
  event.preventDefault();
  const select = document.getElementById('realm-switch');
  const realm = select.value;
  if (!realm || realm === state.realm) return;
  select.disabled = true;
  try {
    const result = await requestJson('/admin/ui/switch-realm', { method: 'POST', body: { realm } });
    if (typeof result?.authorizationUrl !== 'string') throw new Error('AuthMe did not return a realm authorization URL.');
    const authorizationUrl = new URL(result.authorizationUrl, window.location.origin);
    if (authorizationUrl.origin !== window.location.origin) throw new Error('AuthMe returned an unsafe realm authorization URL.');
    window.location.assign(authorizationUrl);
  } catch (error) {
    select.disabled = false;
    select.value = state.realm;
    toast(humanError(error), 'error');
  }
}

async function logout(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  try {
    await busy(button, '…', () => requestJson('/admin/ui/logout', { method: 'POST', body: {} }));
  } finally {
    window.location.replace('/admin/');
  }
}

function wireStaticEvents() {
  document.getElementById('realm-switch-form').addEventListener('submit', switchRealm);
  document.getElementById('realm-switch').addEventListener('change', switchRealm);
  document.getElementById('logout-form').addEventListener('submit', logout);
  document.getElementById('user-form').addEventListener('submit', submitUserForm);
  document.getElementById('password-form').addEventListener('submit', submitPasswordForm);
  document.getElementById('totp-form').addEventListener('submit', submitTotpForm);
  document.getElementById('client-form').addEventListener('submit', submitClientForm);
  document.getElementById('identity-form').addEventListener('submit', submitIdentityForm);
  document.getElementById('copy-totp-secret').addEventListener('click', () => {
    copyValue(document.getElementById('totp-secret').textContent).catch((error) => toast(humanError(error), 'error'));
  });
  for (const close of document.querySelectorAll('[data-close-dialog]')) {
    close.addEventListener('click', () => closeDialog(close.getAttribute('data-close-dialog')));
  }
  document.getElementById('credential-dialog').addEventListener('close', () => {
    document.getElementById('credential-content').replaceChildren();
  });
  document.getElementById('totp-dialog').addEventListener('close', () => {
    document.getElementById('totp-secret').textContent = '';
    document.getElementById('totp-uri').value = '';
    document.getElementById('totp-token').value = '';
    state.totpUserId = null;
  });
  window.addEventListener('hashchange', () => navigate());
}

async function bootstrap() {
  wireStaticEvents();
  try {
    const session = await requestJson('/admin/ui/session');
    if (!session || typeof session.realm !== 'string' || typeof session.csrf !== 'string' || !session.csrf) {
      throw new ApiError('The administrator session response is incomplete.');
    }
    state.session = session;
    state.realm = session.realm;
    state.csrf = session.csrf;
    if (can('realms.read')) {
      const realmsResponse = await requestJson('/admin/v1/realms');
      state.realms = list(realmsResponse.realms)
        .filter((realm) => realm && typeof realm.name === 'string');
    } else {
      state.realms = [{ name: state.realm }];
    }
    if (!state.realms.some((realm) => realm.name === state.realm)) {
      state.realms.unshift({ name: state.realm });
    }
    populateSessionShell();
    if (can('configuration.read')) {
      loadConfiguration().catch((error) => toast(`Safe configuration is unavailable: ${humanError(error)}`, 'error'));
    }
    if (!window.location.hash) window.history.replaceState(null, '', '#overview');
    await navigate({ focus: false });
  } catch (error) {
    if (error?.status !== 401) renderErrorState(error, () => window.location.reload());
  }
}

bootstrap();
