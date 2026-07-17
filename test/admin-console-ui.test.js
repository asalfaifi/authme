import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

class FakeElement {
  constructor(id = '') {
    this.id = id;
    this.children = [];
    this.listeners = new Map();
    this.open = false;
    this.returnValue = '';
    this.textContent = '';
    this.value = '';
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    this.listeners.set(type, listeners.filter((candidate) => candidate !== listener));
  }

  dispatchEvent(event) {
    for (const listener of [...(this.listeners.get(event.type) ?? [])]) listener.call(this, event);
    return !event.defaultPrevented;
  }

  showModal() {
    this.open = true;
  }

  close(returnValue) {
    if (returnValue !== undefined) this.returnValue = returnValue;
    this.open = false;
    this.dispatchEvent({ type: 'close', defaultPrevented: false });
  }

  setAttribute(name, value) {
    if (name === 'open') this.open = true;
    this[name] = value;
  }

  removeAttribute(name) {
    if (name === 'open') this.open = false;
    delete this[name];
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
  }

  remove() {}
}

function withTimeout(promise, milliseconds = 1_000) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('The confirmation promise did not settle.')), milliseconds);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

test('confirmation dialogs reset stale approval and treat Escape as cancellation', async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement(id));
    return elements.get(id);
  };
  const document = {
    getElementById: element,
    createElement: (tagName) => new FakeElement(tagName),
    querySelectorAll: () => [],
  };
  const window = {
    location: {
      origin: 'http://authme.test',
      hash: '',
      replace() {},
      reload() {},
    },
    history: { replaceState() {} },
    addEventListener() {},
    setTimeout,
  };
  const source = await readFile(new URL('../src/ui/admin-console.js', import.meta.url), 'utf8');
  const context = {
    AbortController,
    Headers,
    Response,
    URL,
    document,
    fetch: async () => new Response(JSON.stringify({
      type: 'about:blank',
      title: 'Administrator sign-in required',
      status: 401,
    }), { status: 401, headers: { 'content-type': 'application/problem+json' } }),
    navigator: {},
    setTimeout,
    window,
  };
  vm.runInNewContext(`${source}\nglobalThis.__askConfirmation = askConfirmation;`, context, {
    filename: 'admin-console.js',
  });

  const dialog = element('confirm-dialog');
  const first = context.__askConfirmation({
    title: 'Delete account',
    message: 'This cannot be undone.',
    action: 'Delete',
  });
  assert.equal(dialog.returnValue, 'cancel');
  assert.equal(dialog.open, true);
  dialog.close('confirm');
  assert.equal(await withTimeout(first), true);

  const second = context.__askConfirmation({
    title: 'Revoke sessions',
    message: 'Every active session will end.',
    action: 'Revoke',
  });
  assert.equal(dialog.returnValue, 'cancel', 'A previous confirmation leaked into the next prompt');
  const cancelEvent = {
    type: 'cancel',
    defaultPrevented: false,
    preventDefault() { this.defaultPrevented = true; },
  };
  dialog.dispatchEvent(cancelEvent);
  assert.equal(cancelEvent.defaultPrevented, true);
  assert.equal(dialog.open, false);
  assert.equal(await withTimeout(second), false, 'Escape was interpreted as confirmation');
});

test('client scopes can be unassigned from a client in the admin console', async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement(id));
    return elements.get(id);
  };
  const document = {
    title: '',
    getElementById: element,
    createElement: (tagName) => new FakeElement(tagName),
    querySelectorAll: () => [],
  };
  let resolveDeletion;
  const deletion = new Promise((resolve) => { resolveDeletion = resolve; });
  const fetch = async (url, options = {}) => {
    const path = new URL(url).pathname;
    if (path === '/admin/ui/session') {
      return new Response(JSON.stringify({ title: 'Administrator sign-in required' }), {
        status: 401,
        headers: { 'content-type': 'application/problem+json' },
      });
    }
    if (options.method === 'DELETE') {
      resolveDeletion({ path, options });
      return new Response(null, { status: 204 });
    }
    const payload = path.endsWith('/client-scopes')
      ? { clientScopes: [{ id: 'scope-id', name: 'profile-extra', description: '', protocol: 'openid-connect', attributes: {} }] }
      : path.endsWith('/roles') ? { roles: [] }
        : path.endsWith('/groups') ? { groups: [] }
          : path.endsWith('/authentication-flows') ? { authenticationFlows: [] }
            : { claimMappers: [] };
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  const window = {
    location: {
      origin: 'http://authme.test',
      hash: '',
      replace() {},
      reload() {},
    },
    history: { replaceState() {} },
    addEventListener() {},
    prompt: () => 'managed-native',
    setTimeout() {},
  };
  const source = await readFile(new URL('../src/ui/admin-console.js', import.meta.url), 'utf8');
  const context = {
    AbortController,
    Headers,
    Response,
    URL,
    document,
    fetch,
    navigator: {},
    setTimeout,
    window,
  };
  vm.runInNewContext(`${source}\nglobalThis.__renderAccessModel = renderAccessModel; globalThis.__state = state;`, context, {
    filename: 'admin-console.js',
  });
  context.__state.realm = 'master';
  context.__state.session = { permissions: ['client-scopes.manage'] };
  context.__state.csrf = 'csrf-token';
  await context.__renderAccessModel();

  const descendants = (node) => [node, ...node.children.flatMap(descendants)];
  const unassign = descendants(element('page-content'))
    .find((node) => node.textContent === 'Unassign');
  assert(unassign, 'The client-scope lifecycle has no unassign action');
  unassign.dispatchEvent({ type: 'click', defaultPrevented: false });
  const request = await withTimeout(deletion);
  assert.equal(request.path, '/admin/v1/realms/master/clients/managed-native/client-scopes/scope-id');
  assert.equal(request.options.method, 'DELETE');
  assert.equal(request.options.headers.get('x-authme-csrf'), 'csrf-token');
});

test('federation catalog uses responsive protocol and provisioning groups', async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement(id));
    return elements.get(id);
  };
  const document = {
    title: '',
    getElementById: element,
    createElement: (tagName) => new FakeElement(tagName),
    querySelectorAll: () => [],
  };
  const window = {
    location: { origin: 'http://authme.test', hash: '', replace() {}, reload() {} },
    history: { replaceState() {} },
    addEventListener() {},
    setTimeout() {},
  };
  const source = await readFile(new URL('../src/ui/admin-console.js', import.meta.url), 'utf8');
  const context = {
    AbortController,
    Headers,
    Response,
    URL,
    document,
    fetch: async () => new Response(JSON.stringify({ title: 'Administrator sign-in required' }), {
      status: 401,
      headers: { 'content-type': 'application/problem+json' },
    }),
    navigator: {},
    setTimeout,
    window,
  };
  vm.runInNewContext(`${source}\nglobalThis.__renderFederation = renderFederation; globalThis.__state = state;`, context, {
    filename: 'admin-console.js',
  });
  context.__state.realm = 'master';
  context.__state.session = { permissions: ['configuration.read'] };
  context.__state.configuration = {
    federation: {
      ldap: [{ id: 'directory', displayName: 'Directory', enabled: true, jitProvisioning: true }],
      oidc: [],
      saml: [],
    },
    scim: { enabled: false },
    extensions: [{ id: 'builtin.ldap', kind: 'federation', capabilities: ['authenticate'] }],
  };

  await context.__renderFederation();
  const descendants = (node) => [node, ...node.children.flatMap(descendants)];
  const rendered = descendants(element('page-content'));
  const protocolGrid = rendered.find((node) => node.className === 'federation-protocol-grid');
  const supportGrid = rendered.find((node) => node.className === 'federation-support-grid');
  assert(protocolGrid, 'Federation protocols are not grouped in the responsive grid');
  assert.equal(protocolGrid.children.length, 3);
  assert(supportGrid, 'Provisioning and extension cards are not grouped separately');
  assert.equal(supportGrid.children.length, 2);
  assert.equal(rendered.some((node) => node.textContent === 'Realm-isolated identity sources'), true);
});
