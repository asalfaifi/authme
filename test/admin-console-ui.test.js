import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

class FakeElement {
  constructor(id = '') {
    this.id = id;
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

  append() {}

  replaceChildren() {}
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
