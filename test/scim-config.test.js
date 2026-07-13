import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createScimTokenAuthenticator, parseScimTokens } from '../src/scim/config.js';

test('SCIM bearer tokens are realm-isolated, strongly sized, and constant-time compared', async () => {
  const tokens = parseScimTokens(JSON.stringify({
    staff: [{ id: 'entra', token: 'a'.repeat(48) }, { id: 'okta', token: 'b'.repeat(48) }],
  }), { realms: ['master', 'staff'], devMode: false });
  const authenticate = createScimTokenAuthenticator(tokens);
  assert.deepEqual(await authenticate({ realm: 'staff', token: 'b'.repeat(48) }), { type: 'scim-token', id: 'okta' });
  assert.equal(await authenticate({ realm: 'master', token: 'b'.repeat(48) }), null);
  assert.equal(await authenticate({ realm: 'staff', token: 'wrong' }), null);
  assert.equal(Object.isFrozen(tokens.staff), true);
});

test('SCIM bearer token configuration rejects weak, duplicate, and placeholder values', () => {
  assert.throws(() => parseScimTokens(JSON.stringify({ staff: [{ id: 'entra', token: 'short' }] }), {
    realms: ['staff'], devMode: false,
  }), /32 to 4096 bytes/);
  assert.throws(() => parseScimTokens(JSON.stringify({ staff: [
    { id: 'entra', token: 'a'.repeat(48) }, { id: 'entra', token: 'b'.repeat(48) },
  ] }), { realms: ['staff'], devMode: false }), /invalid or duplicated/);
  assert.throws(() => parseScimTokens(JSON.stringify({
    staff: [{ id: 'entra', token: `replace-with-${'x'.repeat(48)}` }],
  }), { realms: ['staff'], devMode: false }), /placeholder/);
});
