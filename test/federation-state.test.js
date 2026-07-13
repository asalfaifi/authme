import assert from 'node:assert/strict';
import { test } from 'node:test';

import { clearMemoryAdapter, createMemoryAdapter } from '../src/adapters/memory.js';
import { createAdapterFederationStateStore } from '../src/federation/state-store.js';

test('federation state is realm-bound and one-use', async () => {
  clearMemoryAdapter();
  const adapterFor = (realm) => createMemoryAdapter({ realm });
  const store = createAdapterFederationStateStore(adapterFor);
  const state = await store.issue('staff', { interactionUid: 'interaction-1' }, 60);
  assert.match(state, /^[A-Za-z0-9_-]{43}$/);
  await assert.rejects(() => store.consume('master', state), /missing, expired, or already used/);
  assert.deepEqual(await store.consume('staff', state), { interactionUid: 'interaction-1' });
  await assert.rejects(() => store.consume('staff', state), /missing, expired, or already used/);
  await assert.rejects(() => store.consume('staff', `${'a'.repeat(32)}:injected`), /missing, expired, or already used/);
});
