import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateDevelopmentJwks } from '../src/crypto/jwks.js';
import { createSigningKeyManager } from '../src/crypto/signing-key-manager.js';
import { loadConfig } from '../src/config.js';
import { MemoryManagementStore } from '../src/repositories/management-store.js';

test('external signing adapter loads keys and performs overlap-safe forced rotation', async () => {
  let keySet = await generateDevelopmentJwks();
  const firstKid = keySet.keys[0].kid;
  const adapter = {
    async loadJwks() { return keySet; },
    async rotate() {
      const next = await generateDevelopmentJwks();
      keySet = { keys: [next.keys[0], ...keySet.keys] };
    },
  };
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({
      master: {
        provider: 'aws-kms', algorithm: 'RS256', material_reference: 'arn:aws:kms:region:account:key/example',
        rotation_days: 30, overlap_seconds: 3600,
      },
    }),
  });
  const management = new MemoryManagementStore(['master']);
  const manager = createSigningKeyManager({ config, realm: 'master', management, adapters: { 'aws-kms': adapter } });
  await manager.load();
  const result = await manager.rotate({ force: true });
  assert.equal(result.rotated, true);
  assert.notEqual(result.keyId, firstKid);
  const inventory = await management.listSigningKeys('master');
  assert.equal(inventory.find((entry) => entry.keyId === result.keyId).status, 'active');
  assert.equal(inventory.find((entry) => entry.keyId === firstKid).status, 'retiring');
  assert.equal(Object.hasOwn(inventory[0].publicJwk, 'd'), false);
});

test('external signing configuration fails closed without a provider adapter', () => {
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'pkcs11', algorithm: 'ES256', material_reference: 'pkcs11:token=authme;object=realm-master',
    } }),
  });
  assert.throws(
    () => createSigningKeyManager({ config, realm: 'master', management: new MemoryManagementStore(['master']) }),
    /requires loadJwks and rotate/iu,
  );
});
