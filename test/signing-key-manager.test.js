import assert from 'node:assert/strict';
import {
  constants,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { ExternalSigningKey } from 'oidc-provider';
import { createAuthMeApp } from '../src/app.js';
import { generateDevelopmentJwks, publicSigningJwks } from '../src/crypto/jwks.js';
import { loadSigningKeyAdapters } from '../src/crypto/signing-adapters.js';
import { createSigningKeyManager } from '../src/crypto/signing-key-manager.js';
import { loadConfig } from '../src/config.js';
import { MemoryManagementStore } from '../src/repositories/management-store.js';

test('external signing adapter loads keys and performs overlap-safe forced rotation', async () => {
  let keySet = await generateDevelopmentJwks();
  const firstKid = keySet.keys[0].kid;
  const adapter = {
    async loadJwks() { return publicSigningJwks(keySet); },
    async sign({ keyId, data }) {
      const key = keySet.keys.find(({ kid }) => kid === keyId);
      return cryptoSign('sha256', data, {
        key: createPrivateKey({ key, format: 'jwk' }),
        padding: constants.RSA_PKCS1_PADDING,
      });
    },
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
  const loaded = await manager.load();
  assert(loaded.keys[0] instanceof ExternalSigningKey);
  const message = Buffer.from('authme-external-signing-contract');
  const signature = await loaded.keys[0].sign(message);
  assert.equal(cryptoVerify('sha256', message, {
    key: loaded.keys[0].keyObject(),
    padding: constants.RSA_PKCS1_PADDING,
  }, signature), true);
  assert.deepEqual(publicSigningJwks(loaded), publicSigningJwks(keySet));
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
    /requires loadJwks, sign, and rotate/iu,
  );
});

test('ES256 external signing converts provider DER signatures to JWS encoding', async () => {
  const { privateKey } = await generateKeyPair('ES256', { crv: 'P-256', extractable: true });
  const privateJwk = { ...await exportJWK(privateKey), kid: 'external-es256', alg: 'ES256', use: 'sig' };
  const publicJwk = publicSigningJwks({ keys: [privateJwk] }).keys[0];
  const adapter = {
    async loadJwks() { return { keys: [publicJwk] }; },
    async sign({ data }) { return cryptoSign('sha256', data, createPrivateKey({ key: privateJwk, format: 'jwk' })); },
    async rotate() {},
  };
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'pkcs11', algorithm: 'ES256', material_reference: 'pkcs11:object=realm-master',
    } }),
  });
  const manager = createSigningKeyManager({ config, realm: 'master', management: new MemoryManagementStore(['master']), adapters: { pkcs11: adapter } });
  const [key] = (await manager.load()).keys;
  const message = Buffer.from('authme-es256-external-signature');
  const signature = await key.sign(message);
  assert.equal(signature.length, 64);
  assert.equal(cryptoVerify('sha256', message, {
    key: createPublicKey({ key: publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
  }, signature), true);
});

test('PS256 external signing verifies the required PSS salt policy locally', async () => {
  const privateJwk = { ...(await generateDevelopmentJwks()).keys[0], alg: 'PS256' };
  const publicJwk = publicSigningJwks({ keys: [privateJwk] }).keys[0];
  const adapter = {
    async loadJwks() { return { keys: [publicJwk] }; },
    async sign({ data }) {
      return cryptoSign('sha256', data, {
        key: createPrivateKey({ key: privateJwk, format: 'jwk' }),
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      });
    },
    async rotate() {},
  };
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'aws-kms', algorithm: 'PS256', material_reference: 'arn:aws:kms:us-east-1:000000000000:key/pss',
    } }),
  });
  const key = (await createSigningKeyManager({
    config, realm: 'master', management: new MemoryManagementStore(['master']), adapters: { 'aws-kms': adapter },
  }).load()).keys[0];
  assert((await key.sign(Buffer.from('ps256-signing-input'))).length > 0);
});

test('normal server adapter loader resolves every configured external provider module', async () => {
  const adapter = { async loadJwks() {}, async sign() {}, async rotate() {} };
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'gcp-kms', algorithm: 'RS256', material_reference: 'projects/example/locations/global/keyRings/authme/cryptoKeys/master',
    } }),
    AUTHME_SIGNING_ADAPTER_MODULES_JSON: JSON.stringify({ 'gcp-kms': 'authme-gcp-signing-adapter' }),
  });
  let received;
  const adapters = await loadSigningKeyAdapters(config, async (specifier) => {
    assert.equal(specifier, 'authme-gcp-signing-adapter');
    return { async createSigningAdapter(options) { received = options; return adapter; } };
  });
  assert.equal(adapters.get('gcp-kms'), adapter);
  assert.equal(received.provider, 'gcp-kms');
  assert.equal(received.policies.master.materialReference.includes('cryptoKeys/master'), true);
  const missingModule = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'gcp-kms', algorithm: 'RS256', material_reference: 'projects/example/locations/global/keyRings/authme/cryptoKeys/master',
    } }),
  });
  await assert.rejects(loadSigningKeyAdapters(missingModule), /must configure a module for gcp-kms/iu);
});

test('normal server adapter loader imports a configured deployment module', async () => {
  const specifier = new URL('../test-support/signing-adapter.js', import.meta.url).href;
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'pkcs11', algorithm: 'ES256', material_reference: 'pkcs11:object=master',
    } }),
    AUTHME_SIGNING_ADAPTER_MODULES_JSON: JSON.stringify({ pkcs11: specifier }),
  });
  const adapters = await loadSigningKeyAdapters(config);
  assert.equal(typeof adapters.get('pkcs11').sign, 'function');
});

test('oidc-provider issues a verifiable ID token through the external signing boundary', async () => {
  const keySet = await generateDevelopmentJwks();
  let signCount = 0;
  const adapter = {
    async loadJwks() { return publicSigningJwks(keySet); },
    async sign({ keyId, data }) {
      signCount += 1;
      const key = keySet.keys.find(({ kid }) => kid === keyId);
      return cryptoSign('sha256', data, {
        key: createPrivateKey({ key, format: 'jwk' }), padding: constants.RSA_PKCS1_PADDING,
      });
    },
    async rotate() {},
  };
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true', AUTHME_PUBLIC_URL: 'http://127.0.0.1:34889', AUTHME_LOG_LEVEL: 'silent',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'aws-kms', algorithm: 'RS256', material_reference: 'arn:aws:kms:us-east-1:000000000000:key/test',
    } }),
  });
  const runtime = await createAuthMeApp(config, { signingKeyAdapters: new Map([['aws-kms', adapter]]) });
  try {
    const provider = runtime.providers.get('master');
    const client = await provider.Client.find('authme-account-console');
    assert.equal(client.idTokenSignedResponseAlg, 'RS256');
    const idToken = new provider.IdToken({ sub: 'external-signer-subject' }, { client });
    idToken.scope = 'openid';
    const token = await idToken.issue({ use: 'idtoken' });
    const verified = await jwtVerify(token, createPublicKey({ key: publicSigningJwks(keySet).keys[0], format: 'jwk' }), {
      issuer: 'http://127.0.0.1:34889/realms/master', audience: 'authme-account-console',
    });
    assert.equal(verified.payload.sub, 'external-signer-subject');
    assert.equal(signCount, 1);
  } finally {
    await runtime.close();
  }
});

test('external signing providers cannot return private key material', async () => {
  const keySet = await generateDevelopmentJwks();
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'azure-key-vault', algorithm: 'RS256', material_reference: 'https://vault.example/keys/master',
    } }),
  });
  const manager = createSigningKeyManager({
    config, realm: 'master', management: new MemoryManagementStore(['master']),
    adapters: { 'azure-key-vault': { async loadJwks() { return keySet; }, async sign() {}, async rotate() {} } },
  });
  await assert.rejects(manager.load(), /public keys only/iu);
});

test('external rotation fails closed when the provider drops the previous verification key', async () => {
  let keySet = await generateDevelopmentJwks();
  const adapter = {
    async loadJwks() { return publicSigningJwks(keySet); },
    async sign() { return Buffer.from('not-used'); },
    async rotate() { keySet = await generateDevelopmentJwks(); },
  };
  const config = loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_SIGNING_KEY_PROVIDERS_JSON: JSON.stringify({ master: {
      provider: 'pkcs11', algorithm: 'RS256', material_reference: 'pkcs11:object=overlap-test',
    } }),
  });
  const manager = createSigningKeyManager({
    config, realm: 'master', management: new MemoryManagementStore(['master']), adapters: { pkcs11: adapter },
  });
  await manager.load();
  await assert.rejects(manager.rotate({ force: true }), /removed the previous signing key/iu);
});
