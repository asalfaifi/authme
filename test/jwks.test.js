import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { generateDevelopmentJwks, loadRealmJwks } from '../src/crypto/jwks.js';

test('development JWKS generation returns an extractable private signing key', { timeout: 30_000 }, async () => {
  const jwks = await generateDevelopmentJwks();

  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].kty, 'RSA');
  assert.equal(jwks.keys[0].alg, 'RS256');
  assert.equal(jwks.keys[0].use, 'sig');
  assert.equal(jwks.keys[0].key_ops, undefined);
  assert.ok(jwks.keys[0].kid);
  assert.ok(jwks.keys[0].d);
});

test('development mode generates a JWKS when no directory is configured', { timeout: 30_000 }, async () => {
  const jwks = await loadRealmJwks({ devMode: true, jwksDir: undefined }, 'master');

  assert.equal(jwks.keys.length, 1);
  assert.ok(jwks.keys[0].d);
});

test('realm JWKS loading accepts private signing keys and rejects unsafe sets', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'authme-jwks-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'master.json');
  const config = { devMode: false, jwksDir: directory };
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const validKey = {
    ...privateKey.export({ format: 'jwk' }),
    kid: '2026-rotation-a',
    use: 'sig',
    key_ops: ['sign'],
    alg: 'RS256',
  };

  await writeFile(path, JSON.stringify({ keys: [validKey] }));
  assert.deepEqual(await loadRealmJwks(config, 'master'), { keys: [validKey] });

  const invalidSets = [
    [{ keys: [] }, /non-empty JWK Set/],
    [{ keys: [{ ...validKey, d: undefined }] }, /private signing keys/],
    [{ keys: [validKey, { ...validKey }] }, /missing or duplicate kid/],
    [{ keys: [{ ...validKey, use: 'enc' }] }, /not explicitly intended for signing/],
    [{ keys: [{ ...validKey, key_ops: ['verify'] }] }, /not explicitly intended for signing/],
    [{ keys: [{ ...validKey, alg: 'HS256' }] }, /unsupported or missing algorithm HS256/],
    [{ keys: [{ ...validKey, alg: 'ES256' }] }, /does not match ES256/],
  ];

  for (const [jwks, expectedError] of invalidSets) {
    await writeFile(path, JSON.stringify(jwks));
    await assert.rejects(loadRealmJwks(config, 'master'), expectedError);
  }

  await writeFile(path, '{not-json');
  await assert.rejects(loadRealmJwks(config, 'master'), /Unable to load realm key set/);

  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({ format: 'jwk' });
  await writeFile(path, JSON.stringify({ keys: [{ ...weak, kid: 'weak', use: 'sig', key_ops: ['sign'], alg: 'RS256' }] }));
  await assert.rejects(loadRealmJwks(config, 'master'), /smaller than 2048 bits/);
});
