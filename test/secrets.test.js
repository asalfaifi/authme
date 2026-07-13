import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  decryptSecret,
  encryptSecret,
  keyedDigest,
  randomToken,
  safeEqual,
} from '../src/crypto/secrets.js';

const key = Buffer.alloc(32, 0x11);
const otherKey = Buffer.alloc(32, 0x22);
const context = 'master:8d416ea3-7548-44fe-ae81-584c1190f72f:totp';

test('field encryption round-trips and uses a fresh nonce', () => {
  const plaintext = 'JBSWY3DPEHPK3PXP';
  const first = encryptSecret(plaintext, key, context);
  const second = encryptSecret(plaintext, key, context);

  assert.notEqual(first, second);
  assert.equal(decryptSecret(first, key, context), plaintext);
  assert.equal(decryptSecret(second, key, context), plaintext);
  assert.equal(decryptSecret(encryptSecret('', key, context), key, context), '');
});

test('field encryption is separated by context and key', () => {
  const encrypted = encryptSecret('realm-bound secret', key, context);

  assert.throws(() => decryptSecret(encrypted, key, `${context}:different`));
  assert.throws(() => decryptSecret(encrypted, otherKey, context));
});

test('field encryption detects ciphertext, tag, and format tampering', () => {
  const encrypted = encryptSecret('authenticated secret', key, context);
  const ciphertextTamper = Buffer.from(encrypted, 'base64url');
  ciphertextTamper[ciphertextTamper.length - 1] ^= 0x01;

  const tagTamper = Buffer.from(encrypted, 'base64url');
  tagTamper[13] ^= 0x01;

  const versionTamper = Buffer.from(encrypted, 'base64url');
  versionTamper[0] = 2;

  assert.throws(() => decryptSecret(ciphertextTamper.toString('base64url'), key, context));
  assert.throws(() => decryptSecret(tagTamper.toString('base64url'), key, context));
  assert.throws(
    () => decryptSecret(versionTamper.toString('base64url'), key, context),
    /Unsupported encrypted secret format/,
  );
  assert.throws(() => decryptSecret('too-short', key, context), /Unsupported encrypted secret format/);
});

test('token and digest helpers preserve their security boundaries', () => {
  const token = randomToken(24);

  assert.equal(Buffer.from(token, 'base64url').length, 24);
  assert.equal(keyedDigest('value', 'key'), keyedDigest('value', 'key'));
  assert.notEqual(keyedDigest('value', 'key'), keyedDigest('value', 'other-key'));
  assert.equal(safeEqual('same-value', 'same-value'), true);
  assert.equal(safeEqual('same-value', 'different-value'), false);
  assert.equal(safeEqual('a', 'longer'), false);
});
