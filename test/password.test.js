import assert from 'node:assert/strict';
import { test } from 'node:test';
import argon2 from 'argon2';

import { hashPassword, needsPasswordRehash, verifyPassword } from '../src/crypto/password.js';

const password = 'correct horse battery staple';
const pepper = 'deployment-pepper-that-is-not-in-the-database';

test('password hashes verify only with the matching password and pepper', { timeout: 30_000 }, async () => {
  const hash = await hashPassword(password, pepper);

  assert.equal(await verifyPassword(hash, password, pepper), true);
  assert.equal(await verifyPassword(hash, 'wrong password value', pepper), false);
  assert.equal(await verifyPassword(hash, password, `${pepper}-rotated`), false);
  assert.equal(await verifyPassword('not-an-argon2-hash', password, pepper), false);
  assert.equal(await verifyPassword(hash, 1234, pepper), false);
  assert.equal(await verifyPassword(hash, 'x'.repeat(1025), pepper), false);
});

test('current hashes do not need rehashing while valid legacy parameters do', { timeout: 30_000 }, async () => {
  const currentHash = await hashPassword(password, pepper);
  const legacyHash = await argon2.hash(`${password}\u0000${pepper}`, {
    type: argon2.argon2id,
    memoryCost: 8192,
    timeCost: 1,
    parallelism: 1,
    hashLength: 16,
  });

  assert.equal(needsPasswordRehash(currentHash), false);
  assert.equal(await verifyPassword(legacyHash, password, pepper), true);
  assert.equal(needsPasswordRehash(legacyHash), true);
  assert.equal(needsPasswordRehash('malformed-hash'), true);
});

test('new passwords enforce the documented length boundary', async () => {
  await assert.rejects(hashPassword('too-short', pepper), /between 12 and 1024 characters/);
  await assert.rejects(hashPassword('x'.repeat(1025), pepper), /between 12 and 1024 characters/);
});
