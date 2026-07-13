import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as OTPAuth from 'otpauth';

import {
  createRecoveryCodes,
  createTotp,
  normalizeRecoveryCode,
  recoveryCodeDigest,
  totpStep,
  verifyTotp,
} from '../src/crypto/mfa.js';
import { MemoryIdentityStore } from '../src/repositories/identity-store.js';

test('generated TOTP enrollment data produces verifiable six-digit tokens', () => {
  const enrollment = createTotp({ issuer: 'AuthMe', accountName: 'alice@example.test' });
  const totp = new OTPAuth.TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });
  const token = totp.generate();

  assert.match(enrollment.secret, /^[A-Z2-7]+$/);
  assert.match(enrollment.uri, /^otpauth:\/\/totp\//);
  assert.match(token, /^\d{6}$/);
  assert.equal(verifyTotp(enrollment.secret, token), true);
  assert.equal(verifyTotp(enrollment.secret, '12345'), false);
  assert.equal(verifyTotp('not-base32!', token), false);
  assert.equal(Number.isSafeInteger(totpStep(enrollment.secret, token)), true);
});

test('a TOTP time step can be consumed only once', async () => {
  const store = new MemoryIdentityStore();
  const user = await store.createUser({
    realm: 'master', username: 'replay-test', email: 'replay@example.test', passwordHash: 'unused',
  });
  const step = 123456;
  const attempts = await Promise.all([
    store.consumeTotpStep('master', user.id, step),
    store.consumeTotpStep('master', user.id, step),
  ]);
  assert.deepEqual(attempts.sort(), [false, true]);
  assert.equal(await store.consumeTotpStep('master', user.id, step - 1), false);
  assert.equal(await store.consumeTotpStep('master', user.id, step + 1), true);
});

test('TOTP rotation preserves the active factor and confirms atomically', async () => {
  const store = new MemoryIdentityStore();
  const user = await store.createUser({
    realm: 'master', username: 'rotation-test', email: 'rotation@example.test', passwordHash: 'unused',
    totpSecret: 'active-secret', totpConfirmed: true, recoveryCodeHashes: ['old-code'],
  });
  await store.beginTotpEnrollment('master', user.id, 'pending-secret');
  let current = await store.findUserById('master', user.id);
  assert.equal(current.totpSecret, 'active-secret');
  assert.equal(current.totpConfirmed, true);
  assert.equal(current.pendingTotpSecret, 'pending-secret');

  const attempts = await Promise.all([
    store.confirmTotpEnrollment('master', user.id, {
      pendingSecret: 'pending-secret', activeSecret: 'new-active-secret', step: 100, recoveryCodeHashes: ['new-a'],
    }),
    store.confirmTotpEnrollment('master', user.id, {
      pendingSecret: 'pending-secret', activeSecret: 'new-active-secret', step: 100, recoveryCodeHashes: ['new-b'],
    }),
  ]);
  assert.deepEqual(attempts.sort(), [false, true]);
  current = await store.findUserById('master', user.id);
  assert.equal(current.totpSecret, 'new-active-secret');
  assert.equal(current.pendingTotpSecret, null);
  assert.equal(current.lastTotpStep, 100);
  assert.equal(current.recoveryCodeHashes.length, 1);
  assert.match(current.recoveryCodeHashes[0], /^new-[ab]$/);
});

test('recovery codes normalize consistently and are stored as keyed digests', () => {
  const digestKey = 'recovery-code-digest-key';
  const { codes, digests } = createRecoveryCodes(digestKey, 6);

  assert.equal(codes.length, 6);
  assert.equal(new Set(codes).size, 6);
  assert.equal(digests.length, 6);
  for (const [index, code] of codes.entries()) {
    assert.match(code, /^[0-9A-F]{5}(?:-[0-9A-F]{5}){3}$/);
    assert.equal(digests[index], recoveryCodeDigest(code, digestKey));
    assert.equal(
      recoveryCodeDigest(` ${code.toLowerCase().replaceAll('-', ' ')} `, digestKey),
      digests[index],
    );
  }
  assert.equal(normalizeRecoveryCode(' ab-cd 12! '), 'ABCD12');
});

test('a recovery code can be consumed exactly once and only in its realm', async () => {
  const store = new MemoryIdentityStore();
  const digestKey = 'recovery-code-digest-key';
  const { codes, digests } = createRecoveryCodes(digestKey, 2);
  const user = await store.createUser({
    id: '3cd2d887-6fc7-41ce-a02f-07558cb79937',
    realm: 'master',
    username: 'alice',
    email: 'alice@example.test',
    passwordHash: 'not-used-in-this-test',
  });
  await store.configureTotp('master', user.id, {
    secret: 'encrypted-totp-secret',
    confirmed: true,
    recoveryCodeHashes: digests,
  });

  const firstDigest = recoveryCodeDigest(codes[0], digestKey);
  assert.equal(await store.consumeRecoveryCode('other', user.id, firstDigest), false);
  const competingAttempts = await Promise.all([
    store.consumeRecoveryCode('master', user.id, firstDigest),
    store.consumeRecoveryCode('master', user.id, firstDigest),
  ]);
  assert.deepEqual(competingAttempts.sort(), [false, true]);
  assert.equal(await store.consumeRecoveryCode('master', user.id, firstDigest), false);

  const remaining = await store.findUserById('master', user.id);
  assert.deepEqual(remaining.recoveryCodeHashes, [digests[1]]);
});
