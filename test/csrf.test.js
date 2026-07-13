import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createCsrfToken, verifyCsrfToken } from '../src/crypto/csrf.js';

const now = Date.UTC(2026, 6, 13, 12, 0, 0);
const subject = 'master:interaction-id:login';
const secret = 'csrf-secret-with-at-least-thirty-two-bytes';

function changeLastCharacter(value) {
  return `${value.slice(0, -1)}${value.endsWith('A') ? 'B' : 'A'}`;
}

test('CSRF tokens are bound to their subject, secret, and age', () => {
  const token = createCsrfToken(subject, secret, now);

  assert.equal(verifyCsrfToken(token, subject, secret, now), true);
  assert.equal(verifyCsrfToken(token, subject, secret, now + 600_000), true);
  assert.equal(verifyCsrfToken(token, subject, secret, now + 601_000), false);
  assert.equal(verifyCsrfToken(token, `${subject}:other`, secret, now), false);
  assert.equal(verifyCsrfToken(token, subject, `${secret}:other`, now), false);
});

test('CSRF payload and signature tampering are rejected', () => {
  const token = createCsrfToken(subject, secret, now);
  const parts = token.split('.');

  const changedNonce = [...parts];
  changedNonce[2] = changeLastCharacter(changedNonce[2]);
  assert.equal(verifyCsrfToken(changedNonce.join('.'), subject, secret, now), false);

  const changedTimestamp = [...parts];
  changedTimestamp[1] = String(Number(changedTimestamp[1]) - 1);
  assert.equal(verifyCsrfToken(changedTimestamp.join('.'), subject, secret, now), false);

  const changedSignature = [...parts];
  changedSignature[3] = changeLastCharacter(changedSignature[3]);
  assert.equal(verifyCsrfToken(changedSignature.join('.'), subject, secret, now), false);
});

test('CSRF verification rejects malformed and excessively future-dated tokens', () => {
  const futureToken = createCsrfToken(subject, secret, now + 31_000);

  assert.equal(verifyCsrfToken(futureToken, subject, secret, now), false);
  assert.equal(verifyCsrfToken(null, subject, secret, now), false);
  assert.equal(verifyCsrfToken('only.three.parts', subject, secret, now), false);
  assert.equal(verifyCsrfToken('x'.repeat(513), subject, secret, now), false);
});
