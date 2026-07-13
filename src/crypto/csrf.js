import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

function signature(payload, secret) {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

export function createCsrfToken(subject, secret, now = Date.now()) {
  const payload = `${subject}.${Math.floor(now / 1000)}.${randomBytes(18).toString('base64url')}`;
  return `${payload}.${signature(payload, secret)}`;
}

export function verifyCsrfToken(token, subject, secret, now = Date.now(), maxAgeSeconds = 600) {
  if (typeof token !== 'string' || token.length > 512) return false;
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== subject) return false;
  const timestamp = Number(parts[1]);
  if (!Number.isSafeInteger(timestamp)) return false;
  const age = Math.floor(now / 1000) - timestamp;
  if (age < -30 || age > maxAgeSeconds) return false;
  const payload = parts.slice(0, 3).join('.');
  const expected = Buffer.from(signature(payload, secret));
  const actual = Buffer.from(parts[3]);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
