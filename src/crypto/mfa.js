import { randomBytes } from 'node:crypto';
import * as OTPAuth from 'otpauth';
import { keyedDigest } from './secrets.js';

export function createTotp({ issuer, accountName }) {
  const totp = new OTPAuth.TOTP({
    issuer,
    label: accountName,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: new OTPAuth.Secret({ size: 20 }),
  });
  return { secret: totp.secret.base32, uri: totp.toString() };
}

export function totpStep(secret, token, timestamp = Date.now()) {
  if (!/^[0-9]{6}$/.test(String(token ?? ''))) return null;
  try {
    const totp = new OTPAuth.TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });
    const delta = totp.validate({ token: String(token), timestamp, window: 1 });
    return delta === null ? null : Math.floor(timestamp / 30_000) + delta;
  } catch {
    return null;
  }
}

export function verifyTotp(secret, token, timestamp = Date.now()) {
  return totpStep(secret, token, timestamp) !== null;
}

export function createRecoveryCodes(digestKey, count = 10) {
  const codes = Array.from({ length: count }, () => {
    const raw = randomBytes(10).toString('hex').toUpperCase();
    return `${raw.slice(0, 5)}-${raw.slice(5, 10)}-${raw.slice(10, 15)}-${raw.slice(15)}`;
  });
  return { codes, digests: codes.map((code) => keyedDigest(normalizeRecoveryCode(code), digestKey)) };
}

export function normalizeRecoveryCode(code) {
  return String(code ?? '').replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
}

export function recoveryCodeDigest(code, digestKey) {
  return keyedDigest(normalizeRecoveryCode(code), digestKey);
}
