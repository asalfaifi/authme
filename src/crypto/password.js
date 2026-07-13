import argon2 from 'argon2';

const options = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
});

function peppered(password, pepper) {
  return `${password}\u0000${pepper}`;
}

export async function hashPassword(password, pepper) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 1024) {
    throw new Error('Passwords must be between 12 and 1024 characters');
  }
  return argon2.hash(peppered(password, pepper), options);
}

export async function verifyPassword(hash, password, pepper) {
  if (typeof hash !== 'string' || typeof password !== 'string' || password.length > 1024) return false;
  try {
    return await argon2.verify(hash, peppered(password, pepper), options);
  } catch {
    return false;
  }
}

export function needsPasswordRehash(hash) {
  try {
    return argon2.needsRehash(hash, options);
  } catch {
    return true;
  }
}
