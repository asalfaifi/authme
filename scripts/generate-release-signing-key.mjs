#!/usr/bin/env node
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve } from 'node:path';

function outputDirectory(argv) {
  if (argv.length !== 2 || argv[0] !== '--output-directory' || !argv[1] || argv[1].startsWith('--')) {
    throw new Error('usage: npm run release:key:generate -- --output-directory <new-directory>');
  }
  return resolve(argv[1]);
}

const directory = outputDirectory(process.argv.slice(2));
const repository = resolve('.');
const repositoryRelative = relative(repository, directory);
if (!repositoryRelative.startsWith('..') && !isAbsolute(repositoryRelative)) {
  throw new Error('release signing keys must be generated outside the repository');
}
await mkdir(directory, { mode: 0o700 });
await chmod(directory, 0o700);

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicExponent: 0x10001,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const privateKeyPath = join(directory, 'authme-release-key.pem');
const publicKeyPath = join(directory, 'authme-release-public-key.pem');
const fingerprintPath = join(directory, 'authme-release-key-fingerprint.txt');
const publicDer = createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
const fingerprint = `SHA256:${createHash('sha256').update(publicDer).digest('hex')}`;

await writeFile(privateKeyPath, privateKey, { flag: 'wx', mode: 0o600 });
await chmod(privateKeyPath, 0o600);
await writeFile(publicKeyPath, publicKey, { flag: 'wx', mode: 0o644 });
await writeFile(fingerprintPath, `${fingerprint}\n`, { flag: 'wx', mode: 0o644 });

process.stdout.write(`${JSON.stringify({
  algorithm: 'RSA',
  key_size_bits: 4096,
  private_key: privateKeyPath,
  public_key: publicKeyPath,
  fingerprint_file: fingerprintPath,
  fingerprint,
}, null, 2)}\n`);
