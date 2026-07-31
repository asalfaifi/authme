#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { exportJWK, generateKeyPair } from 'jose';
import { validateJwks } from '../src/crypto/jwks.js';

function option(name) { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; }
const realm = option('--realm');
const directory = option('--jwks-dir') ?? process.env.AUTHME_JWKS_DIR;
const algorithm = option('--algorithm') ?? 'RS256';
if (!realm || !directory || !['RS256', 'PS256', 'ES256'].includes(algorithm)) throw new Error('Usage: node scripts/rotate-jwks.mjs --realm master --jwks-dir /protected/keys [--algorithm RS256]');
const path = join(directory, `${realm}.json`);
const current = await validateJwks(JSON.parse(await readFile(path, 'utf8')), path);
const options = algorithm === 'ES256' ? { crv: 'P-256', extractable: true } : { modulusLength: 3072, extractable: true };
const { privateKey } = await generateKeyPair(algorithm, options);
const next = { ...await exportJWK(privateKey), kid: randomBytes(16).toString('base64url'), alg: algorithm, use: 'sig' };
const rotated = await validateJwks({ keys: [next, ...current.keys.slice(0, 1)] }, `${path} rotation`);
const temporary = `${path}.new-${process.pid}`;
await writeFile(temporary, `${JSON.stringify(rotated, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
await chmod(temporary, 0o600);
await rename(temporary, path);
process.stdout.write(`${JSON.stringify({ realm, activeKid: next.kid, retainedKids: rotated.keys.slice(1).map((key) => key.kid), activation: 'rolling-restart-required' })}\n`);
