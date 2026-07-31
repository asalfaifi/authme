#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { createEncryptedBackup, backupEncryptionKey } from '../src/operations/backup.js';
import { loadMigrationManifest } from '../src/migrations.js';

function option(name) { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; }

const outputDirectory = option('--output');
if (!outputDirectory) throw new Error('Usage: node scripts/backup.mjs --output /protected/path [--jwks-dir /protected/jwks]');
const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const manifest = await createEncryptedBackup({
  databaseUrl: process.env.DATABASE_URL,
  outputDirectory,
  jwksDirectory: option('--jwks-dir') ?? process.env.AUTHME_JWKS_DIR,
  encryptionKey: backupEncryptionKey(process.env.AUTHME_BACKUP_ENCRYPTION_KEY),
  migrationManifest: await loadMigrationManifest(),
  version: packageJson.version,
});
process.stdout.write(`${JSON.stringify({ status: 'created', outputDirectory, createdAt: manifest.createdAt, files: manifest.files.length })}\n`);
