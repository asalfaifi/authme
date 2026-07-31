#!/usr/bin/env node
import { restoreEncryptedBackup, backupEncryptionKey } from '../src/operations/backup.js';
import { loadMigrationManifest } from '../src/migrations.js';

function option(name) { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; }
const inputDirectory = option('--input');
if (!inputDirectory || !process.argv.includes('--confirm-destructive-restore')) {
  throw new Error('Usage: node scripts/restore.mjs --input /protected/backup --jwks-dir /restore/keys --confirm-destructive-restore');
}
const manifest = await restoreEncryptedBackup({
  databaseUrl: process.env.DATABASE_URL,
  inputDirectory,
  jwksDirectory: option('--jwks-dir'),
  encryptionKey: backupEncryptionKey(process.env.AUTHME_BACKUP_ENCRYPTION_KEY),
  expectedMigrations: await loadMigrationManifest(),
});
process.stdout.write(`${JSON.stringify({ status: 'restored', createdAt: manifest.createdAt, version: manifest.version })}\n`);
