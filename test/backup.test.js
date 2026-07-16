import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import {
  backupEncryptionKey,
  createEncryptedBackup,
  restoreEncryptedBackup,
  verifyBackup,
} from '../src/operations/backup.js';

let root;
const key = backupEncryptionKey(Buffer.alloc(32, 7).toString('base64url'));
const migrations = [{ id: '001_initial.sql', checksum: 'a'.repeat(64) }];

before(async () => { root = await mkdtemp(join(tmpdir(), 'authme-backup-test-')); });
after(async () => rm(root, { recursive: true, force: true }));

test('backup encrypts database and key material, verifies checksums, and restores through pg_restore', async () => {
  const jwks = join(root, 'source-jwks');
  await mkdir(jwks);
  await writeFile(join(jwks, 'master.json'), '{"keys":[{"kid":"not-a-real-test-key"}]}');
  const backup = join(root, 'backup');
  const commands = [];
  const command = async (name, args) => {
    commands.push({ name, args });
    if (name === 'pg_dump') await writeFile(args[args.indexOf('--file') + 1], 'sensitive database bytes');
    if (name === 'pg_restore') assert.equal(await readFile(args.at(-1), 'utf8'), 'sensitive database bytes');
  };
  await createEncryptedBackup({ databaseUrl: 'postgresql://test', outputDirectory: backup, jwksDirectory: jwks, encryptionKey: key, migrationManifest: migrations, version: '1.0.0', command });
  const manifest = await verifyBackup(backup);
  assert.equal(manifest.files.length, 2);
  assert.doesNotMatch(await readFile(join(backup, 'database.dump.enc'), 'utf8'), /sensitive database bytes/u);
  const restoredJwks = join(root, 'restored-jwks');
  await restoreEncryptedBackup({ databaseUrl: 'postgresql://restore', inputDirectory: backup, jwksDirectory: restoredJwks, encryptionKey: key, expectedMigrations: migrations, command });
  assert.equal(await readFile(join(restoredJwks, 'master.json'), 'utf8'), '{"keys":[{"kid":"not-a-real-test-key"}]}');
  assert.deepEqual(commands.map(({ name }) => name), ['pg_dump', 'pg_restore']);
});

test('restore fails before command execution when an encrypted file is tampered with', async () => {
  const backup = join(root, 'tampered');
  const command = async (_name, args) => writeFile(args[args.indexOf('--file') + 1], 'dump');
  await createEncryptedBackup({ databaseUrl: 'postgresql://test', outputDirectory: backup, encryptionKey: key, migrationManifest: migrations, version: '1.0.0', command });
  await writeFile(join(backup, 'database.dump.enc'), 'tampered');
  let called = false;
  await assert.rejects(restoreEncryptedBackup({ databaseUrl: 'postgresql://restore', inputDirectory: backup, encryptionKey: key, expectedMigrations: migrations, command: async () => { called = true; } }), /checksum/iu);
  assert.equal(called, false);
});
