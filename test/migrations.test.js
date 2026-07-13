import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { join } from 'node:path';

import {
  loadMigrationManifest,
  migrationsDirectory,
  verifyMigrationHistory,
  verifyMigrationState,
} from '../src/migrations.js';

function queryableWith(rows) {
  return {
    calls: [],
    async query(text) {
      this.calls.push(text);
      return { rows };
    },
  };
}

test('migration manifest is ordered and binds each file to its SHA-256 checksum', async () => {
  const manifest = await loadMigrationManifest();
  assert.ok(manifest.length > 0);
  assert.deepEqual(
    manifest.map(({ name }) => name),
    [...manifest.map(({ name }) => name)].sort(),
  );

  for (const entry of manifest) {
    const sql = await readFile(join(migrationsDirectory, entry.name), 'utf8');
    assert.equal(entry.sql, sql);
    assert.equal(entry.checksum, createHash('sha256').update(sql).digest('hex'));
    assert.ok(Object.isFrozen(entry));
  }
});

test('schema verification accepts only the exact applied migration set', async () => {
  const manifest = [
    { name: '001_initial.sql', checksum: 'checksum-one' },
    { name: '002_security.sql', checksum: 'checksum-two' },
  ];
  const database = queryableWith(manifest.map(({ name, checksum }) => ({ name, checksum })));

  assert.equal(await verifyMigrationState(database, manifest), true);
  assert.deepEqual(database.calls, ['SELECT name, checksum FROM schema_migrations ORDER BY name']);
});

test('schema verification rejects missing, pending, modified, and unknown migrations', async () => {
  const manifest = [
    { name: '001_initial.sql', checksum: 'checksum-one' },
    { name: '002_security.sql', checksum: 'checksum-two' },
  ];

  await assert.rejects(
    verifyMigrationState({
      async query() { throw Object.assign(new Error('missing'), { code: '42P01' }); },
    }, manifest),
    (error) => error.code === 'AUTHME_SCHEMA_MISMATCH' && /schema_migrations is missing/.test(error.message),
  );

  await assert.rejects(
    verifyMigrationState(queryableWith([
      { name: '001_initial.sql', checksum: 'changed' },
      { name: '999_future.sql', checksum: 'future' },
    ]), manifest),
    (error) => error.code === 'AUTHME_SCHEMA_MISMATCH'
      && /pending migrations: 002_security.sql/.test(error.message)
      && /checksum mismatches: 001_initial.sql/.test(error.message)
      && /unknown migrations: 999_future.sql/.test(error.message),
  );
});

test('schema verification wraps unreadable migration metadata as a startup mismatch', async () => {
  const failure = Object.assign(new Error('permission denied'), { code: '42501' });
  await assert.rejects(
    verifyMigrationState({ async query() { throw failure; } }, []),
    (error) => error.code === 'AUTHME_SCHEMA_MISMATCH'
      && error.cause === failure
      && /could not be read/.test(error.message),
  );
});

test('migration preflight permits pending known files but rejects incompatible history before applying them', async () => {
  const manifest = [
    { name: '001_initial.sql', checksum: 'checksum-one' },
    { name: '002_pending.sql', checksum: 'checksum-two' },
  ];
  assert.equal(await verifyMigrationHistory(queryableWith([
    { name: '001_initial.sql', checksum: 'checksum-one' },
  ]), manifest), true);

  await assert.rejects(
    verifyMigrationHistory(queryableWith([
      { name: '001_initial.sql', checksum: 'changed' },
      { name: '999_unknown.sql', checksum: 'unknown' },
    ]), manifest),
    (error) => error.code === 'AUTHME_SCHEMA_MISMATCH'
      && /checksum mismatches: 001_initial.sql/.test(error.message)
      && /unknown migrations: 999_unknown.sql/.test(error.message)
      && /refusing to apply pending migrations/.test(error.message),
  );
});
