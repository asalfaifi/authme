import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import pg from 'pg';

import { createDataLayer } from '../src/db.js';
import { loadMigrationManifest, verifyMigrationState } from '../src/migrations.js';

const databaseUrl = process.env.DATABASE_URL;
let client;
let manifest;

before(async () => {
  if (!databaseUrl) return;
  client = new pg.Client({ connectionString: databaseUrl, application_name: 'authme-migration-test' });
  await client.connect();
  manifest = await loadMigrationManifest();
});

after(async () => {
  await client?.end();
});

test('the migrated PostgreSQL schema matches the release manifest', { skip: !databaseUrl }, async () => {
  assert.equal(await verifyMigrationState(client, manifest), true);
});

test('live verification rejects missing, modified, and unknown migration state', { skip: !databaseUrl }, async () => {
  await client.query('BEGIN');
  try {
    await client.query("SET LOCAL search_path TO pg_temp");
    await assert.rejects(
      verifyMigrationState(client, manifest),
      (error) => error.code === 'AUTHME_SCHEMA_MISMATCH' && /schema_migrations is missing/.test(error.message),
    );
  } finally {
    await client.query('ROLLBACK');
  }

  await client.query('BEGIN');
  try {
    await client.query(
      'UPDATE schema_migrations SET checksum=$2 WHERE name=$1',
      [manifest[0].name, 'intentionally-invalid-for-test'],
    );
    await client.query(
      "INSERT INTO schema_migrations (name, checksum) VALUES ('999_unknown.sql', 'unknown')",
    );
    await assert.rejects(
      verifyMigrationState(client, manifest),
      (error) => error.code === 'AUTHME_SCHEMA_MISMATCH'
        && error.message.includes(`checksum mismatches: ${manifest[0].name}`)
        && /unknown migrations: 999_unknown.sql/.test(error.message),
    );
  } finally {
    await client.query('ROLLBACK');
  }
});

test('production data-layer startup fails closed before using a mismatched schema', { skip: !databaseUrl }, async () => {
  const schema = `authme_mismatch_${randomUUID().replaceAll('-', '')}`;
  const isolatedUrl = new URL(databaseUrl);
  isolatedUrl.searchParams.set('options', `-c search_path=${schema}`);
  await client.query(`CREATE SCHEMA ${schema}`);
  try {
    await assert.rejects(
      createDataLayer({ databaseUrl: isolatedUrl.toString(), devMode: false, realms: ['master'] }),
      (error) => error.code === 'AUTHME_SCHEMA_MISMATCH' && /schema_migrations is missing/.test(error.message),
    );

    await client.query(`CREATE TABLE ${schema}.schema_migrations (
      name TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);
    await client.query(
      `INSERT INTO ${schema}.schema_migrations (name, checksum) VALUES ($1, $2), ($3, $4)`,
      [manifest[0].name, 'modified', '999_unknown.sql', 'unknown'],
    );
    await assert.rejects(
      createDataLayer({ databaseUrl: isolatedUrl.toString(), devMode: false, realms: ['master'] }),
      (error) => error.code === 'AUTHME_SCHEMA_MISMATCH'
        && error.message.includes(`checksum mismatches: ${manifest[0].name}`)
        && /unknown migrations: 999_unknown.sql/.test(error.message),
    );
  } finally {
    await client.query(`DROP SCHEMA ${schema} CASCADE`);
  }
});
