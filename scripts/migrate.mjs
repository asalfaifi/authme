import pg from 'pg';
import { loadMigrationManifest, verifyMigrationHistory, verifyMigrationState } from '../src/migrations.js';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const manifest = await loadMigrationManifest();
const pool = new pg.Pool({ connectionString: databaseUrl, max: 1, application_name: 'authme-migrate' });
const client = await pool.connect();

try {
  await client.query("SELECT pg_advisory_lock(hashtext('authme-schema-migrations'))");
  await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await verifyMigrationHistory(client, manifest);
  for (const { name, sql, checksum } of manifest) {
    const existing = await client.query('SELECT checksum FROM schema_migrations WHERE name=$1', [name]);
    if (existing.rows[0]) {
      if (existing.rows[0].checksum !== checksum) throw new Error(`Applied migration ${name} has been modified`);
      console.log(`skip ${name}`);
      continue;
    }
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1,$2)', [name, checksum]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
    console.log(`apply ${name}`);
  }
  await verifyMigrationState(client, manifest);
} finally {
  await client.query("SELECT pg_advisory_unlock(hashtext('authme-schema-migrations'))").catch(() => {});
  client.release();
  await pool.end();
}
