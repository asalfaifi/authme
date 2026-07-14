import { spawn } from 'node:child_process';
import pg from 'pg';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error('DATABASE_URL is required for PostgreSQL release tests');
}

const client = new pg.Client({ connectionString: databaseUrl, application_name: 'authme-test-preflight' });
try {
  await client.connect();
  await client.query('SELECT 1');
} catch (error) {
  throw new Error('PostgreSQL release-test database is unavailable', { cause: error });
} finally {
  await client.end().catch(() => {});
}

const child = spawn(process.execPath, [
  '--test',
  '--test-reporter=spec',
  'test/postgres-adapter.test.js',
  'test/postgres-admin-console.test.js',
  'test/postgres-concurrency.test.js',
  'test/postgres-federated-identities.test.js',
  'test/postgres-migrations.test.js',
  'test/postgres-scim.test.js',
  'test/postgres-webauthn.test.js',
], {
  env: process.env,
  stdio: 'inherit',
});

const exitCode = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('exit', (code, signal) => {
    if (signal) reject(new Error(`PostgreSQL tests terminated by ${signal}`));
    else resolve(code ?? 1);
  });
});
process.exitCode = exitCode;
