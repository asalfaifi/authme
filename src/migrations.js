import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const defaultDirectory = fileURLToPath(new URL('../migrations', import.meta.url));
const migrationName = /^\d+_.+\.sql$/;

function schemaMismatch(message, cause) {
  return Object.assign(new Error(`Database schema verification failed: ${message}`, cause ? { cause } : undefined), {
    code: 'AUTHME_SCHEMA_MISMATCH',
  });
}

export async function loadMigrationManifest(directory = defaultDirectory) {
  const names = (await readdir(directory))
    .filter((name) => migrationName.test(name))
    .sort();
  if (!names.length) throw schemaMismatch('the release contains no migrations');

  return Promise.all(names.map(async (name) => {
    const sql = await readFile(join(directory, name), 'utf8');
    return Object.freeze({
      name,
      checksum: createHash('sha256').update(sql).digest('hex'),
      sql,
    });
  }));
}

export async function verifyMigrationState(queryable, manifest) {
  const expectedManifest = manifest ?? await loadMigrationManifest();
  let rows;
  try {
    ({ rows } = await queryable.query('SELECT name, checksum FROM schema_migrations ORDER BY name'));
  } catch (error) {
    if (error?.code === '42P01') {
      throw schemaMismatch('schema_migrations is missing; run `npm run db:migrate` before starting AuthMe', error);
    }
    throw schemaMismatch('the schema_migrations table could not be read', error);
  }

  const expected = new Map(expectedManifest.map(({ name, checksum }) => [name, checksum]));
  const applied = new Map(rows.map(({ name, checksum }) => [name, checksum]));
  const pending = [...expected.keys()].filter((name) => !applied.has(name));
  const modified = [...expected].filter(([name, checksum]) => applied.has(name) && applied.get(name) !== checksum)
    .map(([name]) => name);
  const unknown = [...applied.keys()].filter((name) => !expected.has(name));

  const problems = [];
  if (pending.length) problems.push(`pending migrations: ${pending.join(', ')}`);
  if (modified.length) problems.push(`checksum mismatches: ${modified.join(', ')}`);
  if (unknown.length) problems.push(`unknown migrations: ${unknown.join(', ')}`);
  if (problems.length) {
    throw schemaMismatch(`${problems.join('; ')}; deploy the matching application and migration set`);
  }

  return true;
}

export async function verifyMigrationHistory(queryable, manifest) {
  const expectedManifest = manifest ?? await loadMigrationManifest();
  let rows;
  try {
    ({ rows } = await queryable.query('SELECT name, checksum FROM schema_migrations ORDER BY name'));
  } catch (error) {
    throw schemaMismatch('the schema_migrations table could not be read', error);
  }

  const expected = new Map(expectedManifest.map(({ name, checksum }) => [name, checksum]));
  const modified = rows
    .filter(({ name, checksum }) => expected.has(name) && expected.get(name) !== checksum)
    .map(({ name }) => name);
  const unknown = rows.filter(({ name }) => !expected.has(name)).map(({ name }) => name);
  const problems = [];
  if (modified.length) problems.push(`checksum mismatches: ${modified.join(', ')}`);
  if (unknown.length) problems.push(`unknown migrations: ${unknown.join(', ')}`);
  if (problems.length) {
    throw schemaMismatch(`${problems.join('; ')}; refusing to apply pending migrations to an incompatible history`);
  }
  return true;
}

export { defaultDirectory as migrationsDirectory };
