import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { access, chmod, mkdir, open, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { spawn } from 'node:child_process';

const backupFormat = 'authme-backup/v1';
const encryptedMagic = Buffer.from('AUTHMEB1');

export function backupEncryptionKey(value) {
  const decoded = Buffer.from(String(value ?? ''), 'base64url');
  if (decoded.length !== 32) throw new Error('AUTHME_BACKUP_ENCRYPTION_KEY must be a base64url-encoded 32-byte key');
  return decoded;
}

export async function runCommand(command, args, { env = process.env, cwd } = {}) {
  await new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'inherit', 'inherit'], shell: false });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0
      ? resolvePromise()
      : reject(new Error(`${command} failed with ${signal ? `signal ${signal}` : `exit code ${code}`}`)));
  });
}

export async function sha256File(path) {
  const hash = createHash('sha256');
  await pipeline(createReadStream(path), hash);
  return hash.digest('hex');
}

export async function encryptBackupFile(source, destination, key) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const handle = await open(destination, 'wx', 0o600);
  await handle.write(Buffer.concat([encryptedMagic, nonce]));
  const output = createWriteStream(destination, { fd: handle.fd, autoClose: false, flags: 'a' });
  try {
    await pipeline(createReadStream(source), cipher, output);
    await handle.write(cipher.getAuthTag());
  } finally {
    await handle.close();
  }
}

export async function decryptBackupFile(source, destination, key) {
  const details = await stat(source);
  if (details.size < encryptedMagic.length + 12 + 16) throw new Error(`Encrypted backup file is truncated: ${basename(source)}`);
  const handle = await open(source, 'r');
  const header = Buffer.alloc(encryptedMagic.length + 12);
  const tag = Buffer.alloc(16);
  await handle.read(header, 0, header.length, 0);
  await handle.read(tag, 0, tag.length, details.size - tag.length);
  await handle.close();
  if (!header.subarray(0, encryptedMagic.length).equals(encryptedMagic)) throw new Error(`Encrypted backup file has an invalid header: ${basename(source)}`);
  const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(encryptedMagic.length));
  decipher.setAuthTag(tag);
  await pipeline(
    createReadStream(source, { start: header.length, end: details.size - tag.length - 1 }),
    decipher,
    createWriteStream(destination, { flags: 'wx', mode: 0o600 }),
  );
}

async function copyEncrypted(source, staging, logicalName, key) {
  const destination = join(staging, `${logicalName}.enc`);
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  await encryptBackupFile(source, destination, key);
  return {
    logicalName,
    file: `${logicalName}.enc`,
    bytes: (await stat(destination)).size,
    sha256: await sha256File(destination),
  };
}

async function jsonFiles(root) {
  const result = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) result.push(...await jsonFiles(path));
    else if (entry.isFile() && entry.name.endsWith('.json')) result.push(path);
  }
  return result;
}

export async function createEncryptedBackup({
  databaseUrl,
  outputDirectory,
  jwksDirectory,
  encryptionKey,
  migrationManifest,
  version,
  command = runCommand,
  clock = () => new Date(),
}) {
  if (!databaseUrl) throw new Error('DATABASE_URL is required for a backup');
  const target = resolve(outputDirectory);
  const staging = `${target}.partial-${process.pid}-${randomBytes(5).toString('hex')}`;
  await mkdir(staging, { recursive: false, mode: 0o700 });
  const rawDump = join(staging, 'database.dump');
  try {
    await command('pg_dump', ['--format=custom', '--no-owner', '--no-acl', '--file', rawDump, databaseUrl]);
    const files = [await copyEncrypted(rawDump, staging, 'database.dump', encryptionKey)];
    await rm(rawDump, { force: true });
    if (jwksDirectory) {
      const root = resolve(jwksDirectory);
      for (const source of await jsonFiles(root)) {
        const logical = `jwks/${relative(root, source).split(sep).join('/')}`;
        files.push(await copyEncrypted(source, staging, logical, encryptionKey));
      }
    }
    files.sort((left, right) => left.logicalName.localeCompare(right.logicalName));
    const manifest = {
      format: backupFormat,
      version,
      createdAt: clock().toISOString(),
      encryption: 'AES-256-GCM',
      migrations: migrationManifest.map(({ id, checksum }) => ({ id, checksum })),
      files,
    };
    await writeFile(join(staging, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    await rename(staging, target);
    await chmod(target, 0o700);
    return manifest;
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyBackup(directory) {
  const root = resolve(directory);
  const manifest = JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8'));
  if (manifest.format !== backupFormat || manifest.encryption !== 'AES-256-GCM' || !Array.isArray(manifest.files)) {
    throw new Error('Backup manifest format is unsupported');
  }
  for (const file of manifest.files) {
    if (typeof file.logicalName !== 'string' || typeof file.file !== 'string'
      || file.file.includes('..') || resolve(root, file.file) !== join(root, file.file)) {
      throw new Error('Backup manifest contains an unsafe file path');
    }
    const path = join(root, file.file);
    const details = await stat(path);
    if (details.size !== file.bytes || await sha256File(path) !== file.sha256) {
      throw new Error(`Backup checksum verification failed for ${file.logicalName}`);
    }
  }
  return manifest;
}

export async function restoreEncryptedBackup({
  databaseUrl,
  inputDirectory,
  jwksDirectory,
  encryptionKey,
  expectedMigrations,
  command = runCommand,
}) {
  if (!databaseUrl) throw new Error('DATABASE_URL is required for a restore');
  const root = resolve(inputDirectory);
  const manifest = await verifyBackup(root);
  if (expectedMigrations) {
    const expected = JSON.stringify(expectedMigrations.map(({ id, checksum }) => ({ id, checksum })));
    if (JSON.stringify(manifest.migrations) !== expected) throw new Error('Backup migration manifest does not match this AuthMe build');
  }
  const staging = join(root, `.restore-${process.pid}-${randomBytes(5).toString('hex')}`);
  const stagedJwks = [];
  await mkdir(staging, { mode: 0o700 });
  try {
    const database = manifest.files.find((file) => file.logicalName === 'database.dump');
    if (!database) throw new Error('Backup does not contain database.dump');
    const jwks = manifest.files.filter((file) => file.logicalName.startsWith('jwks/'));
    if (jwks.length && !jwksDirectory) throw new Error('The backup contains signing keys; --jwks-dir is required to restore them');
    for (const file of jwks) {
      const destinationRoot = resolve(jwksDirectory);
      const destination = resolve(destinationRoot, file.logicalName.slice('jwks/'.length));
      if (!destination.startsWith(`${destinationRoot}${sep}`)) throw new Error('Backup contains an unsafe signing-key path');
      try {
        await access(destination);
        throw new Error(`Refusing to overwrite existing signing-key file ${destination}`);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    const dump = join(staging, 'database.dump');
    await decryptBackupFile(join(root, database.file), dump, encryptionKey);
    for (const file of jwks) {
      const relativeName = file.logicalName.slice('jwks/'.length);
      const destination = join(resolve(jwksDirectory), relativeName);
      const staged = `${destination}.restore-${process.pid}-${randomBytes(5).toString('hex')}`;
      await mkdir(dirname(staged), { recursive: true, mode: 0o700 });
      await decryptBackupFile(join(root, file.file), staged, encryptionKey);
      stagedJwks.push({ staged, destination });
    }
    await command('pg_restore', ['--clean', '--if-exists', '--no-owner', '--no-acl', '--exit-on-error', '--dbname', databaseUrl, dump]);
    for (const { staged: source, destination } of stagedJwks) {
      await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
      await rename(source, destination);
    }
    return manifest;
  } finally {
    await Promise.all(stagedJwks.map(({ staged }) => rm(staged, { force: true })));
    await rm(staging, { recursive: true, force: true });
  }
}
