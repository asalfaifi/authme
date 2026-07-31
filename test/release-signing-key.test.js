import assert from 'node:assert/strict';
import { createPublicKey, sign, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { test } from 'node:test';

function run(args) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, args, {
      cwd: new URL('..', import.meta.url),
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('exit', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

test('release key generation is strong, private, useful, and overwrite-safe', { timeout: 30_000 }, async () => {
  const parent = await mkdtemp(join(tmpdir(), 'authme-release-key-'));
  const directory = join(parent, 'owner-custody');
  try {
    const generated = await run([
      'scripts/generate-release-signing-key.mjs',
      '--output-directory', directory,
    ]);
    assert.equal(generated.code, 0, generated.stderr);
    const summary = JSON.parse(generated.stdout);
    assert.equal(summary.algorithm, 'RSA');
    assert.equal(summary.key_size_bits, 4096);
    assert.match(summary.fingerprint, /^SHA256:[a-f0-9]{64}$/u);
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
    assert.equal((await stat(summary.private_key)).mode & 0o777, 0o600);
    assert.equal((await stat(summary.public_key)).mode & 0o777, 0o644);
    assert.equal(await readFile(summary.fingerprint_file, 'utf8'), `${summary.fingerprint}\n`);

    const privateKey = await readFile(summary.private_key);
    const publicKey = await readFile(summary.public_key);
    const payload = Buffer.from('authme release signing boundary');
    const signature = sign('sha256', payload, privateKey);
    assert.equal(verify('sha256', payload, createPublicKey(publicKey), signature), true);

    const repeated = await run([
      'scripts/generate-release-signing-key.mjs',
      '--output-directory', directory,
    ]);
    assert.notEqual(repeated.code, 0);
    assert.match(repeated.stderr, /EEXIST/u);
    assert.deepEqual(await readFile(summary.private_key), privateKey);

    const inRepository = await run([
      'scripts/generate-release-signing-key.mjs',
      '--output-directory', 'release-key-must-not-exist',
    ]);
    assert.notEqual(inRepository.code, 0);
    assert.match(inRepository.stderr, /outside the repository/u);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
