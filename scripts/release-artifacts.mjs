#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, open, readdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { spawn } from 'node:child_process';

async function capture(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { shell: false, stdio: ['ignore', 'pipe', 'inherit'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? resolvePromise(output) : reject(new Error(`${command} exited with ${code}`)));
  });
}

async function sha256(path) {
  const hash = createHash('sha256');
  await pipeline(createReadStream(path), hash);
  return hash.digest('hex');
}

const outputIndex = process.argv.indexOf('--output');
if (outputIndex !== -1 && !process.argv[outputIndex + 1]) {
  throw new Error('--output requires a directory');
}
const output = resolve(outputIndex === -1 ? 'dist' : process.argv[outputIndex + 1]);
await rm(output, { recursive: true, force: true });
await mkdir(output, { mode: 0o755 });
const packed = JSON.parse(await capture('npm', ['pack', '--json', '--pack-destination', output]));
if (packed.length !== 1) throw new Error('npm pack did not produce exactly one release archive');
const archive = join(output, packed[0].filename);
const sbom = join(output, 'authme-sbom.cdx.json');
const sbomDocument = JSON.parse(await capture('npm', ['sbom', '--sbom-format', 'cyclonedx']));
// npm supplies a fresh UUID and wall-clock timestamp on every invocation. Both
// are optional CycloneDX metadata, so omit them to keep identical source and
// lockfile inputs byte-for-byte reproducible.
delete sbomDocument.serialNumber;
delete sbomDocument.metadata?.timestamp;
await writeFile(sbom, `${JSON.stringify(sbomDocument, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
const artifacts = [archive, sbom];
const checksums = `${(await Promise.all(artifacts.map(async (path) => `${await sha256(path)}  ${path.split('/').at(-1)}`))).join('\n')}\n`;
const checksumPath = join(output, 'SHA256SUMS');
await writeFile(checksumPath, checksums, { flag: 'wx', mode: 0o644 });
artifacts.push(checksumPath);

const signingKey = process.env.AUTHME_RELEASE_SIGNING_KEY;
if (!signingKey && !process.argv.includes('--unsigned')) throw new Error('AUTHME_RELEASE_SIGNING_KEY is required (use --unsigned only for non-release rehearsal)');
if (signingKey) {
  await Promise.all(artifacts.map(async (path) => {
    const signature = await open(`${path}.sig`, 'wx', 0o644);
    await new Promise((resolvePromise, reject) => {
      const child = spawn('openssl', ['dgst', '-sha256', '-sign', signingKey, path], { shell: false, stdio: ['ignore', signature.fd, 'inherit'] });
      child.once('error', reject);
      child.once('exit', (code) => code === 0 ? resolvePromise() : reject(new Error(`openssl signing failed with ${code}`)));
    });
    await signature.close();
  }));
}
process.stdout.write(`${JSON.stringify({ output, artifacts: await readdir(output), signed: Boolean(signingKey) }, null, 2)}\n`);
