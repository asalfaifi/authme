#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, open, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { spawn } from 'node:child_process';
import { validateExternalReleaseEvidence } from './verify-external-release-evidence.mjs';

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

function normalizedCycloneDx(document, label, { requireContainer = false } = {}) {
  if (!document || document.bomFormat !== 'CycloneDX'
    || typeof document.specVersion !== 'string'
    || document.version !== 1
    || !Array.isArray(document.components)) {
    throw new Error(`${label} is not a supported CycloneDX document`);
  }
  if (requireContainer && document.metadata?.component?.type !== 'container') {
    throw new Error(`${label} does not describe a container image`);
  }
  // SBOM generators supply a fresh UUID and wall-clock timestamp. Both are
  // optional CycloneDX metadata; omitting them preserves deterministic output
  // without changing the component or dependency inventory.
  delete document.serialNumber;
  delete document.metadata?.timestamp;
  return document;
}

const outputIndex = process.argv.indexOf('--output');
if (outputIndex !== -1 && !process.argv[outputIndex + 1]) {
  throw new Error('--output requires a directory');
}
const output = resolve(outputIndex === -1 ? 'dist' : process.argv[outputIndex + 1]);
const signingKey = process.env.AUTHME_RELEASE_SIGNING_KEY;
if (!signingKey && !process.argv.includes('--unsigned')) throw new Error('AUTHME_RELEASE_SIGNING_KEY is required (use --unsigned only for non-release rehearsal)');
const packageDocument = JSON.parse(await readFile('package.json', 'utf8'));
await rm(output, { recursive: true, force: true });
await mkdir(output, { mode: 0o755 });
const packed = JSON.parse(await capture('npm', ['pack', '--json', '--pack-destination', output]));
if (packed.length !== 1) throw new Error('npm pack did not produce exactly one release archive');
const archive = join(output, packed[0].filename);
const sbom = join(output, 'authme-sbom.cdx.json');
const sbomDocument = normalizedCycloneDx(
  JSON.parse(await capture('npm', ['sbom', '--sbom-format', 'cyclonedx'])),
  'npm SBOM',
);
await writeFile(sbom, `${JSON.stringify(sbomDocument, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
const artifacts = [archive, sbom];
const imageSbomInput = process.env.AUTHME_RELEASE_IMAGE_SBOM;
const imageReferenceInput = process.env.AUTHME_RELEASE_IMAGE_REFERENCE;
if (process.argv.includes('--require-image') && (!imageSbomInput || !imageReferenceInput)) {
  throw new Error('--require-image needs AUTHME_RELEASE_IMAGE_SBOM and AUTHME_RELEASE_IMAGE_REFERENCE');
}
if (Boolean(imageSbomInput) !== Boolean(imageReferenceInput)) {
  throw new Error('container image SBOM and digest reference must be released together');
}
if (imageSbomInput) {
  const imageSbom = join(output, 'authme-image-sbom.cdx.json');
  const imageSbomDocument = normalizedCycloneDx(
    JSON.parse(await readFile(resolve(imageSbomInput), 'utf8')),
    'container image SBOM',
    { requireContainer: true },
  );
  await writeFile(imageSbom, `${JSON.stringify(imageSbomDocument, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
  artifacts.push(imageSbom);
}
if (imageReferenceInput) {
  const imageReference = imageReferenceInput.trim();
  if (!/^[a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/u.test(imageReference)) {
    throw new Error('AUTHME_RELEASE_IMAGE_REFERENCE must be a fully-qualified lowercase OCI image digest');
  }
  const imageReferencePath = join(output, 'authme-image-reference.txt');
  await writeFile(imageReferencePath, `${imageReference}\n`, { flag: 'wx', mode: 0o644 });
  artifacts.push(imageReferencePath);
}
const externalEvidenceInput = process.env.AUTHME_EXTERNAL_RELEASE_EVIDENCE;
if (externalEvidenceInput) {
  const evidenceDocument = JSON.parse(await readFile(resolve(externalEvidenceInput), 'utf8'));
  validateExternalReleaseEvidence(evidenceDocument, { expectedVersion: packageDocument.version });
  const evidencePath = join(output, 'authme-external-release-evidence.json');
  await writeFile(evidencePath, `${JSON.stringify(evidenceDocument, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
  artifacts.push(evidencePath);
}
if (signingKey) {
  const publicKeyPath = join(output, 'authme-release-public-key.pem');
  const publicKey = await capture('openssl', ['pkey', '-in', signingKey, '-pubout']);
  if (!publicKey.startsWith('-----BEGIN PUBLIC KEY-----\n')) {
    throw new Error('release signing key did not produce a PEM public key');
  }
  await writeFile(publicKeyPath, publicKey, { flag: 'wx', mode: 0o644 });
  artifacts.push(publicKeyPath);
}
const checksums = `${(await Promise.all(artifacts.map(async (path) => `${await sha256(path)}  ${path.split('/').at(-1)}`))).join('\n')}\n`;
const checksumPath = join(output, 'SHA256SUMS');
await writeFile(checksumPath, checksums, { flag: 'wx', mode: 0o644 });
artifacts.push(checksumPath);

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
