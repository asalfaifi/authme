import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { test } from 'node:test';

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => code === 0
      ? resolve(stdout)
      : reject(new Error(`${command} exited with ${code}: ${stderr}`)));
  });
}

test('release artifacts normalize, checksum, and sign the runtime-image SBOM', { timeout: 120_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'authme-release-artifacts-'));
  try {
    const imageSbomInput = join(directory, 'image.raw.cdx.json');
    await writeFile(imageSbomInput, JSON.stringify({
      $schema: 'http://cyclonedx.org/schema/bom-1.7.schema.json',
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111',
      version: 1,
      metadata: {
        timestamp: '2026-07-31T00:00:00Z',
        component: { type: 'container', name: 'authme:test', 'bom-ref': 'authme-image' },
      },
      components: [{ type: 'library', name: 'runtime-component', version: '1.0.0', 'bom-ref': 'runtime-component@1.0.0' }],
    }));
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const signingKey = join(directory, 'release-key.pem');
    await writeFile(signingKey, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    const output = join(directory, 'dist');
    await run(process.execPath, ['scripts/release-artifacts.mjs', '--output', output, '--require-image'], {
      cwd: new URL('..', import.meta.url),
      env: {
        ...process.env,
        AUTHME_RELEASE_IMAGE_SBOM: imageSbomInput,
        AUTHME_RELEASE_IMAGE_REFERENCE: `ghcr.io/asalfaifi/authme@sha256:${'a'.repeat(64)}`,
        AUTHME_RELEASE_SIGNING_KEY: signingKey,
      },
    });

    const imageSbom = JSON.parse(await readFile(join(output, 'authme-image-sbom.cdx.json'), 'utf8'));
    assert.equal(imageSbom.serialNumber, undefined);
    assert.equal(imageSbom.metadata.timestamp, undefined);
    assert.equal(imageSbom.metadata.component.type, 'container');
    assert.equal(imageSbom.components[0].name, 'runtime-component');

    const checksums = await readFile(join(output, 'SHA256SUMS'), 'utf8');
    for (const artifact of [
      'authme-1.0.0-rc.1.tgz',
      'authme-sbom.cdx.json',
      'authme-image-sbom.cdx.json',
      'authme-release-public-key.pem',
      'authme-image-reference.txt',
    ]) {
      assert.match(checksums, new RegExp(`^[a-f0-9]{64}  ${artifact.replaceAll('.', '\\.')}$`, 'mu'));
    }
    assert.equal(
      await readFile(join(output, 'authme-image-reference.txt'), 'utf8'),
      `ghcr.io/asalfaifi/authme@sha256:${'a'.repeat(64)}\n`,
    );
    assert.equal(
      await readFile(join(output, 'authme-release-public-key.pem'), 'utf8'),
      publicKey.export({ type: 'spki', format: 'pem' }),
    );
    for (const artifact of ['authme-1.0.0-rc.1.tgz', 'authme-sbom.cdx.json', 'authme-image-sbom.cdx.json', 'authme-image-reference.txt', 'authme-release-public-key.pem', 'SHA256SUMS']) {
      const data = await readFile(join(output, artifact));
      const signature = await readFile(join(output, `${artifact}.sig`));
      assert.equal(verify('sha256', data, publicKey, signature), true, `${artifact} signature did not verify`);
    }
    assert.deepEqual((await readdir(output)).sort(), [
      'SHA256SUMS', 'SHA256SUMS.sig',
      'authme-1.0.0-rc.1.tgz', 'authme-1.0.0-rc.1.tgz.sig',
      'authme-image-reference.txt', 'authme-image-reference.txt.sig',
      'authme-image-sbom.cdx.json', 'authme-image-sbom.cdx.json.sig',
      'authme-release-public-key.pem', 'authme-release-public-key.pem.sig',
      'authme-sbom.cdx.json', 'authme-sbom.cdx.json.sig',
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
