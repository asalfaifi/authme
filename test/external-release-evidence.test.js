import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { test } from 'node:test';
import { validateExternalReleaseEvidence } from '../scripts/verify-external-release-evidence.mjs';
import {
  createExternalAttestation,
  IMAGE_REFERENCE,
  SOURCE_COMMIT,
  validExternalReleaseEvidence,
} from '../test-support/external-release-evidence.js';

const WEAK_ATTESTATION_KEY_PAIR = generateKeyPairSync('rsa', { modulusLength: 1024 });

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

test('external release evidence binds every passed gate to one stable build', () => {
  const summary = validateExternalReleaseEvidence(validExternalReleaseEvidence(), {
    expectedVersion: '1.0.0',
    expectedSourceCommit: SOURCE_COMMIT,
    expectedImageRepository: 'ghcr.io/asalfaifi/authme',
    expectedImageReference: IMAGE_REFERENCE,
  });
  assert.deepEqual(summary, {
    valid: true,
    version: '1.0.0',
    source_commit: SOURCE_COMMIT,
    candidate_image: IMAGE_REFERENCE,
    certified_profiles: ['Basic OP'],
    assessor: 'Independent Security Review Ltd',
    drills: ['database-restore', 'dependency-outage', 'regional-failover', 'rolling-upgrade'],
  });
});

test('external release evidence fails closed on incomplete or weaker claims', () => {
  const cases = [
    ['unknown fields', (value) => { value.x1.unreviewed = true; }, /x1\.unreviewed is not supported/u],
    ['prerelease versions', (value) => { value.release.version = '1.0.0-rc.1'; }, /release\.version has an invalid format/u],
    ['future evidence', (value) => { value.release.created_at = '2099-01-01T00:00:00.000Z'; }, /must not be in the future/u],
    ['unofficial certification', (value) => { value.x1.certification_url = 'https://example.com/certification'; }, /OpenID Foundation URL/u],
    ['wrong certified version', (value) => { value.x1.deployment_name_version = 'AuthMe 2.0.0'; }, /must identify release version/u],
    ['ambiguous certified version', (value) => { value.x1.deployment_name_version = 'AuthMe 11.0.0'; }, /must identify release version/u],
    ['duplicate profiles', (value) => { value.x1.profiles.push(structuredClone(value.x1.profiles[0])); }, /must be unique/u],
    ['non-independent review', (value) => { value.x2.independent = false; }, /x2\.independent must be true/u],
    ['open high findings', (value) => { value.x2.high_open = 1; }, /x2\.high_open must be zero/u],
    ['forged assessor signature', (value) => { value.x2.attestation.signature_base64 = Buffer.from('forged').toString('base64'); }, /does not authenticate/u],
    ['weak assessor key', (value) => { value.x2.attestation = createExternalAttestation('x2', '2'.repeat(64), 'Weak Assessor', WEAK_ATTESTATION_KEY_PAIR); }, /at least 2048 bits/u],
    ['substituted operator key', (value) => { value.x3.attestation.public_key_sha256 = '4'.repeat(64); }, /does not match/u],
    ['untested HSM rotation', (value) => { value.x3.kms_hsm.rotation_under_traffic = false; }, /rotation_under_traffic must be true/u],
    ['missed recovery objective', (value) => { value.x3.recovery.rto_observed_seconds = 1801; }, /must not exceed its target/u],
    ['protocol errors', (value) => { value.x3.drills[0].observed_protocol_errors = 1; }, /must be zero/u],
    ['missing drill', (value) => { value.x3.drills.pop(); }, /must contain exactly 4/u],
    ['unapproved production release', (value) => { value.release_approval.statement = 'draft'; }, /approved-for-production/u],
    ['premature manifest', (value) => { value.release.created_at = '2026-07-28T12:00:00.000Z'; }, /must not be later than release\.created_at/u],
    ['premature approval', (value) => { value.release_approval.approved_at = '2026-07-29T23:00:00.000Z'; }, /must not be earlier/u],
  ];
  for (const [label, mutate, pattern] of cases) {
    const value = validExternalReleaseEvidence();
    mutate(value);
    assert.throws(() => validateExternalReleaseEvidence(value), pattern, label);
  }
  assert.throws(
    () => validateExternalReleaseEvidence(validExternalReleaseEvidence(), { expectedSourceCommit: 'd'.repeat(40) }),
    /does not match/u,
  );
});

test('external evidence CLI validates its immutable release coordinates', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'authme-external-evidence-'));
  try {
    const manifest = join(directory, 'evidence.json');
    await writeFile(manifest, `${JSON.stringify(validExternalReleaseEvidence())}\n`);
    const accepted = await run([
      'scripts/verify-external-release-evidence.mjs',
      '--manifest', manifest,
      '--version', '1.0.0',
      '--source-commit', SOURCE_COMMIT,
      '--image-repository', 'ghcr.io/asalfaifi/authme',
      '--image-reference', IMAGE_REFERENCE,
    ]);
    assert.equal(accepted.code, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).valid, true);

    const rejected = await run([
      'scripts/verify-external-release-evidence.mjs',
      '--manifest', manifest,
      '--image-reference', `ghcr.io/asalfaifi/authme@sha256:${'b'.repeat(64)}`,
    ]);
    assert.notEqual(rejected.code, 0);
    assert.match(rejected.stderr, /does not match published image/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
