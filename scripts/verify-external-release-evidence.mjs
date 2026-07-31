#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const IMAGE_REFERENCE = /^([a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+)@sha256:([a-f0-9]{64})$/u;
const REQUIRED_DRILLS = new Set([
  'database-restore',
  'dependency-outage',
  'regional-failover',
  'rolling-upgrade',
]);

function failure(path, message) {
  throw new Error(`${path} ${message}`);
}

function record(value, path, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    failure(path, 'must be an object');
  }
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) failure(`${path}.${key}`, 'is required');
  }
  for (const key of Object.keys(value)) {
    if (!keys.includes(key)) failure(`${path}.${key}`, 'is not supported by this schema');
  }
  return value;
}

function text(value, path, { exact, pattern, max = 512 } = {}) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || value.trim() !== value) {
    failure(path, `must be a non-empty trimmed string of at most ${max} characters`);
  }
  if (exact !== undefined && value !== exact) failure(path, `must equal ${JSON.stringify(exact)}`);
  if (pattern && !pattern.test(value)) failure(path, 'has an invalid format');
  return value;
}

function integer(value, path, { min = 0 } = {}) {
  if (!Number.isSafeInteger(value) || value < min) failure(path, `must be an integer greater than or equal to ${min}`);
  return value;
}

function truth(value, path) {
  if (value !== true) failure(path, 'must be true');
  return value;
}

function timestamp(value, path) {
  text(value, path, { max: 32 });
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value) {
    failure(path, 'must be an ISO-8601 UTC instant in canonical form');
  }
  if (parsed.valueOf() > Date.now() + 300_000) failure(path, 'must not be in the future');
  return value;
}

function httpsUrl(value, path, { openId = false, originOnly = false } = {}) {
  text(value, path, { max: 2048 });
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    failure(path, 'must be an absolute URL');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    failure(path, 'must be an HTTPS URL without credentials');
  }
  if (openId && parsed.hostname !== 'openid.net' && !parsed.hostname.endsWith('.openid.net')) {
    failure(path, 'must identify an OpenID Foundation URL');
  }
  if (originOnly && (parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.origin !== value)) {
    failure(path, 'must be an HTTPS origin without a path, query, or fragment');
  }
  return value;
}

function sha256(value, path) {
  return text(value, path, { pattern: SHA256, max: 64 });
}

function publicKey(value, path) {
  if (typeof value !== 'string' || value.length > 8192
    || !value.startsWith('-----BEGIN PUBLIC KEY-----\n')
    || !value.endsWith('-----END PUBLIC KEY-----\n')) {
    failure(path, 'must be a PEM SPKI public key');
  }
  let key;
  try {
    key = createPublicKey(value);
  } catch {
    failure(path, 'must be a valid PEM SPKI public key');
  }
  if (!['rsa', 'rsa-pss', 'ec'].includes(key.asymmetricKeyType)) {
    failure(path, 'must use RSA, RSA-PSS, or EC key material');
  }
  if (['rsa', 'rsa-pss'].includes(key.asymmetricKeyType)
    && (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    failure(path, 'must use an RSA modulus of at least 2048 bits');
  }
  if (key.asymmetricKeyType === 'ec'
    && !['prime256v1', 'secp384r1', 'secp521r1'].includes(key.asymmetricKeyDetails?.namedCurve)) {
    failure(path, 'must use P-256, P-384, or P-521');
  }
  return key;
}

function canonicalBase64(value, path) {
  text(value, path, { max: 16384 });
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.toString('base64') !== value) {
    failure(path, 'must be canonical base64');
  }
  return decoded;
}

function validateAttestation(attestation, path, gate, reportDigest) {
  record(attestation, path, [
    'signer', 'signed_at', 'algorithm', 'public_key_pem',
    'public_key_sha256', 'signature_base64',
  ]);
  text(attestation.signer, `${path}.signer`);
  timestamp(attestation.signed_at, `${path}.signed_at`);
  text(attestation.algorithm, `${path}.algorithm`, { exact: 'sha256' });
  const key = publicKey(attestation.public_key_pem, `${path}.public_key_pem`);
  const expectedFingerprint = sha256(attestation.public_key_sha256, `${path}.public_key_sha256`);
  const actualFingerprint = createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('hex');
  if (actualFingerprint !== expectedFingerprint) {
    failure(`${path}.public_key_sha256`, 'does not match the attestation public key');
  }
  const signature = canonicalBase64(attestation.signature_base64, `${path}.signature_base64`);
  const payload = Buffer.from(`authme-${gate}-report-sha256:${reportDigest}\n`);
  let accepted = false;
  try {
    accepted = verify('sha256', payload, key, signature);
  } catch {
    accepted = false;
  }
  if (!accepted) failure(`${path}.signature_base64`, `does not authenticate the ${gate} report digest`);
}

function validateRelease(release, expectations) {
  record(release, 'release', ['version', 'source_commit', 'candidate_image', 'public_origin', 'created_at']);
  text(release.version, 'release.version', { pattern: VERSION, max: 64 });
  text(release.source_commit, 'release.source_commit', { pattern: COMMIT, max: 40 });
  const imageMatch = text(release.candidate_image, 'release.candidate_image', {
    pattern: IMAGE_REFERENCE,
    max: 512,
  }).match(IMAGE_REFERENCE);
  httpsUrl(release.public_origin, 'release.public_origin', { originOnly: true });
  timestamp(release.created_at, 'release.created_at');

  if (expectations.expectedVersion && release.version !== expectations.expectedVersion) {
    failure('release.version', `does not match ${expectations.expectedVersion}`);
  }
  if (expectations.expectedSourceCommit && release.source_commit !== expectations.expectedSourceCommit) {
    failure('release.source_commit', `does not match ${expectations.expectedSourceCommit}`);
  }
  if (expectations.expectedImageRepository && imageMatch[1] !== expectations.expectedImageRepository) {
    failure('release.candidate_image', `does not use ${expectations.expectedImageRepository}`);
  }
  if (expectations.expectedImageReference && release.candidate_image !== expectations.expectedImageReference) {
    failure('release.candidate_image', `does not match published image ${expectations.expectedImageReference}`);
  }
}

function validateX1(gate, releaseVersion) {
  record(gate, 'x1', [
    'status', 'authority', 'deployment_name_version', 'certification_url',
    'certified_at', 'profiles',
  ]);
  text(gate.status, 'x1.status', { exact: 'passed' });
  text(gate.authority, 'x1.authority', { exact: 'OpenID Foundation' });
  const deployment = text(gate.deployment_name_version, 'x1.deployment_name_version');
  const versionToken = new RegExp(`(?:^|[^0-9])${releaseVersion.replaceAll('.', '\\.')}($|[^0-9])`, 'u');
  if (!versionToken.test(deployment)) {
    failure('x1.deployment_name_version', `must identify release version ${releaseVersion}`);
  }
  httpsUrl(gate.certification_url, 'x1.certification_url', { openId: true });
  timestamp(gate.certified_at, 'x1.certified_at');
  if (!Array.isArray(gate.profiles) || gate.profiles.length === 0 || gate.profiles.length > 32) {
    failure('x1.profiles', 'must contain between 1 and 32 certified profiles');
  }
  const names = new Set();
  gate.profiles.forEach((profile, index) => {
    const path = `x1.profiles[${index}]`;
    record(profile, path, ['name', 'test_plan_url', 'results_url', 'results_sha256']);
    const name = text(profile.name, `${path}.name`);
    if (names.has(name)) failure(`${path}.name`, 'must be unique');
    names.add(name);
    httpsUrl(profile.test_plan_url, `${path}.test_plan_url`, { openId: true });
    httpsUrl(profile.results_url, `${path}.results_url`, { openId: true });
    sha256(profile.results_sha256, `${path}.results_sha256`);
  });
}

function validateX2(gate) {
  record(gate, 'x2', [
    'status', 'assessor', 'independent', 'completed_at', 'methodology',
    'report_url', 'report_sha256', 'attestation', 'critical_open', 'high_open',
  ]);
  text(gate.status, 'x2.status', { exact: 'passed' });
  text(gate.assessor, 'x2.assessor');
  truth(gate.independent, 'x2.independent');
  timestamp(gate.completed_at, 'x2.completed_at');
  text(gate.methodology, 'x2.methodology', { max: 1024 });
  httpsUrl(gate.report_url, 'x2.report_url');
  const reportDigest = sha256(gate.report_sha256, 'x2.report_sha256');
  validateAttestation(gate.attestation, 'x2.attestation', 'x2', reportDigest);
  if (integer(gate.critical_open, 'x2.critical_open') !== 0) failure('x2.critical_open', 'must be zero');
  if (integer(gate.high_open, 'x2.high_open') !== 0) failure('x2.high_open', 'must be zero');
}

function validateX3(gate) {
  record(gate, 'x3', [
    'status', 'operator', 'environment', 'completed_at', 'report_url',
    'report_sha256', 'attestation', 'kms_hsm', 'recovery', 'drills',
  ]);
  text(gate.status, 'x3.status', { exact: 'passed' });
  text(gate.operator, 'x3.operator');
  text(gate.environment, 'x3.environment');
  timestamp(gate.completed_at, 'x3.completed_at');
  httpsUrl(gate.report_url, 'x3.report_url');
  const reportDigest = sha256(gate.report_sha256, 'x3.report_sha256');
  validateAttestation(gate.attestation, 'x3.attestation', 'x3', reportDigest);

  record(gate.kms_hsm, 'x3.kms_hsm', [
    'provider', 'key_reference_fingerprint', 'rotation_under_traffic',
    'dependency_outage_recovery',
  ]);
  text(gate.kms_hsm.provider, 'x3.kms_hsm.provider');
  text(gate.kms_hsm.key_reference_fingerprint, 'x3.kms_hsm.key_reference_fingerprint');
  truth(gate.kms_hsm.rotation_under_traffic, 'x3.kms_hsm.rotation_under_traffic');
  truth(gate.kms_hsm.dependency_outage_recovery, 'x3.kms_hsm.dependency_outage_recovery');

  record(gate.recovery, 'x3.recovery', [
    'rto_target_seconds', 'rto_observed_seconds', 'rpo_target_seconds',
    'rpo_observed_seconds',
  ]);
  const rtoTarget = integer(gate.recovery.rto_target_seconds, 'x3.recovery.rto_target_seconds', { min: 1 });
  const rtoObserved = integer(gate.recovery.rto_observed_seconds, 'x3.recovery.rto_observed_seconds');
  const rpoTarget = integer(gate.recovery.rpo_target_seconds, 'x3.recovery.rpo_target_seconds');
  const rpoObserved = integer(gate.recovery.rpo_observed_seconds, 'x3.recovery.rpo_observed_seconds');
  if (rtoObserved > rtoTarget) failure('x3.recovery.rto_observed_seconds', 'must not exceed its target');
  if (rpoObserved > rpoTarget) failure('x3.recovery.rpo_observed_seconds', 'must not exceed its target');

  if (!Array.isArray(gate.drills) || gate.drills.length !== REQUIRED_DRILLS.size) {
    failure('x3.drills', `must contain exactly ${REQUIRED_DRILLS.size} required drills`);
  }
  const names = new Set();
  gate.drills.forEach((drill, index) => {
    const path = `x3.drills[${index}]`;
    record(drill, path, [
      'name', 'status', 'completed_at', 'observed_protocol_errors',
      'evidence_url', 'evidence_sha256',
    ]);
    const name = text(drill.name, `${path}.name`);
    if (!REQUIRED_DRILLS.has(name)) failure(`${path}.name`, 'is not a required drill');
    if (names.has(name)) failure(`${path}.name`, 'must be unique');
    names.add(name);
    text(drill.status, `${path}.status`, { exact: 'passed' });
    timestamp(drill.completed_at, `${path}.completed_at`);
    if (integer(drill.observed_protocol_errors, `${path}.observed_protocol_errors`) !== 0) {
      failure(`${path}.observed_protocol_errors`, 'must be zero');
    }
    httpsUrl(drill.evidence_url, `${path}.evidence_url`);
    sha256(drill.evidence_sha256, `${path}.evidence_sha256`);
  });
  for (const name of REQUIRED_DRILLS) {
    if (!names.has(name)) failure('x3.drills', `is missing ${name}`);
  }
}

export function validateExternalReleaseEvidence(document, expectations = {}) {
  record(document, 'manifest', ['schema_version', 'release', 'x1', 'x2', 'x3', 'release_approval']);
  if (document.schema_version !== 1) failure('manifest.schema_version', 'must equal 1');
  validateRelease(document.release, expectations);
  validateX1(document.x1, document.release.version);
  validateX2(document.x2);
  validateX3(document.x3);
  record(document.release_approval, 'release_approval', ['owner', 'approved_at', 'statement']);
  text(document.release_approval.owner, 'release_approval.owner');
  timestamp(document.release_approval.approved_at, 'release_approval.approved_at');
  text(document.release_approval.statement, 'release_approval.statement', { exact: 'approved-for-production' });
  const releaseCreated = new Date(document.release.created_at).valueOf();
  const prerequisites = [
    ['x1.certified_at', document.x1.certified_at],
    ['x2.completed_at', document.x2.completed_at],
    ['x2.attestation.signed_at', document.x2.attestation.signed_at],
    ['x3.completed_at', document.x3.completed_at],
    ['x3.attestation.signed_at', document.x3.attestation.signed_at],
    ...document.x3.drills.map((drill, index) => [`x3.drills[${index}].completed_at`, drill.completed_at]),
  ];
  for (const [path, value] of prerequisites) {
    if (new Date(value).valueOf() > releaseCreated) failure(path, 'must not be later than release.created_at');
  }
  if (new Date(document.release_approval.approved_at).valueOf() < releaseCreated) {
    failure('release_approval.approved_at', 'must not be earlier than release.created_at');
  }
  return {
    valid: true,
    version: document.release.version,
    source_commit: document.release.source_commit,
    candidate_image: document.release.candidate_image,
    certified_profiles: document.x1.profiles.map(({ name }) => name),
    assessor: document.x2.assessor,
    drills: document.x3.drills.map(({ name }) => name).sort(),
  };
}

function options(argv) {
  const supported = new Set([
    '--manifest', '--version', '--source-commit', '--image-repository', '--image-reference',
  ]);
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!supported.has(name) || value === undefined || value.startsWith('--')) {
      throw new Error(`invalid or incomplete option: ${name ?? '<missing>'}`);
    }
    if (Object.hasOwn(result, name)) throw new Error(`duplicate option: ${name}`);
    result[name] = value;
  }
  if (!result['--manifest']) throw new Error('--manifest is required');
  return result;
}

async function main() {
  const parsed = options(process.argv.slice(2));
  const document = JSON.parse(await readFile(resolve(parsed['--manifest']), 'utf8'));
  const summary = validateExternalReleaseEvidence(document, {
    expectedVersion: parsed['--version'],
    expectedSourceCommit: parsed['--source-commit'],
    expectedImageRepository: parsed['--image-repository'],
    expectedImageReference: parsed['--image-reference'],
  });
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
