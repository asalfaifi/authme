import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';

export const SOURCE_COMMIT = 'c'.repeat(40);
export const IMAGE_REFERENCE = `ghcr.io/asalfaifi/authme@sha256:${'a'.repeat(64)}`;
const DEFAULT_ATTESTATION_KEYS = generateKeyPairSync('rsa', { modulusLength: 2048 });

export function createExternalAttestation(gate, reportDigest, signer, keyPair = DEFAULT_ATTESTATION_KEYS) {
  const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });
  const publicKeySha256 = createHash('sha256')
    .update(createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' }))
    .digest('hex');
  const payload = Buffer.from(`authme-${gate}-report-sha256:${reportDigest}\n`);
  return {
    signer,
    signed_at: '2026-07-29T13:00:00.000Z',
    algorithm: 'sha256',
    public_key_pem: publicKeyPem,
    public_key_sha256: publicKeySha256,
    signature_base64: sign('sha256', payload, keyPair.privateKey).toString('base64'),
  };
}

export function validExternalReleaseEvidence() {
  return {
    schema_version: 1,
    release: {
      version: '1.0.0',
      source_commit: SOURCE_COMMIT,
      candidate_image: IMAGE_REFERENCE,
      public_origin: 'https://auth.example.com',
      created_at: '2026-07-30T00:00:00.000Z',
    },
    x1: {
      status: 'passed',
      authority: 'OpenID Foundation',
      deployment_name_version: 'AuthMe 1.0.0',
      certification_url: 'https://openid.net/certification/authme-1-0-0',
      certified_at: '2026-07-28T00:00:00.000Z',
      profiles: [{
        name: 'Basic OP',
        test_plan_url: 'https://www.certification.openid.net/plan/plan-id',
        results_url: 'https://www.certification.openid.net/log-detail.html?public=true',
        results_sha256: '1'.repeat(64),
      }],
    },
    x2: {
      status: 'passed',
      assessor: 'Independent Security Review Ltd',
      independent: true,
      completed_at: '2026-07-29T00:00:00.000Z',
      methodology: 'Architecture review and authenticated black-box penetration test',
      report_url: 'https://evidence.example.com/authme/security-review.pdf',
      report_sha256: '2'.repeat(64),
      attestation: createExternalAttestation('x2', '2'.repeat(64), 'Independent Security Review Ltd'),
      critical_open: 0,
      high_open: 0,
    },
    x3: {
      status: 'passed',
      operator: 'AuthMe Production Operations',
      environment: 'production-equivalent-primary-and-dr',
      completed_at: '2026-07-29T12:00:00.000Z',
      report_url: 'https://evidence.example.com/authme/operations-report.json',
      report_sha256: '3'.repeat(64),
      attestation: createExternalAttestation('x3', '3'.repeat(64), 'Operations Assurance Officer'),
      kms_hsm: {
        provider: 'production-hsm-cluster',
        key_reference_fingerprint: 'sha256:non-secret-material-reference-fingerprint',
        rotation_under_traffic: true,
        dependency_outage_recovery: true,
      },
      recovery: {
        rto_target_seconds: 1800,
        rto_observed_seconds: 900,
        rpo_target_seconds: 300,
        rpo_observed_seconds: 60,
      },
      drills: [
        'database-restore',
        'dependency-outage',
        'regional-failover',
        'rolling-upgrade',
      ].map((name, index) => ({
        name,
        status: 'passed',
        completed_at: `2026-07-2${index + 5}T00:00:00.000Z`,
        observed_protocol_errors: 0,
        evidence_url: `https://evidence.example.com/authme/${name}.json`,
        evidence_sha256: String(index + 5).repeat(64),
      })),
    },
    release_approval: {
      owner: 'AuthMe Release Owner',
      approved_at: '2026-07-30T01:00:00.000Z',
      statement: 'approved-for-production',
    },
  };
}
