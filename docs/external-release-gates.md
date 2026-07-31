# External release gates and final promotion

AuthMe release candidates are buildable without claiming independent approval.
A stable version such as `v1.0.0` is different: the tag workflow refuses it
unless one evidence manifest proves X1, X2, and X3 for the exact source commit
and immutable candidate image. After rebuilding, the workflow also requires the
published stable image digest to equal that candidate digest. The validated
manifest is included in the signed release archive and GitHub attestation set.

The manifest is an index, not a substitute for the underlying records. Report
URLs may use access-controlled evidence storage, but they must be durable HTTPS
locations and their SHA-256 values must identify immutable files. Do not place
credentials, findings, personal contact details, or other confidential report
content in the manifest because the final release publishes it.

## Establish release-key custody

Create a protected GitHub Actions environment named `release` before loading any
release material. Require an independent reviewer, prevent self-review and
administrator bypass, and restrict deployments to the intended
`certification/*` and signed `v*` tag patterns. The workflow declares this
environment for candidate and release jobs; an unreviewed branch dispatch must
never receive its secrets. The workflow serializes all candidate and release
jobs so two publications cannot race.

Generate the release key on a secured release-owner workstation, outside the
repository and its backup/synchronization paths:

```sh
npm run release:key:generate -- \
  --output-directory /secure/offline/authme-release-key-1
```

The command creates a mode `0700` directory, a mode `0600` RSA-4096 private key,
the public key, and its SHA-256 SPKI fingerprint. It refuses an existing output
directory and never prints private material. Keep this key separate from realm
OIDC/SAML keys. Record and authenticate the public fingerprint through an
independent owner channel.

Load the base64-encoded PEM into GitHub without putting it in a command argument
or shell variable:

```sh
openssl base64 -A \
  -in /secure/offline/authme-release-key-1/authme-release-key.pem | \
  gh secret set AUTHME_RELEASE_SIGNING_KEY_B64 --env release
```

Restrict repository administration and Actions-secret access to release owners.
Retain the offline private key according to the organization's custody, backup,
rotation, and revocation policy. Historical releases contain their public key;
an independent fingerprint channel remains the trust root.

## Freeze and publish a certification candidate

1. Set the intended stable package version (for example `1.0.0`), complete all
   code and documentation, and commit it. No source change is allowed after the
   candidate is tested; any correction starts a new candidate.
2. Create and push a non-`v*` candidate ref pointing to that commit so it cannot
   be mistaken for a release, then manually dispatch
   `.github/workflows/release.yml` at that ref:

   ```sh
   git tag certification/1.0.0-candidate.1 EXACT_COMMIT
   git push origin certification/1.0.0-candidate.1
   gh workflow run release.yml --ref certification/1.0.0-candidate.1
   ```

3. The workflow runs every release gate and publishes an immutable image named
   `candidate-<40-character-commit>`, with image provenance and SBOM
   attestations. Record the resulting digest reference. Deploy that digest—not
   the tag—to the public certification and production-equivalent test origins.

The workflow refuses to overwrite an existing candidate tag. A rerun therefore
requires a new commit and candidate ref, preserving the tested object.

## X1 — OpenID certification

Run every profile AuthMe will claim against the candidate deployment. The
[OpenID Foundation conformance suite](https://openid.net/certification/about-conformance-suite/)
is free for testing, but certification uses the Foundation's production service
and submission process. Publish each passing plan for certification, retain the
exported results ZIP and SHA-256 digest, submit the signed Declaration of
Conformance, and wait for the public certification record. The Foundation's
[submission instructions](https://openid.net/certification/op_submission/)
require a deployment name and version identifying a specific point in time and
the published test results for each profile.

Record only profiles present in the final public certification. Upstream
`oidc-provider` certification is not an AuthMe result.

## X2 — independent security review

Commission an assessor independent of AuthMe implementation and release
approval. Scope the exact candidate image, source commit, public deployment,
realm isolation, protocol and browser surfaces, administration/account flows,
PostgreSQL/Redis behavior, federation/provisioning, deployment manifests,
cryptographic boundaries, and architecture/threat model.

Retain the final report and its SHA-256 digest. The assessor must sign the exact
UTF-8 line `authme-x2-report-sha256:<64-lowercase-hex-digest>\n`; include the
SPKI public key, its SHA-256 DER fingerprint, and canonical base64 signature in
the manifest. All critical and high findings must be resolved and retested; the
manifest cannot pass with either count nonzero. Lower-severity risk acceptance
remains an explicit release-owner decision and belongs in the assessor record,
not as an omitted finding.

## X3 — target infrastructure and hardware drills

Use the intended KMS/HSM adapter, platform identity, database topology, backup
system, ingress, DNS, and regional recovery environment. The accountable
operator must sign the exact UTF-8 line
`authme-x3-report-sha256:<64-lowercase-hex-digest>\n`; include the SPKI public
key, its SHA-256 DER fingerprint, and canonical base64 signature in the
manifest. The following evidence is mandatory:

- live signing-key rotation and KMS/HSM outage recovery under traffic;
- authenticated database/JWKS restore with measured RTO and RPO;
- PostgreSQL/Redis or other dependency outage behavior;
- rolling upgrade with continuous issuer/protocol probes; and
- regional failover for the documented single-writer topology.

Each drill must record zero observed public protocol errors. Observed RTO and
RPO must not exceed the approved targets. The exercise and maintenance approach
should follow the operator's contingency program; [NIST SP 800-34 Rev. 1](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final)
is a useful baseline for planning, exercising, and maintaining recovery plans.

## Validate and authorize final promotion

Copy `docs/external-release-gates.example.json` outside the repository, replace
every placeholder, and validate it against the exact candidate:

```sh
npm run release:verify-external-evidence -- \
  --manifest /secure/release/authme-1.0.0-evidence.json \
  --version 1.0.0 \
  --source-commit EXACT_40_CHARACTER_COMMIT \
  --image-repository ghcr.io/asalfaifi/authme \
  --image-reference ghcr.io/asalfaifi/authme@sha256:CANDIDATE_DIGEST
```

After the release owner reviews the complete records and sets
`approved-for-production`, load the manifest into the trusted tag workflow:

```sh
openssl base64 -A \
  -in /secure/release/authme-1.0.0-evidence.json | \
  gh secret set AUTHME_EXTERNAL_RELEASE_EVIDENCE_B64 --env release
```

Create the signed stable tag on the **same commit** used by the candidate and
push it. Never create a release commit after testing:

```sh
git tag -s v1.0.0 EXACT_40_CHARACTER_COMMIT
git push origin v1.0.0
```

Every published `v*` workflow requires GitHub to verify the annotated tag
signature. The stable workflow also validates the manifest before testing,
rebuilds from the same commit and
timestamp, and then compares the resulting published digest to
`release.candidate_image`. A lightweight/invalid tag, mismatched source commit,
image repository/digest, unofficial X1 URL, unresolved critical/high issue,
forged assessor/operator signature, missing drill, missed RTO/RPO, protocol
error, or missing owner approval fails closed.

After publication, remove or rotate the transport secret for the next release;
the signed release artifact is the durable manifest copy. Preserve all
underlying evidence for the full support and regulatory retention period.
