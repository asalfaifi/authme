# v1 release-candidate evidence map

This document maps every autonomous milestone to executable evidence. A green unit suite alone is not sufficient: the signed-tag workflow also runs the PostgreSQL-only suite without skips, the PostgreSQL protocol smoke test, production dependency audit, Helm validation, image/configuration/secret scans, and exact runtime-image checks. It then publishes a no-overwrite GHCR tag, signs the archive, package/image SBOMs, image digest, verification key, and checksum manifest, and creates release provenance plus registry provenance/SBOM attestations.

| Milestone | Implementation boundary | Primary executable evidence |
|---|---|---|
| K1 | Deterministic Keycloak export transformer, structured/human compatibility reports, dry-run default, and zero-blocker minimal fixtures for all three declared profiles | `test/keycloak-import.test.js`; `docs/keycloak-compatibility.md`; `docs/keycloak-migration.md` |
| K2 | Subject-bound account console for profile/recovery/password/MFA/passkeys/sessions/invitations and standalone production delivery integration | `test/account-console.test.js`; `test/account-email-delivery.test.js`; `test/postgres-account-console.test.js` |
| K3 | Mutable realm status/settings, managed and dynamically registered clients, roles, nested groups, users, complete client-scope assignment controls, and audited native admin UI/API | `test/admin-management.test.js`; `test/admin-console.test.js`; `test/admin-console-ui.test.js`; `test/admin-api.test.js`; `test/client-auth-jwt.test.js` |
| K4 | Realm-local organizations, unique domains, invitations, current membership, IdP allowlists, durable token context | `test/organization-flow.test.js`; `test/management-store.test.js`; PostgreSQL management test |
| K5 | Downstream SAML IdP metadata, signed Response/Assertion, encryption, IdP initiation, redirect SLO | `test/saml-idp.test.js` |
| K6 | LDAP/AD authentication, bounded import/sync/reconciliation, immutable external identity, outage thresholds | `test/ldap.test.js`; `test/ldap-sync.test.js`; PostgreSQL LDAP tests |
| K7 | SCIM Bulk, stable sorting, full supported core filter grammar, ETags and realm isolation | `test/scim-bulk.test.js`; `test/scim-filter-grammar.test.js`; `test/scim-sorting.test.js`; `test/scim-protocol.test.js`; `test/postgres-scim.test.js` |
| Tenant registration | Per-client opt-in account creation, denied-by-default access, complete Authorization Code flow, audit evidence, and duplicate identity isolation across two realms | `test/user-registration.test.js`; `test/ui.test.js`; `test/config.test.js` |
| K8 | Executable required/alternative/conditional flow policy; exact client/ACR/AMR/max-age selection; browser, federation, CIBA, and existing-session enforcement | `test/organization-flow.test.js`; `test/ciba.test.js`; `test/management-store.test.js`; admin negative tests |
| K9 | Realm/client composite role graphs, Keycloak-shaped token claims, nested path lifecycle, existing-reference validation, reusable scopes, mapper ownership | `test/organization-flow.test.js`; `test/admin-management.test.js`; `test/management-store.test.js`; `test/postgres-management.test.js` |
| K10 | Authenticated encrypted backup/restore, manifest/checksum verification, continuous zero-error rollout probe, representative protocol load driver | `test/backup.test.js`; `test/availability-rehearsal.test.js`; `test/load-rehearsal.test.js`; `scripts/ha-rehearsal.mjs` |
| K11 | Public-only KMS/HSM inventory, `oidc-provider` external signing, deployable adapter modules, fail-closed overlap rotation | `test/signing-key-manager.test.js`; `docs/production.md` signing contract |
| H1 | Redirect/action token log redaction | `test/logging.test.js` |
| H2 | Resource audience cannot widen through refresh, client credentials, or device polling | `test/resource-indicators.test.js` |
| H3 | CIBA slow-down remains unbounded and durable | CIBA unit and PostgreSQL concurrency tests |
| H4 | Expired CIBA records retain `expired_token` semantics through cleanup | CIBA and PostgreSQL cleanup tests |

## Required release commands

The tagged release workflow in `.github/workflows/release.yml` is the canonical automated gate. A local release rehearsal uses the same boundaries:

```sh
npm ci --no-audit --no-fund
npm run db:migrate
npm run check
npm test
npm run test:postgres
AUTHME_SMOKE_DATABASE_URL="$DATABASE_URL" npm run smoke
npm audit --omit=dev --audit-level=high
./scripts/check-helm.sh
docker buildx create --name authme-release-rehearsal --driver docker-container \
  --driver-opt image=moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5
docker buildx inspect --bootstrap authme-release-rehearsal
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
docker buildx build --builder authme-release-rehearsal \
  --pull --no-cache --target runtime --platform linux/amd64 \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --tag authme:release-candidate \
  --output type=docker,dest=/tmp/authme.tar,rewrite-timestamp=true .
docker load --input /tmp/authme.tar
docker buildx rm authme-release-rehearsal
trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 authme:release-candidate
trivy config --severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore.yaml .
trivy fs --scanners secret --exit-code 1 .
syft authme:release-candidate --output cyclonedx-json=/tmp/authme-image.cdx.json
AUTHME_RELEASE_IMAGE_SBOM=/tmp/authme-image.cdx.json \
AUTHME_RELEASE_IMAGE_REFERENCE=ghcr.io/owner/authme@sha256:RELEASE_DIGEST \
npm run release:artifacts -- --require-image
```

`DATABASE_URL` must identify a migrated disposable PostgreSQL 17 database. `test:postgres` intentionally fails instead of skipping when that boundary is absent. Release artifact generation requires `AUTHME_RELEASE_SIGNING_KEY` to name an OpenSSL PEM private key compatible with `openssl dgst -sha256` signing (for example RSA or ECDSA); Ed25519 does not accept an explicit digest in this format. `--unsigned` is rehearsal-only. The tag workflow derives the image digest only after pushing the exact gated image, refuses to overwrite an existing version tag, and fails if the image SBOM or digest reference is absent. GitHub OIDC and registry attestation steps can run only in that trusted tag workflow.

The Dockerfile pins both its frontend and the complete Node 22.23.1
multi-platform manifest digest, and release PostgreSQL/Redis services use the
same pinned digests as local CI. The tag workflow pins Buildx and BuildKit, sets
`SOURCE_DATE_EPOCH` to the tagged commit time, targets `linux/amd64`, uses
BuildKit's timestamp-rewriting Docker exporter for two independent no-cache
runtime builds, and refuses publication unless both their image IDs and
uncompressed layer digests match. Dependabot monitors the npm, Docker, Helm, and
GitHub Actions inputs; digest/version updates remain reviewed changes rather
than release-time drift.

Manual workflow dispatches publish immutable `candidate-<commit>` images for
X1–X3 testing without creating a final release. A stable tag requires the
machine-validated external manifest described in
`docs/external-release-gates.md`, binds it to the exact source commit and
candidate digest, includes it in the signed artifacts, and fails if the rebuilt
stable image is not byte-identical to the candidate. Prerelease tags do not
claim or require those independent records.

Every release publishes `authme-release-public-key.pem`. Verify checksums and detached signatures, then authenticate that key's SHA-256 fingerprint through an independent release-owner channel; co-location is not a trust root. GitHub-hosted provenance is independently verifiable:

```sh
(cd dist && shasum -a 256 --check SHA256SUMS)
openssl dgst -sha256 -verify dist/authme-release-public-key.pem \
  -signature dist/SHA256SUMS.sig dist/SHA256SUMS
openssl pkey -pubin -in dist/authme-release-public-key.pem -outform DER | \
  openssl dgst -sha256
gh attestation verify oci://ghcr.io/asalfaifi/authme@sha256:RELEASE_DIGEST \
  --repo asalfaifi/authme
```

## Evidence that cannot be synthesized in this repository

- X1 closes only with an OpenID Foundation conformance/certification record tied to the exact build and supported profiles.
- X2 closes only with an independent penetration and architecture review plus resolution records for every critical/high finding.
- X3 closes only with signed operator evidence from the target KMS/HSM and infrastructure: live rotation, dependency outage, restore/DR, and regional failover under traffic.

Until all three records are attached, the accurate product label is **v1.0 release candidate**, even when every autonomous milestone and automated gate passes.

## Latest autonomous verification

The repository was re-audited on 2026-07-31 after the v1 lifecycle corrections
were integrated with the current trunk supply-chain and CI hardening:

- Node.js 22.23.1 source validation checked 158 JavaScript files; the complete
  suite ran against migrated PostgreSQL 17 and Redis with 358/358 tests passing
  and zero skips, followed by the dedicated 44/44 PostgreSQL release suite;
- the PostgreSQL protocol smoke passed, including OIDC/RFC 8414, PKCE, token
  audience/claims, refresh replay, device flow, MFA/recovery, SCIM, and audit;
- a real PostgreSQL 17 `pg_dump` v2 backup encrypted both the database and JWKS,
  restored destructively into a separate database, verified all ten migrations
  and a sentinel realm, and preserved `0600` manifest/key permissions;
- the exact production-mode image reached healthy readiness through a trusted
  TLS proxy with PostgreSQL and Redis. Its HA baseline returned the exact issuer;
  500/500 discovery requests passed at concurrency 25 and 480.93 ms p95, while a
  quota-valid 10/10 Authorization Code + PKCE + password + consent + token +
  refresh run passed at concurrency 4 and 4,006.52 ms p95;
- a deliberately over-quota login run confirmed the production account limiter.
  The driver now reports bounded failure reasons, counts each failed operation
  once, and the runbook requires distributed sources/accounts instead of
  weakening throttling for capacity tests;
- two pinned BuildKit v0.29.0 no-cache exports with normalized timestamps
  produced identical image IDs and all 12 uncompressed layer digests. The exact
  `linux/amd64` image ran as uid 1000 with Node.js 22.23.1, no package managers,
  all ten migrations, and a 3,469-component CycloneDX inventory;
- npm reported zero production vulnerabilities; Trivy reported zero fixed
  High/Critical findings across the exact Debian image and every runtime Node
  package, zero High/Critical deployment misconfigurations under the single
  scoped TTL-name exception, and zero repository secrets. Gitleaks found no
  leak in the entire reachable Git history;
- Helm strict lint and deterministic Kubernetes/OpenShift-restricted renders
  passed. Kubeconform strictly validated all 8 default resources and all known
  optional/OpenShift resources; actionlint and ShellCheck also passed;
- the hardened runtime ran as the unprivileged `node` user, contained neither
  npm nor alternate package managers, retained direct operational entrypoints,
  and served the exact configured HTTPS issuer with its container health check
  healthy;
- an ephemeral release-key rehearsal generated the npm archive, normalized
  package and image CycloneDX SBOMs, signed image digest,
  published verification key, and SHA-256 manifest twice with byte-for-byte
  identical output. All published checksums and every detached signature
  verified. The tag workflow is action-pinned and linted to publish/attest those
  files and the exact GHCR image; actual registry/OIDC attestations require the
  trusted tag event and are not represented as locally executed evidence. A
  every version tag requires a GitHub-verified signature, while a stable tag
  additionally requires cryptographic assessor/operator evidence, exact
  candidate source/image binding, and explicit release-owner production
  approval;

These are reproducible autonomous checks, not substitutes for X1 certification,
X2 independent review, or X3 target-infrastructure/hardware drill records.
