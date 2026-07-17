# v1 release-candidate evidence map

This document maps every autonomous milestone to executable evidence. A green unit suite alone is not sufficient: the signed-tag workflow also runs the PostgreSQL-only suite without skips, the PostgreSQL protocol smoke test, production dependency audit, Helm validation, and runtime-image build before producing signed artifacts and an SBOM.

| Milestone | Implementation boundary | Primary executable evidence |
|---|---|---|
| K1 | Deterministic Keycloak export transformer, structured/human compatibility reports, dry-run default, and zero-blocker minimal fixtures for all three declared profiles | `test/keycloak-import.test.js`; `docs/keycloak-compatibility.md`; `docs/keycloak-migration.md` |
| K2 | Subject-bound account console for profile/recovery/password/MFA/passkeys/sessions/invitations and standalone production delivery integration | `test/account-console.test.js`; `test/account-email-delivery.test.js`; `test/postgres-account-console.test.js` |
| K3 | Mutable realm status/settings, managed and dynamically registered clients, roles, nested groups, users, complete client-scope assignment controls, and audited native admin UI/API | `test/admin-management.test.js`; `test/admin-console.test.js`; `test/admin-console-ui.test.js`; `test/admin-api.test.js`; `test/client-auth-jwt.test.js` |
| K4 | Realm-local organizations, unique domains, invitations, current membership, IdP allowlists, durable token context | `test/organization-flow.test.js`; `test/management-store.test.js`; PostgreSQL management test |
| K5 | Downstream SAML IdP metadata, signed Response/Assertion, encryption, IdP initiation, redirect SLO | `test/saml-idp.test.js` |
| K6 | LDAP/AD authentication, bounded import/sync/reconciliation, immutable external identity, outage thresholds | `test/ldap.test.js`; `test/ldap-sync.test.js`; PostgreSQL LDAP tests |
| K7 | SCIM Bulk, stable sorting, full supported core filter grammar, ETags and realm isolation | `test/scim-bulk.test.js`; `test/scim-filter-grammar.test.js`; `test/scim-sorting.test.js`; `test/scim-protocol.test.js`; `test/postgres-scim.test.js` |
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
docker build --pull --target runtime --tag authme:release-candidate .
npm run release:artifacts
```

`DATABASE_URL` must identify a migrated disposable PostgreSQL 17 database. `test:postgres` intentionally fails instead of skipping when that boundary is absent. Release artifact generation requires `AUTHME_RELEASE_SIGNING_KEY` to name an OpenSSL PEM private key compatible with `openssl dgst -sha256` signing (for example RSA or ECDSA); Ed25519 does not accept an explicit digest in this format. `--unsigned` is rehearsal-only.

## Evidence that cannot be synthesized in this repository

- X1 closes only with an OpenID Foundation conformance/certification record tied to the exact build and supported profiles.
- X2 closes only with an independent penetration and architecture review plus resolution records for every critical/high finding.
- X3 closes only with signed operator evidence from the target KMS/HSM and infrastructure: live rotation, dependency outage, restore/DR, and regional failover under traffic.

Until all three records are attached, the accurate product label is **v1.0 release candidate**, even when every autonomous milestone and automated gate passes.

## Latest autonomous verification

The repository was re-audited on 2026-07-17 after the client-role, migration,
flow/federation/CIBA, account-delivery, policy-lifecycle, organization,
federated-link, backup-manifest, dynamic-registration deletion, and admin
client-scope lifecycle corrections:

- clean Node.js 22 container: source check passed for 150 JavaScript files;
  ordinary suite 335 tests, 313 passed, 22 PostgreSQL-only skips, 0 failures;
- clean Node.js 22 container against migrated PostgreSQL 17: 44/44 release
  tests passed with 0 skips, including concurrent role/group graphs, managed
  and registration-managed client policy cleanup, invitation rollback,
  account-membership cascades, and migration `010_client_roles.sql`;
- PostgreSQL protocol smoke passed, including OIDC/RFC 8414, PKCE, token
  audience/claims, refresh replay, device flow, MFA/recovery, SCIM, and audit;
- real `pg_dump` v2 backup and destructive restore into an isolated database
  passed; all 10 migration records, the `client_roles` table, and recovered
  signing keys were checked;
- production dependency audit reported zero vulnerabilities, Helm strict lint
  and deterministic OpenShift-restricted renders passed, and the Node.js 22
  runtime image started with exact issuer discovery;
- signed archive, CycloneDX SBOM, and checksum signatures verified; a second
  artifact run was byte-for-byte identical;
- realm HA baseline probe and a 40-request/8-worker discovery rehearsal passed
  with zero failures and 172.05 ms p95 on the rebuilt local audit image.

These are reproducible autonomous checks, not substitutes for X1 certification,
X2 independent review, or X3 target-infrastructure/hardware drill records.
