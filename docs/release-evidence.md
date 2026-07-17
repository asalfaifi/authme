# v1 release-candidate evidence map

This document maps every autonomous milestone to executable evidence. A green unit suite alone is not sufficient: the signed-tag workflow also runs the PostgreSQL-only suite without skips, the PostgreSQL protocol smoke test, production dependency audit, Helm validation, and runtime-image build before producing signed artifacts and an SBOM.

| Milestone | Implementation boundary | Primary executable evidence |
|---|---|---|
| K1 | Deterministic Keycloak export transformer, structured/human compatibility reports, dry-run default | `test/keycloak-import.test.js`; `docs/keycloak-compatibility.md`; `docs/keycloak-migration.md` |
| K2 | Subject-bound account console for profile/recovery/password/MFA/passkeys/sessions/invitations | `test/account-console.test.js`; `test/account-recovery.test.js`; `test/account-security.test.js` |
| K3 | Mutable realm status/settings, managed clients, roles, nested groups, users, and audited native admin UI/API | `test/admin-management.test.js`; `test/admin-console.test.js`; `test/admin-api.test.js` |
| K4 | Realm-local organizations, unique domains, invitations, current membership, IdP allowlists, durable token context | `test/organization-flow.test.js`; `test/management-store.test.js`; PostgreSQL management test |
| K5 | Downstream SAML IdP metadata, signed Response/Assertion, encryption, IdP initiation, redirect SLO | `test/saml-idp.test.js` |
| K6 | LDAP/AD authentication, bounded import/sync/reconciliation, immutable external identity, outage thresholds | `test/ldap.test.js`; `test/ldap-sync.test.js`; PostgreSQL LDAP tests |
| K7 | SCIM Bulk, stable sorting, full supported core filter grammar, ETags and realm isolation | `test/scim-bulk.test.js`; `test/scim-filter.test.js`; `test/scim-sort.test.js`; PostgreSQL SCIM contract |
| K8 | Executable required/alternative/conditional flow policy; client/ACR/AMR/max-age selection; existing-session revalidation | `test/organization-flow.test.js`; `test/management-store.test.js`; admin negative tests |
| K9 | Composite role graph, nested path lifecycle, existing-reference validation, reusable scopes, mapper ownership | `test/admin-management.test.js`; `test/management-store.test.js`; PostgreSQL management/concurrency tests |
| K10 | Authenticated encrypted backup/restore, manifest/checksum verification, continuous zero-error rollout probe, representative protocol load driver | `test/backup.test.js`; `test/availability-rehearsal.test.js`; `test/load-rehearsal.test.js`; `scripts/ha-rehearsal.mjs` |
| K11 | Public-only KMS/HSM inventory, `oidc-provider` external signing, deployable adapter modules, fail-closed overlap rotation | `test/signing-key-manager.test.js`; `docs/production.md` signing contract |
| H1 | Redirect/action token log redaction | `test/logging.test.js` |
| H2 | Resource audience cannot widen through refresh, client credentials, or device polling | `test/resource-flow.test.js` |
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

`DATABASE_URL` must identify a migrated disposable PostgreSQL 17 database. `test:postgres` intentionally fails instead of skipping when that boundary is absent. Release artifact generation requires `AUTHME_RELEASE_SIGNING_KEY`; `--unsigned` is rehearsal-only.

## Evidence that cannot be synthesized in this repository

- X1 closes only with an OpenID Foundation conformance/certification record tied to the exact build and supported profiles.
- X2 closes only with an independent penetration and architecture review plus resolution records for every critical/high finding.
- X3 closes only with signed operator evidence from the target KMS/HSM and infrastructure: live rotation, dependency outage, restore/DR, and regional failover under traffic.

Until all three records are attached, the accurate product label is **v1.0 release candidate**, even when every autonomous milestone and automated gate passes.
