# AuthMe — Milestones

_Standards-first, self-hosted identity & access server (a Keycloak alternative). Node.js 22 ESM, `oidc-provider` 9.9.1._

**Status legend:** ✅ Done & merged · 🔄 In progress · ⏳ Not started · 🔒 External-only (cannot be finished autonomously)

**Current trunk:** branch `codex-build/v0.4` — **v1.0 code-complete release candidate**. All autonomous milestones and hardening follow-ups are implemented. The three external release gates remain explicitly locked.

---

## Baseline — shipped before this effort

| ID | Milestone | Status |
|----|-----------|--------|
| v0.1 | Standards-based OIDC foundation (Auth Code+PKCE, refresh, client credentials, UserInfo, introspection, revocation, RP-initiated + back-channel logout, device flow, PAR, DPoP, RFC 8707 resources, dynamic registration, Argon2id/TOTP/recovery/passkeys) | ✅ |
| v0.2 | Enterprise identity baseline (WebAuthn passwordless, LDAP/AD auth, upstream OIDC brokering, SAML 2.0 SP federation, SCIM 2.0 Users/Groups, Helm chart) | ✅ |
| v0.3 | Enterprise lifecycle & advanced federation (realm-scoped operator/admin console, reserved OIDC admin client, durable admin grants, LoA2, opaque digest cookies) | ✅ |

---

## v0.4 — Advanced OAuth & FAPI ✅ COMPLETE

| ID | Milestone | Spec | Status |
|----|-----------|------|--------|
| J1 | JARM — JWT-secured authorization response modes | JARM | ✅ merged |
| J2 | JAR — signed request objects | RFC 9101 | ✅ merged |
| J3 | `private_key_jwt` + `client_secret_jwt` client auth | RFC 7523 | ✅ merged |
| J4 | mTLS client auth + certificate-bound tokens (`cnf.x5t#S256`) | RFC 8705 | ✅ merged |
| J5 | JWT-secured introspection + UserInfo responses | RFC 9701 / OIDC Core | ✅ merged |
| J6 | CIBA — client-initiated backchannel authentication (poll mode) | OpenID CIBA Core | ✅ merged |
| J7 | Richer resource-indicator policy (multi-audience governance) | RFC 8707 | ✅ merged |
| J8 | FAPI 2.0 security profile (per-client opt-in) | FAPI 2.0 | ✅ merged |

---

## v1.0 — Keycloak-replacement completion

| ID | Milestone | Status |
|----|-----------|--------|
| K1 | Keycloak realm-import transformation + compatibility report | ✅ merged |
| K7 | SCIM 2.0 Bulk, sorting, and full filter grammar | ✅ merged |
| K6 | LDAP/AD import, synchronization, and reconciliation | ✅ merged |
| K5 | SAML 2.0 IdP mode — metadata, signed/encrypted assertions, SLO | ✅ merged |
| K2 | Self-service end-user account console (profile, password change, email verify, password reset, TOTP/passkey self-mgmt, session revocation) | ✅ merged |
| K3 | Full mutable realm/client/role/group admin API + UI | ✅ implemented |
| K4 | Organizations within realms — domains, invitations, memberships, org-specific IdPs, token context | ✅ implemented |
| K8 | Configurable authentication-flow / step-up engine (`acr`/`amr`/`max_age` policy) | ✅ implemented |
| K9 | Nested groups, composite roles, reusable client scopes, configurable claim mappers | ✅ implemented |
| K10 | Backup/restore automation + single-region HA rehearsal | ✅ implemented |
| K11 | KMS/HSM-backed signing keys + automated rotation (code path) | ✅ implemented |

---

## Hardening follow-ups (from security reviews)

| ID | Milestone | Source |
|----|-----------|--------|
| H1 | Redact/omit `Location` header (signed JWT w/ code+state) from HTTP logs | ✅ implemented |
| H2 | Resource-indicator regression tests for refresh/client-credentials/device-flow widening | ✅ implemented |
| H3 | CIBA poll backoff should keep increasing past 300s per CIBA Core §11 | ✅ implemented |
| H4 | Preserve `expired_token` vs `invalid_grant` distinction for cleaned-up CIBA records | ✅ implemented |

---

## Cannot be completed autonomously — report, never fake 🔒

| ID | Milestone | Why |
|----|-----------|-----|
| X1 | OpenID Foundation certification (supported provider profiles) | External conformance body |
| X2 | Independent penetration test + architecture review | External security firm |
| X3 | HSM/KMS hardware rotation & DR / regional-failover drills | Physical/infra, human-run |

---

## v1.0 exit criteria (gates before declaring 1.0)

- Published compatibility matrix + migration tool with deterministic reconciliation (K1 delivers the tool; matrix to finalize).
- No critical migration blocker for declared reference deployments.
- OpenID certification for supported profiles (X1).
- Independent penetration test + architecture review, critical/high findings resolved (X2).
- Reproducible builds, signed release artifacts, SBOM, vulnerability-response policy, documented support window.
- Proven restore, key rotation, rolling upgrade, dependency-outage, and regional-failover procedures (K10, K11, X3).
- Performance/service-level targets validated under representative load.

---

## Summary

- **v0.4:** 8/8 ✅
- **v1.0 code:** 11/11 ✅
- **Hardening:** 4/4 ✅
- **External gates:** 3 (X1–X3) — require third parties

The repository is therefore a v1.0 release candidate, not a certified final v1.0 release. X1–X3 cannot be represented as complete until their independent evidence is attached to a release record.
