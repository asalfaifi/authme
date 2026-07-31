# AuthMe roadmap

## How to read this roadmap

This roadmap separates shipped behavior from intent. It contains no delivery-date promise.

The v0.1–v0.4 sections are historical release snapshots; a capability described there as staged may be implemented by the later v1.0 section. `MILESTONES.md` is the concise completion ledger.

- **Implemented**: present in the release, documented, and tested.
- **Release-gated**: code may exist, but the required security/conformance/operations evidence is incomplete.
- **Staged**: designed or planned, not a supported product capability.

The upstream [`oidc-provider`](https://github.com/panva/node-oidc-provider#implemented-specs--features) supports many specifications, including OpenID Connect, dynamic registration, logout, device flow, PAR, JAR, DPoP, mTLS, CIBA, and FAPI profiles. AuthMe supports a feature only after it is explicitly configured, integrated with realms and PostgreSQL, threat-modeled, documented, and tested. Library certification is not AuthMe certification.

## v0.1: standards-based OIDC foundation

### Implemented release-candidate contract

- Node.js 22 standalone service.
- `oidc-provider` 9.9.1 protocol engine.
- Realm issuer model at `https://host/realms/{realm}`.
- Keycloak-compatible OIDC endpoint paths.
- PostgreSQL durable provider adapter; no in-memory correctness dependency.
- Optional Redis-backed shared rate limiting.
- OpenID discovery and JWKS.
- Authorization Code with PKCE `S256`.
- Refresh tokens under client/scope policy.
- Client Credentials.
- UserInfo, introspection, revocation, and RP-initiated logout.
- Back-channel logout.
- Device Authorization Grant.
- Pushed Authorization Requests (PAR).
- DPoP-bound tokens for configured clients.
- Implemented RFC 8707 resource policy with per-client audience allowlists,
  explicit multi-resource combinations, audience-bound JWT access tokens,
  per-resource scope and claim filtering, and delegated introspection for
  configured opaque-token resources.
- Public and pairwise subject identifiers.
- Dynamic client registration protected by an initial access token.
- Basic users, clients, realm roles, client roles, groups, and Keycloak-shaped role/group claims.
- Argon2id passwords, TOTP, one-use recovery codes, and fresh WebAuthn passkey registration/login.
- A minimal bearer-protected AuthMe administration API and append-only JSON audit events.
- AuthMe-owned login/consent interactions.
- Health, structured logging, migrations, container/development deployment assets, and automated tests.

### v0.1 limitations

- Not complete Keycloak parity.
- Not an OpenID-certified AuthMe distribution.
- No SAML, LDAP/AD, Kerberos, SCIM, or identity brokering.
- No WebAuthn/U2F credential import, attestation-policy enforcement, or self-service passkey recovery; fresh user-verified passkeys are implemented.
- No Keycloak Admin REST compatibility or complete administrator/account consoles.
- No configurable authentication-flow/plugin system.
- No UMA/Authorization Services policy engine.
- No multi-site active/active design.

### v0.1 release gates

- All unit/integration/browser tests pass on a clean PostgreSQL database.
- Concurrent code/token replay tests pass.
- Cross-realm isolation tests cover each repository/provider artifact model.
- OpenID Foundation conformance plans pass for the supported core, logout, device, PAR and DPoP profiles where a plan exists.
- Protected dynamic-registration and initial-access-token abuse tests pass.
- TOTP enrollment/login and atomic recovery-code consumption tests pass.
- Exact redirect, proxy/issuer, cookie, CSP, CORS, and log-redaction tests pass.
- Migration, backup restore, key rotation, and load/failure rehearsals pass.
- Threat model and independent security review are complete before broad production use.

## v0.2: enterprise identity baseline

### Implemented product contract

- User-verified WebAuthn/passkey registration and passwordless login with durable challenges/counters.
- A realm-scoped self-service account console at `/realms/{realm}/account/`, authenticated through the reserved `authme-account-console` OIDC client with Authorization Code, PKCE, state, nonce, and recent authentication.
- Self-service safe-profile editing, current-password-protected Argon2id password changes, verified email changes, and enumeration-safe rate-limited password reset. Email and reset capabilities are expiring, one-use, and stored only as keyed digests; production delivery is an injected integration rather than a built-in mail transport.
- Self-service TOTP enrollment/replacement/removal, one-time recovery-code regeneration, passkey registration/list/removal, and active account/OIDC session listing and revocation. Every operation is bound to the authenticated subject and issuer realm and emits security audit events.
- Opaque account-console cookies with digest-only durable storage, idle and absolute expiration, account-security-version binding, exact-origin/JSON/CSRF enforcement, and no browser storage of protocol or administration tokens.
- Versioned, realm-aware trusted identity-extension registry.
- LDAP/Active Directory credential authentication over LDAPS/StartTLS with mapping and opt-in JIT.
- Upstream OIDC brokering with Authorization Code + PKCE and strict issuer/callback/token validation.
- SAML 2.0 SP-initiated federation with generated metadata, signed Response/Assertion checks, and durable replay protection.
- Immutable external-subject repository, collision-safe opt-in JIT, and explicit audited administrator linking.
- PostgreSQL SCIM 2.0 Users/Groups with discovery, core filtering, pagination, PATCH/PUT/CRUD, ETags, and account-state revocation.
- Production Helm chart for Kubernetes and OpenShift restricted security constraints.

### Staged scope

- Complete mutable realm/client/group/role policy administration; the v0.3 operator console already covers user, credential, session, federation, registration, and audit operations.
- Self-registration policy and generalized required-action workflows beyond the implemented email-verification and password-reset actions.
- Passkey loss/recovery policy, attestation governance, imported credential support, and migration tooling around the implemented administrator and self-service passkey baseline.
- General client-configurable step-up authentication and `acr`/`amr`/`max_age` policy beyond the v0.3 console's fixed recent-LoA2 production requirement.
- Nested groups, composite roles, reusable client scopes, and configurable claim mappers.
- Offline access/session policy and richer revocation controls.
- Propagation of an expected account security epoch through interactive authentication completion, closing the remaining mutation/in-flight login boundary race; grant-linked code/refresh issuance already requires a live same-epoch parent grant.
- Front-channel logout and richer policy/telemetry for the implemented back-channel logout.
- Software statements and richer policy/governance for the implemented protected dynamic registration.
- Theme/branding model that does not permit arbitrary active content.
- Reliable webhook event delivery and SIEM integrations.

### Exit gates

- [WebAuthn](https://www.w3.org/TR/webauthn-3/) registration/authentication/recovery threat model and browser matrix.
- MFA enrollment, replacement, loss, recovery, and administrator reset tests.
- Admin authorization matrix and audit coverage.
- Logout and device-flow regression plans.
- Accessibility and localization testing for interaction/account/admin UIs.
- Account-recovery abuse and user-enumeration review.

## v0.3: enterprise lifecycle and advanced federation

### Implemented product contract

- A permanently expanded, realm-scoped operator console at `/admin/` with user, credential, session, federation, dynamic-registration, audit, and safe configuration views.
- Realm-scoped LDAP/Active Directory import, synchronization, and reconciliation with immutable external keys, bounded paged searches, collision-safe account creation, mapped group/role updates, and configurable disable/delete handling for removed entries.
- A reserved `authme-admin-console` OIDC client using Authorization Code with PKCE `S256`, exact callback matching, and validated `state` and `nonce`.
- Durable, enabled realm-administrator grants with explicit permissions and a revocable version snapshot. The development bootstrap grant uses `*`; production deployments should grant only required permissions.
- Production console authentication requires a recent LoA2 result: a passkey, or password plus TOTP/recovery. Development mode deliberately permits password-only console authentication.
- Opaque console cookies whose keyed digests—not bearer values—are stored in PostgreSQL, with idle and absolute expiry, user/grant version pinning, and server-side logout invalidation.
- Exact-origin, JSON content-type, CSRF, realm-binding, and per-permission enforcement for unsafe authenticated console API operations.
- A deployment-root bearer for automation under `/admin/v1`, kept separate from the console's OIDC login, cookie, and realm grants.
- A read-only, allowlisted realm configuration catalog that exposes operator-safe policy and capability metadata without secrets, key material, credential hashes, or bootstrap tokens.
- Realm-scoped SAML 2.0 IdP operation with published metadata, HTTP-Redirect and HTTP-POST AuthnRequests, exact registered ACS enforcement, AuthMe login/session reuse, signed Responses and Assertions, audience/time/one-use/request correlation, optional per-SP assertion encryption, opt-in IdP-initiated login, and signed SP-initiated redirect SLO.

### Staged scope

- Curated social-provider templates and advanced upstream OIDC discovery/governance around the v0.2 broker.
- SAML artifact binding, encrypted assertions received by AuthMe's upstream-SP broker, and POST/SOAP or multi-party logout beyond the implemented SAML IdP redirect-SLO baseline.
- SCIM Bulk, sorting, arbitrary extensions, fine-grained token scopes, and full filtering around the v0.2 Users/Groups baseline.
- Organizations within realms: domains, invitations, memberships, organization-specific IdPs, and token context.
- Approval-backed administrator-grant lifecycle and organization-level delegation beyond the implemented realm permission model.
- Joiner/mover/leaver workflows with transactional events.
- KMS/HSM-backed realm signing keys and automated rotation.
- Backup/restore automation and tested single-region HA around the implemented Helm/OpenShift deployment.

Keycloak's official guide describes its [identity brokering](https://www.keycloak.org/docs/latest/server_admin/#_identity_broker), [LDAP federation](https://www.keycloak.org/docs/latest/server_admin/#_ldap), [organizations](https://www.keycloak.org/docs/latest/server_admin/#_managing_organizations), and [SCIM support](https://www.keycloak.org/docs/latest/server_admin/#_scim). Those behaviors form the parity reference; AuthMe v0.3 implements only the explicitly documented v0.1-v0.3 baselines above.

### Exit gates

- SSRF, malicious metadata/JWKS, account-linking, email-trust, and IdP mix-up review.
- LDAP/SCIM reconciliation, conflict, deletion, pagination, and outage tests.
- SAML interoperability and XML signature/encryption review using maintained libraries.
- Organization isolation and delegated-administration tests.
- Console accessibility, localization, OIDC/PKCE, LoA2, realm-permission, CSRF, and session-revocation matrices.
- KMS degradation and key recovery drills.

## v0.4: advanced OAuth and financial-grade profiles

### Implemented product contract

- [JWT Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html) with realm-key-signed authorization responses for `jwt`, `query.jwt`, `fragment.jwt`, and `form_post.jwt` response modes.
- [`private_key_jwt` and `client_secret_jwt` client authentication](https://www.rfc-editor.org/rfc/rfc7523.html) at the token, introspection, and revocation endpoints, with explicit signing-algorithm allowlists, exact assertion audiences, and durable one-use `jti` replay protection.
- [JWT-Secured Authorization Request (JAR, RFC 9101)](https://www.rfc-editor.org/rfc/rfc9101.html) by value with signed request objects, registered client public keys, and an asymmetric algorithm allowlist.
- [Signed JWT UserInfo responses](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfoResponse) for clients that register `userinfo_signed_response_alg`; clients without the opt-in continue to receive JSON.
- [JWT responses for OAuth token introspection](https://www.rfc-editor.org/rfc/rfc9701.html) for authorized resource clients that register `introspection_signed_response_alg` and request `application/token-introspection+jwt`; ordinary introspection remains JSON.
- [Mutual-TLS OAuth client authentication and certificate-bound access tokens (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705.html), with PKI and self-signed client methods, proxy-source/header validation, and `cnf.x5t#S256` token binding.
- [OpenID CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) in poll mode for confidential clients, with realm-scoped request persistence, explicit authentication-device completion, and durable poll throttling.
- An opt-in, per-client [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0.html) authorization-code policy selected by `fapi_profile: "2.0"`, composing client-authenticated PAR, PKCE `S256`, PS256/ES256 JAR and JARM, DPoP or mTLS sender-constrained access tokens, strong client authentication, exact assertion audiences, and 60-second authorization codes. The JAR/JARM layer follows [FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-message-signing-2_0-final.html). This is implemented behavior, not a certification claim.

### Staged scope

- Richer policy profiles layered on the implemented PAR and JAR support.
- Richer Resource Indicator policy, resource administration, and multi-audience token governance beyond the v0.1 configured baseline.
- CIBA ping and push delivery modes.
- FAPI 2.0 CIBA, client-credentials, refresh-grant, ecosystem-specific, and resource-server profiles beyond the implemented authorization-code policy.

PAR and DPoP are already part of the v0.1 product contract. JAR, JARM, the composed FAPI 2.0 authorization-code policy, CIBA poll mode, `private_key_jwt`/`client_secret_jwt` and mTLS client authentication, certificate-bound access tokens, signed JWT UserInfo, and JWT-secured introspection responses are part of the v0.4 product contract. The remaining profiles need additional AuthMe policy, persistence, proxy, key-management, metadata, operational, and conformance integration. PAR is standardized by [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html), DPoP by [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), mTLS by [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), JAR by [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html), JARM by the [JWT Secured Authorization Response Mode specification](https://openid.net/specs/oauth-v2-jarm.html), CIBA by [OpenID CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), client JWT authentication by [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html), signed UserInfo responses by [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfoResponse), and JWT introspection responses by [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701.html). The provider's certifications are listed in its [official README](https://github.com/panva/node-oidc-provider#certification); those certifications do not certify AuthMe.

### Exit gates

- Relevant OpenID/FAPI conformance plans pass against AuthMe.
- Threat model covers sender-constrained token/key lifecycle and proxy certificate handling.
- HSM/KMS and client key rotation are tested.
- Financial-grade deployment profile is independently reviewed.
- AuthMe makes no certification claim until certification is obtained for the named build/profile.

## v1.0: practical Keycloak replacement target

v1.0 means an organization can replace Keycloak for a documented set of OIDC, SAML, federation, lifecycle, administration, and operational use cases—not that every historical Keycloak extension is cloned.

### Implemented product contract

- Deterministic offline transformation of a Keycloak realm/partial export into
  AuthMe realm, OIDC client, downstream SAML service-provider, role, group,
  user, and supported upstream federation
  configuration, with structured JSON and human-readable compatibility reports.
  The tool fails closed on malformed input, omits source credentials/keys, and
  remains a reviewed planning artifact rather than an automatic database
  cutover.
- SCIM 2.0 Bulk, sorting, and the supported full core filter grammar.
- LDAP/AD import, synchronization, and deterministic reconciliation.
- Downstream SAML 2.0 IdP metadata, signed/encrypted assertions, IdP initiation, and redirect SLO.
- End-user account console for profile, password, email recovery/verification, TOTP, recovery codes, passkeys, sessions, and organization invitations.
- AuthMe-native mutable realm/client/role/group administration API and console.
- Nested groups, composite roles, reusable client scopes, and configurable claim mappers.
- Organizations with domain, invitation, membership, organization IdP, and token context policy.
- Configurable authentication flows with client/ACR selection, required/alternative/conditional steps, AMR verification, and maximum-age step-up.
- AES-256-GCM encrypted database/JWKS backup, authenticated-manifest destructive restore, single-region HA and load rehearsal commands.
- File and external KMS/HSM signing-provider lifecycle, public-only inventory, scheduled/forced rotation, and public-key overlap.
- Reproducible npm archives, package/image CycloneDX SBOMs, signed SHA-256 image-digest manifests, published verification key, fail-closed vulnerability/configuration/secret scans, no-overwrite GHCR tag publication, and release/registry provenance plus SBOM attestations.
- H1–H4 security follow-ups: redirect-location redaction, audience non-widening regression coverage, unbounded CIBA slow-down, and retained `expired_token` semantics.

The code is complete for K1–K11. Final `1.0.0` release declaration remains blocked by external OpenID certification, independent penetration/architecture review, and hardware/DR/regional drills.

### Explicitly optional or later parity

- Kerberos/SPNEGO and X.509 authentication.
- Keycloak Admin REST wire compatibility.
- UMA 2/Keycloak Authorization Services policy engine.
- A Keycloak SPI/theme binary compatibility layer.
- Multi-region active/active writes.

These items move into v1 only when demanded by a committed migration and backed by tests. Otherwise they remain post-v1 modules.

### v1 exit criteria

- Published compatibility matrix and migration tool with deterministic reconciliation.
- No critical migration blocker for the declared reference deployments.
- OpenID certification for AuthMe's supported provider profiles.
- Independent penetration test and architecture review with resolved critical/high findings.
- Reproducible builds, signed release artifacts, SBOM, vulnerability response policy, and documented support window.
- Proven restore, key rotation, rolling upgrade, dependency outage, and regional failover procedures for the supported topology.
- Performance/service-level targets validated with representative load.

## Work-item definition of done

No roadmap item is complete until it includes:

1. an updated architecture and threat model;
2. tenant/realm isolation analysis;
3. schema migration and rollback/forward-compatibility plan;
4. protocol and negative tests, including concurrency/replay where applicable;
5. audit, metrics, redaction, and operator runbooks;
6. migration/compatibility documentation;
7. primary-source standards links;
8. conformance evidence when a relevant suite exists.

## Primary references

- [OpenID Connect specifications](https://openid.net/developers/specs/)
- [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/)
- [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- [`oidc-provider` supported specifications and certifications](https://github.com/panva/node-oidc-provider)
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [Keycloak high-availability overview](https://www.keycloak.org/high-availability/introduction)
