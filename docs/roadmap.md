# AuthMe roadmap

## How to read this roadmap

This roadmap separates shipped behavior from intent. It contains no delivery-date promise.

- **Implemented**: present in the release, documented, and tested.
- **Release-gated**: code may exist, but the required security/conformance/operations evidence is incomplete.
- **Staged**: designed or planned, not a supported product capability.

The upstream [`oidc-provider`](https://github.com/panva/node-oidc-provider#implemented-specs--features) supports many specifications, including OpenID Connect, dynamic registration, logout, device flow, PAR, JAR, DPoP, mTLS, CIBA, and FAPI profiles. AuthMe supports a feature only after it is explicitly configured, integrated with realms and PostgreSQL, threat-modeled, documented, and tested. Library certification is not AuthMe certification.

## v0.1: standards-based OIDC foundation

### Implemented product contract

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
- Explicit RFC 8707 resource audiences with audience-bound JWT access tokens,
  filtered Keycloak-shaped authorization claims, and delegated introspection
  for configured opaque-token resources.
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
- Versioned, realm-aware trusted identity-extension registry.
- LDAP/Active Directory credential authentication over LDAPS/StartTLS with mapping and opt-in JIT.
- Upstream OIDC brokering with Authorization Code + PKCE and strict issuer/callback/token validation.
- SAML 2.0 SP-initiated federation with generated metadata, signed Response/Assertion checks, and durable replay protection.
- Immutable external-subject repository, collision-safe opt-in JIT, and explicit audited administrator linking.
- PostgreSQL SCIM 2.0 Users/Groups with discovery, core filtering, pagination, PATCH/PUT/CRUD, ETags, and account-state revocation.
- Production Helm chart for Kubernetes and OpenShift restricted security constraints.

### Staged scope

- Complete realm/client/user/group/role administration API and web console.
- Self-registration policy, verified email, password reset, required actions, account console, and session/device management.
- Self-service passkey enrollment, replacement, loss/recovery policy, attestation governance, and migration tooling around the implemented admin-managed passkey baseline.
- Step-up authentication and `acr`/`amr`/`max_age` policy.
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

### Staged scope

- Curated social-provider templates and advanced upstream OIDC discovery/governance around the v0.2 broker.
- SAML IdP operation, encrypted assertions, artifact binding, IdP-initiated login, and single logout around the v0.2 SP baseline.
- LDAP/Active Directory import, synchronization, and reconciliation around the v0.2 credential-authentication baseline.
- SCIM Bulk, sorting, arbitrary extensions, fine-grained token scopes, and full filtering around the v0.2 Users/Groups baseline.
- Organizations within realms: domains, invitations, memberships, organization-specific IdPs, and token context.
- Delegated fine-grained realm/organization administration.
- Joiner/mover/leaver workflows with transactional events.
- KMS/HSM-backed realm signing keys and automated rotation.
- Backup/restore automation and tested single-region HA around the implemented Helm/OpenShift deployment.

Keycloak's official guide describes its [identity brokering](https://www.keycloak.org/docs/latest/server_admin/#_identity_broker), [LDAP federation](https://www.keycloak.org/docs/latest/server_admin/#_ldap), [organizations](https://www.keycloak.org/docs/latest/server_admin/#_managing_organizations), and [SCIM support](https://www.keycloak.org/docs/latest/server_admin/#_scim). Those behaviors form the parity reference; AuthMe v0.2 implements only the explicitly documented baselines above.

### Exit gates

- SSRF, malicious metadata/JWKS, account-linking, email-trust, and IdP mix-up review.
- LDAP/SCIM reconciliation, conflict, deletion, pagination, and outage tests.
- SAML interoperability and XML signature/encryption review using maintained libraries.
- Organization isolation and delegated-administration tests.
- KMS degradation and key recovery drills.

## v0.4: advanced OAuth and financial-grade profiles

### Staged scope

- JAR and richer policy profiles layered on the implemented PAR support.
- JARM.
- `private_key_jwt` client authentication.
- mTLS client authentication and certificate-bound tokens.
- Richer Resource Indicator policy, resource administration, and multi-audience token governance beyond the v0.1 configured baseline.
- CIBA.
- Selected FAPI 2.0 profiles.

PAR and DPoP are already part of the v0.1 product contract. The remaining profiles—and stronger financial-grade combinations of existing features—need additional AuthMe policy, persistence, proxy, key-management, metadata, operational, and conformance integration. PAR is standardized by [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html), DPoP by [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), and the provider's certifications are listed in its [official README](https://github.com/panva/node-oidc-provider#certification).

### Exit gates

- Relevant OpenID/FAPI conformance plans pass against AuthMe.
- Threat model covers sender-constrained token/key lifecycle and proxy certificate handling.
- HSM/KMS and client key rotation are tested.
- Financial-grade deployment profile is independently reviewed.
- AuthMe makes no certification claim until certification is obtained for the named build/profile.

## v1.0: practical Keycloak replacement target

v1.0 means an organization can replace Keycloak for a documented set of OIDC, SAML, federation, lifecycle, administration, and operational use cases—not that every historical Keycloak extension is cloned.

### Target scope

- Stable, versioned administration and account APIs/UIs.
- Documented Keycloak realm-import transformation and compatibility report.
- Migration support for users, clients, groups, roles, selected credential formats, IdPs, and claim mappers.
- OIDC, SAML, LDAP/AD, SCIM, organizations, strong authentication, brokering, delegated administration, auditing, and lifecycle workflows.
- Production KMS/HSM, HA, backup/restore, rolling upgrades, and disaster-recovery runbooks.
- Extension points with isolation, versioning, and security review boundaries.

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
