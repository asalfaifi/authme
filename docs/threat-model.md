# AuthMe threat model

## Scope

This threat model covers the AuthMe v0.3 standalone service, its browser interactions, OAuth/OIDC endpoints including device flow, PAR, DPoP, mTLS, dynamic registration and logout, upstream OIDC and SAML federation, downstream SAML IdP operation including assertion encryption and redirect SLO, LDAP/AD authentication, SCIM Users/Groups provisioning, PostgreSQL adapter, password/TOTP/recovery/passkey credentials, optional Redis rate limiter, the OIDC-authenticated administration console, the separately bearer-protected root API, and deployment behind a TLS proxy.

It does not claim to cover Kerberos/SPNEGO, RADIUS, X.509 login, SAML artifact binding, upstream-broker assertion decryption, POST/SOAP or multi-party SAML logout, LDAP server-side change-log controls, imported U2F/WebAuthn credentials, authenticator attestation trust policy, KMS/HSM integration, approval-backed administrator-grant lifecycle, organization-level delegation, generalized self-registration/required actions, passkey loss recovery, or multi-site operation. Those features require their own threat-model updates before release.

Normative protocol guidance comes from [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), the [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html), and [JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html).

## Security objectives

AuthMe must:

1. authenticate the intended user without disclosing credentials to clients;
2. issue tokens only to an authenticated, authorized client and redirect URI;
3. prevent cross-realm reads, writes, sessions, and token confusion;
4. preserve the confidentiality and integrity of credentials, tokens, codes, and signing keys;
5. make one-use protocol artifacts resistant to replay and races;
6. provide actionable, tamper-evident-enough security audit data without logging secrets;
7. degrade observably rather than silently bypassing security controls;
8. remain available under expected load and bounded abuse.

## Assets

- User password verifiers and recovery material.
- Client credentials.
- Realm signing private keys.
- Browser sessions, grants, authorization codes, access tokens, refresh tokens, and replay records.
- Realm-scoped administrator grants, opaque console session bearers, and their durable digests/version snapshots.
- User profile, group, and role data.
- Realm/client configuration, especially redirect URIs and issuer values.
- LDAP bind credentials, OIDC client secrets, SAML private keys/certificates, SCIM bearer tokens, and external subject links.
- Audit records and operational configuration.
- PostgreSQL and optional Redis credentials.

## Trust boundaries

```text
untrusted browser/client
        |
        | HTTPS
        v
trusted proxy boundary
        |
        v
AuthMe HTTP / realm / provider boundary
        |                         |
        v                         v
PostgreSQL trust boundary      optional Redis boundary
        |
        v
backup / secret-management boundary

external IdP / LDAP / SCIM client boundaries connect to AuthMe over separately authenticated TLS channels
```

The browser, OAuth client input, proxy headers, database contents, imported migration data, and administrator-supplied configuration are all treated as untrusted until validated for their use. A private network is not itself a trust control.

The administrator browser and root automation client cross different credential boundaries. The browser authenticates through AuthMe OIDC and receives only a realm-bound opaque console cookie. Root automation presents `AUTHME_ADMIN_TOKEN` directly to the API. Neither credential is accepted as a substitute for the other's login flow, and the root bearer must never be delivered to browser code.

## Attacker profiles

- An unauthenticated internet attacker.
- A malicious or compromised registered OAuth client.
- A malicious or compromised upstream IdP, directory entry, or SCIM provisioning client.
- A valid user attacking another user or realm.
- A credential-stuffing or denial-of-service botnet.
- An attacker able to steal a browser token, code, cookie, or refresh token.
- A compromised reverse proxy, application node, dependency, CI runner, or database credential.
- A careless or malicious realm administrator.
- An attacker with access to logs, backups, or metrics.

## Threats and controls

| Threat | v0.3 controls | Residual or staged work |
|---|---|---|
| Redirect URI manipulation or open redirect | Exact registered redirect matching; no wildcard production redirects; validate post-logout redirects | Periodic client-configuration review |
| Authorization-code interception/injection | Authorization Code flow, PKCE `S256`, short-lived one-use codes, client/redirect/PKCE binding; PAR for protected request submission; optional DPoP code/token binding | PAR/DPoP negative and conformance tests remain release gates |
| CSRF/login swapping | Provider-managed transaction state; `state`/`nonce` support; SameSite cookies; CSRF tokens on AuthMe forms | Browser conformance and adversarial tests remain release gates |
| Mix-up between issuers/realms | Immutable per-realm issuer; issuer in discovery and tokens; realm-scoped artifacts; exact issuer validation | Cross-realm fuzz/property tests |
| Upstream OIDC mix-up, SSRF, or token substitution | Fixed HTTPS endpoints, no redirects, PKCE, provider-bound one-use state/nonce/callback, exact issuer/audience/authorized-party/UserInfo-subject checks, signing-algorithm allowlist | Provider metadata/key rotation remains an operator-managed change |
| Upstream SAML signature wrapping, assertion substitution, or replay | Bounded XML, prohibited DTD/entities, pinned IdP certificates, signed Response and Assertion, exact issuer/destination/recipient/audience/`InResponseTo`/time checks, durable Response/Assertion replay keys | Upstream assertion decryption and artifact binding are unsupported |
| SAML IdP XSW, XXE, signature downgrade, or request replay | Bounded DEFLATE/base64/XML; DTD/entity rejection; one protocol root and unique IDs; RSA-SHA-256/512 plus SHA-256/512 and exclusive-canonicalization allowlists; maintained Node-SAML/xml-crypto verification; root-reference checks; pinned per-SP certificates; durable realm-scoped one-use request/state keys | Independent SAML interoperability and XML security review remains a release gate |
| SAML assertion exfiltration or ACS open redirect | SP is selected by exact realm-local Issuer and the request ACS must byte-match its registered HTTPS URL; response Destination/Recipient are server-selected from that registration; IdP initiation uses only the first registered ACS | A malicious registered ACS receives the attributes its operator explicitly mapped; registration and mapping changes are privileged |
| SAML IdP session/login swapping or logout abuse | Authentication runs through a reserved realm OIDC client with state, nonce, PKCE, exact redirect and one-use code binding; SLO requires a signed request, issued session index/NameID, request replay check, active-browser account match, and existing AuthMe logout | Front-channel logout remains susceptible to normal browser availability and SP signing-key compromise |
| LDAP injection, ambiguous account lookup, or credential interception | RFC 4515 filter escaping, exactly-one bounded search, distinct user bind, LDAPS/StartTLS certificate validation, operation/connect timeouts | Directory availability and CA/bind-secret rotation remain operator responsibilities |
| Federated account takeover by email/username collision | Identity key includes realm/provider/canonical issuer/immutable subject; collisions never auto-link; JIT is opt-in; explicit root-admin linking is audited | Root administrator can intentionally create a dangerous link and requires procedural controls |
| SCIM cross-realm mutation, lost update, or bearer theft | Realm-bound independent tokens, constant-time comparison, UUID/realm constraints, weak ETags and CAS, bounded parser/filter/page sizes, account-state revocation | Broad token scope, sequential audit persistence, no delegated SCIM scopes, Bulk, or full filter grammar |
| Authorization-code replay race | PostgreSQL-backed record with atomic consumption and uniqueness | Load testing under concurrent redemption |
| Refresh-token theft/replay | Provider-managed rotation/revocation persisted in PostgreSQL; bounded lifetimes; DPoP binding and mTLS certificate/client binding for configured clients | Explicit family-wide reuse telemetry is staged |
| Access-token replay | TLS, short expiry, audience/scope restriction, DPoP or mTLS sender constraint for configured clients, persisted DPoP replay detection | Resource servers must enforce `cnf` certificate matching; bearer tokens remain replayable |
| JWT algorithm or token-kind confusion | Maintained JOSE stack; configured algorithm allowlist; issuer, audience, type, signature, and time validation | Independent configuration review and negative corpus tests |
| Client impersonation | Confidential-client authentication and protected secret storage; constant-time verification through maintained libraries; allowlisted JWT and mTLS authentication profiles | Client CA issuance policy and proxy compromise remain deployment risks |
| Session fixation or cookie theft | Regenerate session context after authentication; Secure, HttpOnly, SameSite cookies; no tokens in URLs or local storage; user-verified passkey login is available | Password/TOTP paths remain phishable; no self-service passkey recovery |
| Logout abuse | Validate ID-token hint and exact registered post-logout URI; signed back-channel logout tokens and registered client endpoint policy | Front-channel logout is staged unless explicitly enabled |
| Device-code phishing or user-code guessing | Short-lived high-entropy device codes, rate-limited verification, explicit user confirmation displaying the requesting client | Device-flow conformance and usability review |
| PAR request substitution/replay | Authenticated client policy where required, high-entropy expiring request URI, provider persistence and one-use processing | Concurrent replay and request-binding tests |
| DPoP proof replay/substitution | Provider validation of signature, public-key thumbprint, method, URL, timestamps/nonces and replay identifier persisted in PostgreSQL | Clock-skew, nonce and cluster replay tests |
| Unauthorized dynamic registration | Initial access token required, bounded scope/lifetime/use, strict metadata and redirect validation, audited registration | Initial-access-token issuance remains a high-privilege operation |
| Credential stuffing | Per-IP and per-account throttles, generic errors, optional shared Redis counters | Risk-based detection and breached-password checking are staged |
| User enumeration | Equivalent public login errors; password-reset requests use the same status, fields, and message for present, absent, disabled, and malformed accounts, with a same-shaped development token; only eligible accounts persist/deliver a digest | Delivery timing and downstream mail-provider behavior still require operational review |
| Password-reset or email-verification token theft/replay | 256-bit random values, 30-minute expiry, realm/type-bound keyed-digest-only storage, one active token per account/type, atomic delete-on-consume, no production request logging | Email account compromise still defeats email-based recovery; development tokens are intentionally disclosed and development mode must never serve production users |
| Account-recovery flooding | Opaque per-source and per-input reset throttles, generic responses, bounded JSON, injected delivery transport, audit events only for eligible accounts | Distributed deployments require Redis-backed counters and sender-side suppression/quotas |
| Password database theft | Argon2id with per-password salt and independent pepper; secrets excluded from logs/backups distributed outside protected storage | Parameter calibration and pepper rotation require an operational review |
| TOTP/recovery theft or replay | TOTP secrets encrypted with AES-256-GCM field key and contextual AAD; recovery codes stored as keyed digests and consumed atomically | TOTP is phishable; encryption-key compromise exposes TOTP seeds |
| Passkey ceremony replay or cross-tenant use | Random expiring challenges are persisted and atomically consumed; exact origin/RP ID, realm/subject credential lookup, opaque realm user handle, user verification, signature, and counter are checked; self-service routes never accept another user ID | Path-based realms share an RP ID; no attestation trust policy or passkey loss-recovery workflow |
| Stale sessions after a security change | Password, profile, disable, and MFA mutations commit with account-state revocation; persisted account artifacts carry a security-version snapshot; grant-linked issuance requires a live parent grant at the same account epoch, closing late code/refresh saves | An interactive authentication already executing across the mutation boundary can still finish afterward; propagating the expected authentication epoch through interaction completion is staged |
| Cross-realm data disclosure | Mandatory realm identifier in repository calls and provider adapter records; compound constraints where possible | PostgreSQL `FORCE ROW LEVEL SECURITY` is staged defense-in-depth |
| SQL injection | Parameterized database access; schema validation; no dynamic SQL from protocol parameters | Static analysis and database-role least privilege |
| XSS and malicious branding content | Context-aware escaping, restrictive CSP, no arbitrary script in realm configuration | Custom themes require a new review before release |
| Clickjacking | `frame-ancestors` CSP and compatible `X-Frame-Options` for interaction pages | Explicit exceptions require per-client security review |
| Proxy certificate-header or host poisoning | Fixed public origin; explicit trusted proxies; never derive issuer from arbitrary request headers; mTLS disabled without a certificate-header setting; certificate headers require an allowlisted socket peer and one forwarded hop; duplicate/malformed headers and certificates fail closed | The proxy must overwrite external certificate/verification/forwarding headers, validate TLS proof of possession and PKI chains as applicable, and isolate the backend; proxy compromise permits mTLS client impersonation |
| Token/credential leakage through logs | Structured redaction; denylist sensitive headers/fields; no request-body logging on protocol endpoints | Log pipeline and support-bundle review |
| Signing-key theft | Keys supplied through protected deployment secrets; restrictive file/process access; public-only JWKS | Envelope encryption and KMS/HSM signing are staged |
| Key rotation outage | Publish retiring public key longer than maximum token lifetime and cache/skew window | Automated rotation is staged |
| PostgreSQL compromise | Least-privilege application role, TLS where networked, network policy, encrypted backups, audit | Database compromise can expose most durable identity state; KMS reduces but does not eliminate impact |
| Redis compromise | Redis holds only bounded, opaque throttling counters; never canonical tokens/sessions | A compromised limiter can affect availability; isolate credentials/network |
| Denial of service | Body/URL/header limits, request timeouts, throttling, bounded DB pool, readiness and load shedding | Multi-region resilience is staged |
| Supply-chain compromise | Exact dependency pin/lockfile, CI audit, provenance/SBOM review, minimal image, Node 22 security updates | Independent dependency monitoring and signed releases |
| Administration-console login or session theft | OIDC Authorization Code with PKCE/state/nonce; production recent LoA2 requirement; opaque `HttpOnly`/`SameSite=Strict` cookie that is `Secure` in production; digest-only durable storage; idle/absolute expiry; account/grant version binding; server-side logout | An active administrator browser and same-origin XSS retain the granted authority; phishing-resistant passkeys are preferred over TOTP |
| Administration cross-realm or permission confusion | Session is pinned to one realm; switching reauthorizes; every console API route fails closed on an explicit realm permission; unsafe calls require exact Origin, JSON, session-bound CSRF, and authentication no more than 15 minutes old; administrator-account mutations additionally require `administrators.manage` | Grant lifecycle has no approval workflow; wildcard bootstrap grants remain broad privilege |
| Account-console session theft or CSRF | Reserved OIDC client with PKCE/state/nonce/recent authentication; realm-path-scoped opaque `HttpOnly`/`SameSite=Strict` cookie; digest-only storage; idle/absolute expiry and account-version binding; exact Origin, JSON, session-derived CSRF, and recent-authentication checks | A same-origin script compromise acts with the user session; password/TOTP authentication remains phishable |
| Account-console confused deputy or cross-user mutation | Router instance is fixed to one realm and no API accepts a target user ID; all profile/credential/session operations derive the subject from the durable session; passkey/session references are searched only in that subject's realm records | Bugs in a newly added repository method can violate this invariant and require negative cross-user/cross-realm tests |
| Configuration-catalog disclosure | Catalog serializes an explicit safe field allowlist and excludes client/bind/upstream/SCIM/root secrets, private JWK members, and deployment keys | Client IDs, issuers, endpoints, topology, and capability metadata remain sensitive operational information |
| Malicious administrator | Durable realm-scoped permission grants, versioned revocation, retained application audit events, and separation of deployment root from console authority | Tamper-evident external export, approval workflows, and organization delegation are staged |
| Root administration bearer theft | High-entropy independent token, constant-time comparison, no browser delivery, log redaction, TLS, separate rotation, and recommended network restriction | Root bearer remains deployment-wide broad privilege and bypasses console grant restrictions |
| Backup leakage | Encrypted backup, isolated credentials, retention and restore policy | Periodic restore and deletion verification |

## Protocol-specific requirements

### Redirects

Production redirect URIs are compared as exact strings. Wildcards, suffix matching, userinfo components, fragments, and open redirector endpoints are prohibited. Loopback exceptions, if introduced for native clients, must follow [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html). RFC 9700 requires exact matching except the native loopback-port exception.

### Authorization Code and PKCE

Public clients must use PKCE. AuthMe's supported method is `S256`; `plain` is not accepted as a production compatibility shortcut. The code is bound to its realm, client, redirect URI, user session, scopes, nonce, and PKCE challenge as applicable. Redemption is one-use and atomic.

### Tokens

Tokens have the shortest lifetime compatible with the application. Claims are
audience- and scope-limited. ID tokens are not treated as API access tokens.
JWT API tokens are issued only for exact configured RFC 8707 resources, carry
`typ: at+jwt`, and expose only the role namespaces/groups enabled for that
audience. Resource servers must verify signature, issuer, audience, algorithm,
time claims, and token purpose; merely decoding a JWT is never authorization.
JWT tokens are validated locally rather than sent to introspection or
revocation. Offline validators may accept them until their short expiration
after an account security change. APIs that require immediate online revocation
or introspection use an explicitly configured opaque-token resource and a
confidential client allowlisted for that audience.

Refresh tokens are not sent to browser front-channel URLs or logged. Revocation and logout behavior is persisted so it works across AuthMe replicas.

### Device, PAR, DPoP, and registration

The device verification page must clearly name the client and requested access before consent. User codes are throttled independently from device polling. Device codes, PAR request URIs, and DPoP replay identifiers live in the durable adapter so multiple replicas enforce the same expiry and one-use rules.

Dynamic client registration accepts only a valid, short-lived initial access token issued through the protected administration API. Distribute it like an administrator credential. Client metadata, especially redirect URIs, authentication methods, JWKS locations, and logout URIs, is validated before persistence. Initial-access-token issuance is audited.

DPoP is a client policy, not a reason to accept an otherwise invalid token. AuthMe validates the proof's key, signature, `htm`, `htu`, `iat`, `jti`, access-token hash where applicable, and nonce behavior through the maintained provider implementation.

### Mutual TLS

RFC 8705 certificate headers cross a deployment trust boundary: an arbitrary
HTTP client can send the same header names unless the edge removes them and the
backend rejects non-proxy peers. The proxy must prove possession of the client
certificate during TLS, forward exactly one leaf certificate, overwrite the
configured certificate and verification headers, and supply a single
`X-Forwarded-For` value. AuthMe additionally checks the socket peer against
`AUTHME_MTLS_TRUSTED_PROXY_CIDRS`; enabling ordinary proxy handling alone is not
enough. PKI `tls_client_auth` accepts the configured success value only after
the proxy validates the chain against limited client trust anchors, while
`self_signed_tls_client_auth` pins the leaf certificate to client `x5c`
metadata. Resource servers remain responsible for matching
`cnf["x5t#S256"]` to the certificate on their own mTLS connection.

### TOTP and recovery codes

TOTP enrollment requires an already authenticated interaction and confirmation with a valid generated code. Secrets are encrypted at rest with the field-encryption key. Recovery codes are displayed once, stored only as keyed digests, and consumed atomically under a row lock. Neither TOTP nor recovery codes are phishing-resistant according to [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/).

### Passkeys

Passkey registration requires the root-protected administration ceremony and runs only for an existing realm user. Credentials are discoverable and require authenticator user verification. The verifier matches the exact challenge, `webauthn.create`/`webauthn.get` type, configured origin, RP ID hash, signature, user handle, and stored credential counter. A failed attempt consumes its challenge. Credential registration/deletion is audited in the same account-security transaction and invalidates existing account state. Registration requests use no attestation, so AAGUID and device/backup fields are operational metadata rather than proof of authenticator make, hardware protection, or enterprise provenance.

### LDAP and federation

LDAP, OIDC, and SAML provider configuration is trusted operator input but is still schema-validated and frozen at startup. Provider IDs and canonical issuers are identity-security keys and must not be repurposed. JIT is disabled unless explicitly enabled. Upstream authentication results cannot select an arbitrary issuer or account: the server resolves the exact configured provider and immutable subject, and collisions require an explicit administrator link.

Federation initiation is a POST protected by a provider- and interaction-bound CSRF token. Callback state and SAML RelayState are one-use. Successful upstream validation creates only a short-lived opaque same-origin completion handle; no SAML assertion, upstream token, or profile is put in the completion URL. Exact callback/ACS endpoints must be registered at the upstream authority.

SAML IdP registrations are separate, realm-scoped trust records. The request Issuer selects one record only within the URL realm; the request cannot supply a new ACS, SLO target, signing key, encryption key, NameID source, or attribute mapping. XML signatures are checked against the signed root rather than trusting an arbitrary parsed sibling, all XML IDs must be unique, DTD/entity declarations are rejected before parsing, and Redirect signatures are delegated to Node-SAML after an algorithm allowlist. Incoming request IDs, continuation states, outgoing session indexes, and logout requests use the realm adapter's atomic one-use records.

The assertion is signed before optional encryption, and the outer Response is signed afterward. RSA-OAEP and AES-256-GCM are the only emitted encryption profile. Pairwise persistent NameIDs reduce correlation across SPs; email/username NameIDs and every outgoing attribute require explicit operator configuration. The auto-submit page carries only the signed response and bounded RelayState, uses an exact registered form action, nonce-based CSP, no-referrer policy, and no-store caching.

### SCIM

SCIM tokens are root-like provisioning credentials for one realm and must be independently generated, stored in secret management, rotated, and restricted at the network layer. A client must use resource ETags when it needs lost-update protection. Password attributes are accepted only over TLS, immediately hashed, and never serialized. Deactivation, deletion, identity changes, and group membership changes invalidate affected AuthMe account state. A failed audit after a committed SCIM mutation can produce an ambiguous `5xx`; clients must read the resource before retrying.

### Browser sessions and account/administration consoles

Ordinary authentication cookies are `Secure` and `HttpOnly` in production, have an explicit `SameSite` policy and minimal path, and use realm-specific names. Authentication and consent POSTs use interaction-bound CSRF defenses. Sensitive pages use `Cache-Control: no-store`.

The administration console adds a separate trust boundary. Its short-lived login transaction is signed and callback-scoped; the authorization request uses the reserved console client, PKCE `S256`, state, nonce, `max_age`, and requested LoA2. Production admission requires recent MFA/passkey evidence in the verified ID token plus an enabled realm grant. A bootstrap administrator must enroll TOTP through the restricted root API, or establish a reviewed passkey enrollment path, before first production console use.

After callback, the browser receives a random opaque cookie while PostgreSQL stores only its HMAC digest, selected realm, administrator identifier, permission-grant/security version snapshots, and idle/absolute expiry. Every node can validate or revoke the session without affinity. Unsafe authenticated console API calls require exact Origin, JSON content type, and a CSRF value derived from the opaque bearer. Logout deletes the durable row, so replaying a captured pre-logout cookie fails. Console rendering and API responses must not embed `AUTHME_ADMIN_TOKEN`, one-time credentials, or private configuration.

The end-user account console uses a different reserved OIDC client, cookie
namespace, digest domain, database table, and realm path. It accepts the
verified ID-token subject as its only account selector. Profile, password,
TOTP, recovery-code, passkey, and session routes do not accept a user ID or a
realm override. Credential and session references are resolved only after
listing the authenticated subject's realm records. Security mutations advance
the account epoch and revoke provider state; an account-console row carrying
the prior epoch is rejected even if its cookie has not expired.

Password-reset initiation is public but exact-origin, JSON-only, source/input
rate-limited, and response-shape invariant. A random token is generated for
every syntactically bounded request in development so token presence cannot
confirm an account; only an enabled exact-email match is persisted, audited,
and delivered. Confirmation failures use one bounded generic response.
Production uses an injected sender and must prevent its templates, delivery
status, bounce processing, support tooling, and timing from becoming a second
enumeration channel. Email verification is initiated from an authenticated
session but uses the same expiring, single-use, digest-only capability model.

## Abuse-control behavior

Rate limiting is layered:

- coarse per-source limits protect the service;
- client limits protect token and introspection endpoints;
- account-shaped limits slow password guessing without confirming whether the account exists;
- global concurrency and database-pool bounds prevent resource exhaustion.

When Redis is configured, a production deployment must decide explicitly whether Redis failure causes sensitive endpoints to fail closed or fall back to conservative local limits. Silent unlimited fallback is forbidden.

## Security logging

Log:

- timestamp, request/correlation ID, realm ID, event type, outcome, client ID where safe, and coarse source information;
- authentication success/failure, lockout/throttle decisions, grant/revocation/logout, configuration and key changes;
- database/Redis dependency health without credentials.

Never log in production:

- passwords, client secrets, cookies, authorization codes, access/refresh/ID tokens, TOTP seeds, private JWK members, full request bodies on protocol endpoints, or password-reset/email-verification links. Development account delivery deliberately logs one-time links and must use isolated synthetic accounts only.

Audit access is itself privileged and audited. Protocol-event ingestion is bounded and repeated public errors are sampled; overload drops are observable rather than allowed to grow database waiters without limit. Administrative and identity security events are written synchronously. Retention follows `AUTHME_AUDIT_RETENTION_DAYS` and the deployment's privacy and incident-response requirements.

## Required security verification

Before a production release:

1. Run the [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/) against the exact release configuration.
2. Run concurrent replay tests for authorization codes and refresh tokens.
3. Run cross-realm isolation tests for every repository and provider artifact type.
4. Test exact redirect and post-logout URI rejection.
5. Test JWT negative cases: wrong issuer/audience/type/algorithm/key, expired/not-yet-valid, malformed JOSE.
6. Run browser tests for CSRF, exact Origin/media-type enforcement, cookie attributes, CSP, caching, durable session expiry, version invalidation, and logout replay.
7. Run device-code guessing/polling, PAR replay, DPoP proof replay/nonce, and dynamic-registration authorization tests.
8. Test TOTP enrollment/login and concurrent one-use recovery-code consumption.
9. Test root administration for missing, malformed, leaked-in-log, and rotated bearer credentials; separately test OIDC+PKCE console login, production LoA2 admission, realm/permission isolation, safe configuration serialization, and grant revocation.
10. Test account-console OIDC/PKCE login, cross-user and cross-realm mutation attempts, exact Origin/JSON/CSRF enforcement, token expiry/replay, reset response equivalence/throttling, injected-delivery failure, credential changes, and current/remote session revocation.
11. Run dependency, secret, container, and migration scans.
12. Perform backup restoration and signing-key rotation drills.
13. Complete an independent penetration test/security review before claiming production hardening.

Using an OpenID-certified protocol library materially reduces risk, but it does not certify AuthMe's storage adapter, interactions, routes, configuration, deployment, or product as a whole.

## Threat-model maintenance

Update this document in the same change that adds a new credential type, protocol flow, identity provider, administrative surface, storage backend, key backend, or trust boundary. A roadmap item cannot move to implemented until its threats and verification evidence are recorded.
