# AuthMe threat model

## Scope

This threat model covers the AuthMe v0.1 standalone service, its browser interactions, OAuth/OIDC endpoints including device flow, PAR, DPoP, dynamic registration and logout, PostgreSQL adapter, password/TOTP/recovery credentials, optional Redis rate limiter, bearer-protected administration API, and deployment behind a TLS proxy.

It does not claim to cover staged federation, LDAP, SAML, SCIM, WebAuthn/passkeys, KMS/HSM integration, a delegated administrator console, or multi-site operation. Those features require their own threat-model updates before release.

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
- User profile, group, and role data.
- Realm/client configuration, especially redirect URIs and issuer values.
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
```

The browser, OAuth client input, proxy headers, database contents, imported migration data, and administrator-supplied configuration are all treated as untrusted until validated for their use. A private network is not itself a trust control.

## Attacker profiles

- An unauthenticated internet attacker.
- A malicious or compromised registered OAuth client.
- A valid user attacking another user or realm.
- A credential-stuffing or denial-of-service botnet.
- An attacker able to steal a browser token, code, cookie, or refresh token.
- A compromised reverse proxy, application node, dependency, CI runner, or database credential.
- A careless or malicious realm administrator.
- An attacker with access to logs, backups, or metrics.

## Threats and controls

| Threat | v0.1 controls | Residual or staged work |
|---|---|---|
| Redirect URI manipulation or open redirect | Exact registered redirect matching; no wildcard production redirects; validate post-logout redirects | Periodic client-configuration review |
| Authorization-code interception/injection | Authorization Code flow, PKCE `S256`, short-lived one-use codes, client/redirect/PKCE binding; PAR for protected request submission; optional DPoP code/token binding | PAR/DPoP negative and conformance tests remain release gates |
| CSRF/login swapping | Provider-managed transaction state; `state`/`nonce` support; SameSite cookies; CSRF tokens on AuthMe forms | Browser conformance and adversarial tests remain release gates |
| Mix-up between issuers/realms | Immutable per-realm issuer; issuer in discovery and tokens; realm-scoped artifacts; exact issuer validation | Cross-realm fuzz/property tests |
| Authorization-code replay race | PostgreSQL-backed record with atomic consumption and uniqueness | Load testing under concurrent redemption |
| Refresh-token theft/replay | Provider-managed rotation/revocation persisted in PostgreSQL; bounded lifetimes; DPoP binding for configured clients | Explicit family-wide reuse telemetry and mTLS are staged where not already provided by configured provider behavior |
| Access-token replay | TLS, short expiry, audience/scope restriction, DPoP sender constraint for configured clients, persisted replay detection | mTLS certificate-bound tokens are staged |
| JWT algorithm or token-kind confusion | Maintained JOSE stack; configured algorithm allowlist; issuer, audience, type, signature, and time validation | Independent configuration review and negative corpus tests |
| Client impersonation | Confidential-client authentication and protected secret storage; constant-time verification through maintained libraries | `private_key_jwt` and mTLS profiles are staged unless explicitly enabled |
| Session fixation or cookie theft | Regenerate session context after authentication; Secure, HttpOnly, SameSite cookies; no tokens in URLs or local storage | Passkey-based phishing resistance is staged |
| Logout abuse | Validate ID-token hint and exact registered post-logout URI; signed back-channel logout tokens and registered client endpoint policy | Front-channel logout is staged unless explicitly enabled |
| Device-code phishing or user-code guessing | Short-lived high-entropy device codes, rate-limited verification, explicit user confirmation displaying the requesting client | Device-flow conformance and usability review |
| PAR request substitution/replay | Authenticated client policy where required, high-entropy expiring request URI, provider persistence and one-use processing | Concurrent replay and request-binding tests |
| DPoP proof replay/substitution | Provider validation of signature, public-key thumbprint, method, URL, timestamps/nonces and replay identifier persisted in PostgreSQL | Clock-skew, nonce and cluster replay tests |
| Unauthorized dynamic registration | Initial access token required, bounded scope/lifetime/use, strict metadata and redirect validation, audited registration | Initial-access-token issuance remains a high-privilege operation |
| Credential stuffing | Per-IP and per-account throttles, generic errors, optional shared Redis counters | Risk-based detection and breached-password checking are staged |
| User enumeration | Equivalent public errors and response shape for unknown user, wrong password, and locked account | Timing regression tests and email-flow review |
| Password database theft | Argon2id with per-password salt and independent pepper; secrets excluded from logs/backups distributed outside protected storage | Parameter calibration and pepper rotation require an operational review |
| TOTP/recovery theft or replay | TOTP secrets encrypted with AES-256-GCM field key and contextual AAD; recovery codes stored as keyed digests and consumed atomically | TOTP is phishable; WebAuthn is staged; encryption-key compromise exposes TOTP seeds |
| Stale sessions after a security change | Password, profile, disable, and MFA mutations commit with account-state revocation; persisted account artifacts carry a security-version snapshot and stale snapshots fail lookup | An authentication or exchange already executing across the mutation boundary can still finish afterward; propagating the expected parent/authentication epoch through issuance is staged |
| Cross-realm data disclosure | Mandatory realm identifier in repository calls and provider adapter records; compound constraints where possible | PostgreSQL `FORCE ROW LEVEL SECURITY` is staged defense-in-depth |
| SQL injection | Parameterized database access; schema validation; no dynamic SQL from protocol parameters | Static analysis and database-role least privilege |
| XSS and malicious branding content | Context-aware escaping, restrictive CSP, no arbitrary script in realm configuration | Custom themes require a new review before release |
| Clickjacking | `frame-ancestors` CSP and compatible `X-Frame-Options` for interaction pages | Explicit exceptions require per-client security review |
| Proxy-header/host poisoning | Fixed public origin; explicit trusted proxies; never derive issuer from arbitrary request headers | Deployment validation must exercise the real ingress |
| Token/credential leakage through logs | Structured redaction; denylist sensitive headers/fields; no request-body logging on protocol endpoints | Log pipeline and support-bundle review |
| Signing-key theft | Keys supplied through protected deployment secrets; restrictive file/process access; public-only JWKS | Envelope encryption and KMS/HSM signing are staged |
| Key rotation outage | Publish retiring public key longer than maximum token lifetime and cache/skew window | Automated rotation is staged |
| PostgreSQL compromise | Least-privilege application role, TLS where networked, network policy, encrypted backups, audit | Database compromise can expose most durable identity state; KMS reduces but does not eliminate impact |
| Redis compromise | Redis holds only bounded, opaque throttling counters; never canonical tokens/sessions | A compromised limiter can affect availability; isolate credentials/network |
| Denial of service | Body/URL/header limits, request timeouts, throttling, bounded DB pool, readiness and load shedding | Multi-region resilience is staged |
| Supply-chain compromise | Exact dependency pin/lockfile, CI audit, provenance/SBOM review, minimal image, Node 22 security updates | Independent dependency monitoring and signed releases |
| Malicious administrator | Least privilege, retained application audit events, separation of deployment and realm duties | Tamper-evident external export and delegated fine-grained administration are staged |
| Administration bearer theft | High-entropy independent token, constant-time comparison, log redaction, TLS and recommended network restriction | v0.1 token is broad privilege; identity-based delegated admin is staged |
| Backup leakage | Encrypted backup, isolated credentials, retention and restore policy | Periodic restore and deletion verification |

## Protocol-specific requirements

### Redirects

Production redirect URIs are compared as exact strings. Wildcards, suffix matching, userinfo components, fragments, and open redirector endpoints are prohibited. Loopback exceptions, if introduced for native clients, must follow [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html). RFC 9700 requires exact matching except the native loopback-port exception.

### Authorization Code and PKCE

Public clients must use PKCE. AuthMe's supported method is `S256`; `plain` is not accepted as a production compatibility shortcut. The code is bound to its realm, client, redirect URI, user session, scopes, nonce, and PKCE challenge as applicable. Redemption is one-use and atomic.

### Tokens

Tokens have the shortest lifetime compatible with the application. Claims are audience- and scope-limited. ID tokens are not treated as API access tokens. Resource servers must verify signature, issuer, audience, algorithm, time claims, and token purpose; merely decoding a JWT is never authorization.

Refresh tokens are not sent to browser front-channel URLs or logged. Revocation and logout behavior is persisted so it works across AuthMe replicas.

### Device, PAR, DPoP, and registration

The device verification page must clearly name the client and requested access before consent. User codes are throttled independently from device polling. Device codes, PAR request URIs, and DPoP replay identifiers live in the durable adapter so multiple replicas enforce the same expiry and one-use rules.

Dynamic client registration accepts only a valid, short-lived initial access token issued through the protected administration API. Distribute it like an administrator credential. Client metadata, especially redirect URIs, authentication methods, JWKS locations, and logout URIs, is validated before persistence. Initial-access-token issuance is audited.

DPoP is a client policy, not a reason to accept an otherwise invalid token. AuthMe validates the proof's key, signature, `htm`, `htu`, `iat`, `jti`, access-token hash where applicable, and nonce behavior through the maintained provider implementation.

### TOTP and recovery codes

TOTP enrollment requires an already authenticated interaction and confirmation with a valid generated code. Secrets are encrypted at rest with the field-encryption key. Recovery codes are displayed once, stored only as keyed digests, and consumed atomically under a row lock. Neither TOTP nor recovery codes are phishing-resistant according to [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/).

### Browser session

The production cookie is `Secure`, `HttpOnly`, has an explicit `SameSite` policy, a minimal path/domain, and a name that cannot collide across unrelated applications. Authentication and consent POSTs use CSRF defenses. Sensitive pages use `Cache-Control: no-store`.

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

Never log:

- passwords, client secrets, cookies, authorization codes, access/refresh/ID tokens, TOTP seeds, private JWK members, full request bodies on protocol endpoints, or password-reset links.

Audit access is itself privileged and audited. Protocol-event ingestion is bounded and repeated public errors are sampled; overload drops are observable rather than allowed to grow database waiters without limit. Administrative and identity security events are written synchronously. Retention follows `AUTHME_AUDIT_RETENTION_DAYS` and the deployment's privacy and incident-response requirements.

## Required security verification

Before a production release:

1. Run the [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/) against the exact release configuration.
2. Run concurrent replay tests for authorization codes and refresh tokens.
3. Run cross-realm isolation tests for every repository and provider artifact type.
4. Test exact redirect and post-logout URI rejection.
5. Test JWT negative cases: wrong issuer/audience/type/algorithm/key, expired/not-yet-valid, malformed JOSE.
6. Run browser tests for CSRF, cookie attributes, CSP, caching, session rotation, and logout.
7. Run device-code guessing/polling, PAR replay, DPoP proof replay/nonce, and dynamic-registration authorization tests.
8. Test TOTP enrollment/login and concurrent one-use recovery-code consumption.
9. Test the administration API for missing, malformed, leaked-in-log, and rotated bearer credentials.
10. Run dependency, secret, container, and migration scans.
11. Perform backup restoration and signing-key rotation drills.
12. Complete an independent penetration test/security review before claiming production hardening.

Using an OpenID-certified protocol library materially reduces risk, but it does not certify AuthMe's storage adapter, interactions, routes, configuration, deployment, or product as a whole.

## Threat-model maintenance

Update this document in the same change that adds a new credential type, protocol flow, identity provider, administrative surface, storage backend, key backend, or trust boundary. A roadmap item cannot move to implemented until its threats and verification evidence are recorded.
