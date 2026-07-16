# AuthMe architecture

## Status and scope

This document describes the AuthMe v0.3 architecture. In this document:

- **Implemented** means the behavior is part of the v0.3 repository and is expected to be covered by automated tests.
- **Staged** means the architecture reserves a boundary for it, but operators must not depend on it yet.
- **Library capability** means `oidc-provider` can implement the protocol, but AuthMe has not necessarily enabled, configured, tested, or certified it.

AuthMe is a standalone, multi-realm OpenID Provider for Node.js 22. It uses [`oidc-provider` 9.9.1](https://oidc-provider.dev/changelog/#_9-9-1-2026-07-07) for standards-sensitive OAuth 2.0 and OpenID Connect behavior rather than implementing those protocols independently. The upstream project is OpenID and FAPI certified and documents its supported specifications in its [official repository](https://github.com/panva/node-oidc-provider#implemented-specs--features). AuthMe still owns its configuration, interaction UI, storage adapter, tenant isolation, operational controls, and conformance testing.

v0.3 is a secure identity foundation with downstream OAuth/OIDC and SAML IdP operation, upstream OIDC and SAML federation, LDAP/AD authentication and synchronization, SCIM provisioning, password/TOTP/passkey credentials, a realm-scoped end-user account console, and a realm-scoped administration console. It is not yet a complete replacement for every Keycloak feature. The exact boundary is documented in [keycloak-compatibility.md](keycloak-compatibility.md), [federation-and-provisioning.md](federation-and-provisioning.md), and [roadmap.md](roadmap.md).

## Design goals

1. Preserve standard OIDC behavior and Keycloak-compatible public URLs for ordinary OIDC clients.
2. Isolate realms at the issuer, application, and data layers.
3. Keep every protocol artifact required for correctness in PostgreSQL.
4. Run as a single deployable service before introducing distributed-system complexity.
5. Scale horizontally without relying on process memory for sessions, grants, codes, or tokens.
6. Make unsafe production configuration fail at startup.
7. Keep optional infrastructure, such as Redis, outside the correctness path.

## Explicit non-goals for v0.3

v0.3 does not claim Kerberos/SPNEGO, RADIUS, X.509 login, SAML artifact binding, encrypted assertions at the upstream-SP broker, POST/SOAP or multi-party SAML logout, LDAP server-side change-log controls, configurable authentication flows, Keycloak Admin REST compatibility, complete mutable realm/client/group/role administration, generalized required actions/self-registration, passkey loss recovery, WebAuthn attestation assurance, imported U2F credentials, UMA authorization services, multi-site active/active operation, or OpenID certification of the AuthMe product. These are staged capabilities.

## Runtime topology

```text
                    +----------------------+
                    | TLS proxy / ingress  |
                    +----------+-----------+
                               |
              +----------------+----------------+
              |                                 |
     +--------v---------+              +--------v---------+
     | AuthMe Node 22   |              | AuthMe Node 22   |
     | realm facade     |              | realm facade     |
     | oidc-provider    |              | oidc-provider    |
     | interactions     |              | interactions     |
     +--------+---------+              +--------+---------+
              |                                 |
              +----------------+----------------+
                               |
                     +---------v----------+
                     | PostgreSQL         |
                     | canonical state    |
                     +--------------------+

          optional: Redis for shared rate-limit counters only
```

The application is a modular monolith. Protocol handling, interactions, realm resolution, persistence, and operational endpoints live in one deployable unit, while their internal interfaces remain separate. This keeps authorization-code redemption, refresh-token behavior, grant changes, and audit writes close to one transactional system.

## Request lifecycle

1. A trusted proxy terminates TLS and forwards a request to AuthMe.
2. The HTTP edge validates the host/proxy context and extracts the realm slug from the path.
3. Realm resolution loads an enabled realm and constructs its immutable issuer.
4. AuthMe dispatches the request to the `oidc-provider` instance/configuration for that realm.
5. Interactive requests use AuthMe-owned login and consent interactions.
6. `oidc-provider` reads and writes protocol artifacts through the PostgreSQL adapter.
7. AuthMe emits structured operational and security events with secrets removed.

No authorization decision may be made from an untrusted `Host`, `Forwarded`, or `X-Forwarded-*` value. Production deployments must configure a fixed public origin and an explicit trusted-proxy policy.

## Realm model and issuer contract

A realm is AuthMe's top-level security boundary. Users, clients, grants, signing configuration, role assignments, sessions, and protocol artifacts belong to exactly one realm.

The public issuer is:

```text
https://auth.example.com/realms/{realm}
```

Realm slugs are URL-safe, unique, and immutable after exposure. Renaming a realm changes its issuer and therefore breaks token validation and relying-party configuration. Create a replacement realm instead of renaming an issuer in place.

The v0.3 compatibility facade exposes these Keycloak-shaped paths:

```text
/realms/{realm}/.well-known/openid-configuration
/realms/{realm}/protocol/openid-connect/auth
/realms/{realm}/protocol/openid-connect/token
/realms/{realm}/protocol/openid-connect/userinfo
/realms/{realm}/protocol/openid-connect/certs
/realms/{realm}/protocol/openid-connect/logout
/realms/{realm}/protocol/openid-connect/revoke
/realms/{realm}/protocol/openid-connect/token/introspect
/realms/{realm}/protocol/openid-connect/auth/device
/realms/{realm}/device
/realms/{realm}/protocol/openid-connect/ext/par/request
/realms/{realm}/protocol/openid-connect/ext/ciba/auth
/realms/{realm}/clients-registrations/openid-connect
/realms/{realm}/account/
```

The route facade translates public paths to the provider without changing the advertised issuer. The issuer in discovery, ID tokens, access tokens, authorization responses, and introspection data must be identical. OAuth authorization-server metadata and issuer matching are defined by [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html); Keycloak's endpoint surface is documented in its [OIDC endpoint guide](https://www.keycloak.org/securing-apps/oidc-layers).

Every repository operation is realm-scoped. Compound uniqueness and foreign-key constraints must include the realm identifier where they can prevent a cross-realm reference. PostgreSQL row-level security is a planned defense-in-depth layer, not a substitute for explicit realm predicates. PostgreSQL notes that table owners normally bypass RLS unless it is forced and that referential-integrity checks bypass it; see the [PostgreSQL row-security documentation](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

## Protocol engine

AuthMe pins `oidc-provider` to 9.9.1. It does not fork protocol code. The pin is updated only through a reviewed dependency change with protocol, migration, and conformance tests.

The supported v0.3 profile is deliberately smaller than the upstream library's capability surface:

- OpenID Provider discovery and JWKS publication.
- OAuth Authorization Server metadata at the RFC 8414 path for realm issuers.
- Authorization Code flow.
- PKCE using `S256`.
- Refresh tokens where allowed by client policy.
- Client Credentials for service clients.
- UserInfo, with optional realm-key-signed JWT responses per client.
- Token introspection, with optional realm-key-signed JWT responses for authorized resource clients, and revocation.
- RP-initiated logout.
- Back-channel logout.
- Device Authorization Grant.
- OpenID CIBA Core in poll mode.
- Pushed Authorization Requests (PAR).
- DPoP-bound access tokens.
- Mutual-TLS PKI and self-signed client authentication, with optional certificate-bound access tokens.
- Dynamic client registration protected by an initial access token.
- RFC 8707 resource indicators for explicitly configured API audiences, with JWT or opaque access-token policy per audience.

Advanced endpoints are consumed from discovery metadata; clients must not guess their paths. [Dynamic registration](https://www.rfc-editor.org/rfc/rfc7591.html) requires a short-lived initial access token issued through the AuthMe administration API and is not an anonymous client-creation API. DPoP clients create a proof for the intended method and URL and handle provider nonce responses where required. PAR request URIs and device/user codes are short-lived provider artifacts persisted through the PostgreSQL adapter.

The client-authentication allowlist is `client_secret_basic`,
`private_key_jwt`, `client_secret_jwt`, `none`, `tls_client_auth`, and
`self_signed_tls_client_auth`. The two mTLS methods are advertised only when
the deployment enables the trusted certificate-header boundary. The JWT assertion methods
follow [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) at the token,
introspection, and revocation endpoints. Private-key assertions allow only
RS256, PS256, or ES256; shared-secret assertions allow only HS256. Assertions
must use the exact realm issuer, token endpoint, or (for CIBA initiation) the
backchannel authentication endpoint as a single audience and carry
an expiring, one-use `jti` persisted through the realm adapter. A
`private_key_jwt` client can register an inline public `jwks` or an HTTPS
`jwks_uri`; inline keys avoid a runtime network dependency, while remote key
retrieval is size-bounded, rejects redirects, and fails closed without the
provider's socket-level SSRF protection. The provider advertises public and
pairwise subject types. Pairwise identifiers are realm- and sector-bound HMAC
values derived with `AUTHME_SUBJECT_SALT`.

### Resource indicators and API policy

AuthMe implements [Resource Indicators for OAuth 2.0 (RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707.html)
for configured API audiences. `AUTHME_RESOURCE_SERVERS_JSON` defines each
resource's exact audience, scopes, access-token format, claim policy, and
`authorized_client_ids`. Those entries form the authoritative per-client
resource allowlist. A client can request multiple distinct resources in one
authorization request only when every member also lists that client in
`multi_resource_client_ids`; omission denies all multi-resource combinations.
Unknown resources, unauthorized resources, and disallowed combinations fail
with `invalid_target`.

AuthMe does not invent a default audience when the client omits `resource`.
When a grant contains exactly one configured resource, `useGrantedResource`
allows the token request to omit it and the sole granted resource is used. A
grant covering an allowed multi-resource request requires the token request to
select one of those granted resources; AuthMe does not choose among them. Each
resulting access token therefore has exactly one selected audience, and its
scope is the intersection of requested, granted, and resource-server scopes.
Scopes belonging only to another resource are not copied into the token.

### Client-Initiated Backchannel Authentication

AuthMe v0.4 implements [OpenID CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) for confidential clients in poll mode. A CIBA client registers the `urn:openid:params:grant-type:ciba` grant, `backchannel_token_delivery_mode: poll`, and a non-`none` token endpoint authentication method. The backchannel authentication endpoint accepts the same confidential client authentication methods as the token endpoint, including `private_key_jwt`. Ping and push delivery are outside this release.

Plain `login_hint` values resolve only inside the issuer realm through the canonical, uniqueness-constrained username/email namespace. Unknown, disabled, locked, malformed, and unsupported token hints fail with bounded generic protocol errors that do not echo the hint. Signed CIBA Request Objects require an expiring one-use `jti`. The resulting high-entropy `auth_req_id` is stored as a realm- and account-bound `BackchannelAuthenticationRequest`; disabled accounts, security-version changes, expiry, client mismatch, and cross-realm lookup invalidate it.

The provider persists the request before invoking the authentication-device hook. A trusted integration registers one handler through `authmeCiba.setAuthenticationDeviceHandler`; the handler receives only the realm, request/account/client identifiers, binding message, expiry, and requested scopes, then dispatches through the deployment's authentication-device channel. Production never auto-approves: after authenticating the user and obtaining authorization, the integration calls `authmeCiba.complete` with the account, decision, ACR, AMR, and authentication time. Development mode exposes `authmeCiba.approveForDevelopment` for deterministic integration tests; that helper is rejected outside development mode.

Poll acknowledgements advertise a minimum interval. Each token poll atomically advances a PostgreSQL-backed per-request deadline; an early or overlapping request returns `slow_down` and increases the interval, while a timely incomplete request returns `authorization_pending`. Approval is a one-way compare-and-update transition, and successful redemption consumes the request once. PostgreSQL therefore enforces the same behavior across replicas; the memory adapter mirrors it only for development and tests.

An ordinary OIDC access token without a `resource` audience remains opaque and
is usable at UserInfo. A configured resource produces an audience-bound token
in that resource's declared format. JWT resource tokens use `typ: at+jwt` and
are validated locally using the realm JWKS, issuer, audience, signature, and
time claims. The upstream provider intentionally rejects JWTs at introspection
and revocation; configured opaque resource tokens can instead be introspected
by confidential clients explicitly listed for that audience and checked online
for security-state changes. Offline JWT validators accept a token until its
short expiration unless they operate a denylist.

### Mutual TLS

AuthMe v0.4 implements [OAuth 2.0 mutual-TLS client authentication and
certificate-bound access tokens (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705.html)
behind a TLS-terminating reverse proxy. `tls_client_auth` uses one registered
subject DN or SAN and requires the proxy's configured certificate-chain
verification result. `self_signed_tls_client_auth` compares the forwarded leaf
certificate thumbprint with an `x5c` certificate in the client's public `jwks`
or constrained `jwks_uri`. A client opts into certificate-bound tokens with
`tls_client_certificate_bound_access_tokens: true`; resulting access tokens
carry the DER certificate's base64url SHA-256 thumbprint as
`cnf["x5t#S256"]`, and opaque-token introspection returns the same confirmation
value. Resource servers must compare it with the certificate used on their own
mutually authenticated TLS connection.

mTLS is disabled unless `AUTHME_MTLS_CLIENT_CERT_HEADER` is set. Enabling it
also requires `AUTHME_TRUST_PROXY=true` and one or more exact source ranges in
`AUTHME_MTLS_TRUSTED_PROXY_CIDRS`. AuthMe accepts the certificate header only
when the socket peer is in that allowlist and the request contains exactly one
valid `X-Forwarded-For` address. The certificate header may contain PEM directly
or percent-encoded PEM. `AUTHME_MTLS_CLIENT_CERT_VERIFIED_HEADER` and
`AUTHME_MTLS_CLIENT_CERT_VERIFIED_VALUE` default to `x-ssl-client-verify` and
`SUCCESS`; the PKI method requires that exact result.

The proxy is part of the mTLS security boundary. It must remove externally
supplied certificate, verification-status, and forwarding headers; request and
validate the client's TLS `CertificateVerify`; inject only the leaf
certificate; and reach AuthMe from an allowlisted source address over an
isolated or authenticated backend channel. For PKI clients it must validate the
chain against the deployment's deliberately limited client CA set before
emitting the success value. The backend must not be directly reachable by
untrusted clients. A compromised proxy can impersonate any mTLS client.

### JWT-Secured Authorization Requests

AuthMe v0.4 supports signed [JWT-Secured Authorization Requests (JAR, RFC 9101)](https://www.rfc-editor.org/rfc/rfc9101.html) through the authorization endpoint's `request` parameter. Clients register `request_object_signing_alg` as `RS256`, `PS256`, or `ES256` and provide verification keys through public inline `jwks` metadata; inline private and symmetric key material is rejected. A client can set `require_signed_request_object` to prevent downgrade to a plain authorization request. Server-wide mandatory JAR remains off so clients that have not opted into JAR continue to use ordinary Authorization Code requests.

AuthMe does not retrieve client-hosted `request_uri` values. Discovery advertises `request_uri_parameter_supported` as false, avoiding a new outbound-fetch and SSRF surface; provider-issued, short-lived PAR request URNs remain supported through the implemented PAR endpoint. Whether parameters arrive in a signed Request Object or a plain request, PKCE `S256`, client binding, scope validation, and registered redirect URI validation run in the same authorization pipeline.

### JWT-secured UserInfo and introspection responses

AuthMe v0.4 supports signed JWT response opt-in without changing the endpoints or the default JSON response format. A client that registers `userinfo_signed_response_alg: RS256` receives UserInfo as `application/jwt`; the JWT contains `sub`, is issued to that client ID, and is signed with the realm's private provider key. This follows the signed UserInfo response defined by [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfoResponse) and the `userinfo_signed_response_alg` metadata defined by [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0-errata2.html#ClientMetadata). Clients without that metadata continue to receive `application/json`.

An authorized resource client that registers `introspection_signed_response_alg: RS256` can request `Accept: application/token-introspection+jwt`. AuthMe then returns the [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701.html) response: a realm-signed JWT with `typ: token-introspection+jwt`, the caller's client ID as audience, and the RFC 7662 result under `token_introspection`. Requests that do not negotiate that media type continue to receive JSON. Enabling the response format does not change introspection authorization: the existing issuing-client and configured `introspection_client_ids` audience policy still runs before token data is disclosed, and an unauthorized caller receives only an inactive result.

Only asymmetric algorithms backed by the realm's validated private JWKS are advertised and accepted; `none` is rejected as client metadata. The public JWKS endpoint never returns private parameters. Consumers validate the signature against that realm's JWKS and require the exact issuer, their own client ID as audience, and the expected response type before using claims. Response signing provides integrity and origin authentication; TLS, bearer-token protection, scope/claim filtering, and introspection caller authorization remain mandatory.

Implicit flow, Resource Owner Password Credentials, and CIBA ping/push delivery are not part of the v0.3 product contract unless a release explicitly enables and tests them. The OAuth Security Best Current Practice requires authorization servers to support PKCE, requires it for public clients, recommends it for confidential clients, and requires exact redirect URI matching; see [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html). PAR is defined by [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html), DPoP by [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), and Device Authorization by [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html).

### JWT Secured Authorization Response Mode

AuthMe v0.4 supports [JWT Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html). A client can request `jwt`, `query.jwt`, `fragment.jwt`, or `form_post.jwt`; the authorization endpoint returns the response parameters inside a `response` JWT signed by the realm's provider key. The client's optional `authorization_signed_response_alg` defaults to `RS256` and must be an asymmetric algorithm advertised by the realm; `none` is neither advertised nor accepted. Existing non-JWT response modes remain available.

Clients validate the JARM signature against the realm JWKS and require the exact issuer, their own client ID as audience, and a valid expiration before consuming `code`, `state`, or error claims. JARM protects authorization-response integrity; it does not replace PKCE, exact redirect URI validation, state handling, or TLS.

### FAPI 2.0 Security Profile

AuthMe v0.4 composes its existing protocol controls into an opt-in
[FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0.html)
authorization-code policy. A static or dynamically registered client selects it
with `fapi_profile: "2.0"`; omission is the safe default and leaves the client on
the ordinary AuthMe policy. The marker is AuthMe client metadata, not a claim
that the client or deployment is certified. AuthMe currently rejects the marker
when the client enables grants other than `authorization_code`; FAPI CIBA,
client-credentials, and refresh-grant profiles are outside this composed policy.

For a marked client, startup or registration fails unless the client uses
`private_key_jwt`, `tls_client_auth`, or `self_signed_tls_client_auth` and
requires exactly one access-token sender constraint:
`dpop_bound_access_tokens: true` or
`tls_client_certificate_bound_access_tokens: true`. The mTLS choice additionally
requires the trusted proxy certificate boundary. Shared-secret and public-client
authentication are rejected. FAPI `private_key_jwt` assertions use PS256 or
ES256 and accept only the exact realm issuer as the string `aud` value.

Marked authorization flows require client-authenticated PAR, PKCE `S256`, an
explicit redirect URI, a PS256/ES256 signed Request Object at PAR, and
`response_mode=jwt`. Both successful and error authorization responses are
PS256/ES256 JARM responses. AuthMe forces the per-client PAR and signed-Request-
Object metadata flags, limits authorization codes to 60 seconds, and relies on
the provider's durable replay and code-consumption controls. The JAR/JARM
requirements are the authorization-request and authorization-response portions
of the [FAPI 2.0 Message Signing Final specification](https://openid.net/specs/fapi-message-signing-2_0-final.html), layered on the Security Profile. A realm serving marked clients must provision a compatible PS256 or ES256 signing key in addition to any key needed by ordinary clients; missing key or client metadata fails provider startup.

Discovery advertises the shared server capabilities—PAR, `S256`, Request Object
algorithms, JARM response modes and algorithms, DPoP, and the enabled client
authentication methods. It deliberately does not advertise
`require_pushed_authorization_requests: true` globally because that would change
non-FAPI clients; the mandatory policy is stored and enforced on each marked
client. Non-FAPI client metadata, authorization response modes, authentication,
and token behavior are unchanged.

The applicable OpenID Foundation authorization-server conformance plans are
FAPI2SP OP private key + DPoP, FAPI2SP OP private key + MTLS, FAPI2SP OP MTLS +
DPoP, and FAPI2SP OP MTLS + MTLS for the combinations a deployment enables,
plus FAPI2SP OP OpenID Connect. Because AuthMe also requires the Message Signing
extensions, FAPI2MS OP JAR and FAPI2MS OP JARM apply. The Foundation publishes
these as separate [FAPI 2.0 OP Security Profile Final and Message Signing Final
profiles](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/).
FAPI-CIBA and client-credentials plans do not apply to this authorization-code
policy.

AuthMe makes **no FAPI or OpenID certification claim**. Certification requires
the applicable plans to pass against the exact AuthMe build, routes,
configuration, keys, proxy, storage adapter, and deployed security boundary,
followed by the Foundation's certification process. Upstream `oidc-provider`
certification does not transfer to AuthMe or to an AuthMe deployment.

## Persistence

PostgreSQL is the canonical store for AuthMe configuration and for all `oidc-provider` artifacts that affect protocol correctness. The durable adapter stores, as applicable:

- sessions and interactions;
- authorization codes;
- access and refresh tokens;
- grants and consents;
- replay-detection records;
- device codes, CIBA backchannel authentication requests and poll state, pushed authorization requests, DPoP replay records, and dynamic-registration artifacts;
- client and user data;
- realm-scoped administrator grants plus opaque administration- and account-console sessions;
- expiring keyed-digest account action tokens for email verification and password reset;
- realm configuration and signing material metadata;
- audit and operational events.

Adapter records carry a realm discriminator in addition to the upstream model identifier. Expiration is enforced on reads and by periodic cleanup. One-use values must be consumed atomically; a read followed by an unrelated delete is not sufficient under concurrency. PostgreSQL row locks, uniqueness constraints, or compare-and-update statements provide the serialization point. PostgreSQL documents its transaction and locking semantics in [Transaction Isolation](https://www.postgresql.org/docs/current/transaction-iso.html) and [Explicit Locking](https://www.postgresql.org/docs/current/explicit-locking.html).

Process memory may cache non-sensitive, reconstructable configuration for bounded periods, but it is never the only store for sessions, authorization codes, refresh tokens, grants, or revocation state.

## Redis boundary

Redis is optional and is used only for shared rate-limit counters in v0.3. It is not the source of truth for users, clients, sessions, grants, tokens, or signing keys.

- Without Redis, a single-node deployment uses local rate limiting.
- A multi-node production deployment should configure Redis so limits are enforced across replicas.
- Redis failure must not silently disable all abuse controls. The configured failure policy must be observable and documented for the deployment.
- Rate-limit keys contain opaque realm/subject buckets, not passwords, tokens, email addresses, or raw IP/user combinations that unnecessarily expose personal data.

## Identity and claims

AuthMe owns the account lookup used by `oidc-provider`. A subject identifier is stable within its realm and must not be recycled. Client-visible identity claims are minimized to the scopes and mappers allowed for that client.

Passwords are hashed with Argon2id plus an independent deployment pepper. v0.3 also implements [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)-compatible TOTP as a second factor and one-use recovery codes. TOTP secrets are protected with the field-encryption key and realm/user-bound context; recovery codes are shown once and stored as keyed digests. TOTP is not phishing-resistant.

Fresh passkey registration and passwordless interaction login use the maintained `@simplewebauthn/server` verifier. AuthMe requires discoverable credentials and authenticator user verification, derives non-identifying realm-scoped user handles, checks the exact configured origin and RP hostname, persists credential public keys/counters/transports, and atomically consumes short-lived server-side challenges. Registration requests use `attestation: none`; stored AAGUID/device metadata is descriptive and is not an attestation trust decision. Because realms share one path-based origin, the browser RP ID is common while database credentials, user handles, and challenges remain realm-scoped.

## Identity extensions, federation, and provisioning

Trusted built-in identity modules register through the versioned `authme.identity/v1` contract. An extension declares an `authenticator`, `federation`, or `provisioning` kind plus stable capabilities; the realm registry exposes only enabled entries. This isolates protocol code while keeping extensions compile-time reviewed and deployed with AuthMe. Arbitrary runtime plugin loading is deliberately not part of the trust model.

LDAP/AD authentication uses an exact realm provider configuration, escaped and bounded directory search, a distinct user bind, TLS certificate validation, and an immutable directory subject. Its batch synchronizer uses the same realm/provider boundary and mappings, streams RFC 2696 pages, and uses the configured immutable attribute as the federated external subject. Each entry is created or updated in its own transaction. A completed run stamps its observed links with a run UUID, then scans unstamped links in bounded batches and disables or deletes their users according to provider policy. An interrupted search retains completed entry mutations for an idempotent retry but never starts missing-entry reconciliation. Provider-scoped advisory locks reject overlapping PostgreSQL runs.

Directory synchronization does not auto-link username or email collisions. A rename updates the already-linked user through the immutable subject; a conflicting rename preserves the existing link and local login values while reporting a conflict. Group memberships are managed from the configured multivalued attribute only when `sync_groups` is enabled, and roles are directory-managed only when `roles_attribute` is configured. The sync marker is durable in `federated_identities`; links created after a run starts are excluded from that run's deletion sweep.

OIDC federation uses Authorization Code + PKCE with provider-bound one-use state and nonce, fixed endpoints, strict issuer/signature/audience/subject validation, and no redirect following. SAML federation publishes provider-specific SP metadata/ACS endpoints, binds RelayState to the active OIDC interaction, requires signed Response and Assertion validation, and persists response/assertion replay keys through the realm adapter.

The SAML IdP is a separate realm protocol surface at `/realms/{realm}/protocol/saml`. Each enabled realm owns its entity ID, signing key/certificate set, SP registrations, replay namespace, and metadata. A validated AuthnRequest is converted into an authorization request for the reserved `authme-saml-idp` client; the normal AuthMe login, MFA, passkey, federation, and browser-session interaction completes it. The internal authorization code is accepted only with the pending SAML state's exact issuer, client, redirect, nonce, and PKCE challenge, then consumed without exposing a token to the browser. The IdP signs both the Assertion and Response, optionally encrypts the signed Assertion to the registered SP certificate, and posts only to an exact registered ACS. Redirect SLO is correlated to an issued SAML session and passes through the existing AuthMe session-logout implementation.

All external identities resolve through the `federated_identities` repository by realm, provider ID, canonical issuer, and upstream subject. Username/email collisions fail closed and require an explicit administration link. JIT account creation is provider opt-in. Upstream callback completion is converted to a short-lived, one-use same-origin handle before finishing the downstream OIDC interaction, so upstream assertions or tokens never enter an AuthMe front-channel URL.

SCIM is a realm-scoped PostgreSQL provisioning surface under `/scim/v2/realms/{realm}`. Its Users and Groups map to the canonical identity tables, use optimistic ETag comparison, synchronize membership, and advance account security/revoke current state on identity changes. Discovery and core `eq` filtering are implemented; Bulk, sorting, arbitrary extension schemas, and the full filter grammar are outside this release. Configuration and endpoint details are in [federation-and-provisioning.md](federation-and-provisioning.md).

For migration compatibility, v0.3 can emit Keycloak-shaped authorization claims:

```json
{
  "realm_access": {
    "roles": ["member"]
  },
  "resource_access": {
    "orders-api": {
      "roles": ["orders.read"]
    }
  },
  "groups": ["/engineering/platform"]
}
```

Realm roles and client roles use separate namespaces. Resource-token claim
emission requires both a granted `roles` or `groups` scope and the audience's
explicit claim policy. `resource_access` is filtered to the configured role
client IDs for that audience, so unrelated client assignments are not leaked.
Possession of a role in the database does not imply that every token receives
it. Composite roles and configurable protocol mappers are staged.

## End-user account console

Each realm exposes an account console at `/realms/{realm}/account/`. It is a
separate relying party identified by the reserved `authme-account-console`
client. The console starts the realm's ordinary AuthMe interaction rather than
copying password, federation, MFA, or passkey authentication logic. Its
Authorization Code request uses PKCE `S256`, exact redirect matching, `state`,
`nonce`, and `max_age`; the server exchanges the code and validates the ID
token before binding the verified `sub` to an account-console session.

The browser receives a realm-path-scoped random opaque cookie. PostgreSQL
stores only a domain-separated HMAC digest, the realm/account identifiers,
authentication methods, account security-version snapshot, source metadata,
and idle/absolute expiry. The session is unusable if the account is disabled,
the realm differs, its expiry passes, or a credential/security mutation
advances the account version. Unsafe account APIs accept JSON only and require
the exact configured Origin, a session-derived CSRF value, and authentication
no more than 15 minutes old. Routes never accept a target user identifier:
profile, credential, and session repositories are called only with the
authenticated realm and subject. Passkey and session identifiers are resolved
only within that subject's records; public session references are keyed
digests rather than provider session IDs.

Safe profile fields can be updated directly. A requested email is not assigned
until its one-use verification capability is consumed. Email-verification and
password-reset values contain 256 bits of randomness, expire after 30 minutes,
and are stored only as realm/type-bound keyed digests. Issuing a new token
replaces the previous token of that type for the account. Production mail is a
pluggable injected sender; AuthMe does not embed SMTP or another transport.
Development mode deliberately logs and returns test capabilities. Forgot-
password responses retain the same status, fields, and message for present,
absent, disabled, and malformed account names; the development response also
returns a same-shaped random token for nonexistent accounts, but only an
eligible account's digest is stored or delivered. Per-source and opaque
per-input rate limits bound request and confirmation abuse.

Current-password changes use the existing Argon2id verifier and compare-and-
set update. TOTP uses the existing encrypted enrollment/confirmation flow;
recovery codes are regenerated as one-time disclosures and stored only as
keyed digests. Passkeys reuse the realm WebAuthn policy and durable,
atomically-consumed challenges. Security changes and their audit record run in
the account-security mutation boundary, advance the security version, and
revoke OIDC account artifacts. The console lists only the subject's live OIDC
and account-console sessions. Revoking an OIDC session also removes grants and
grant-linked artifacts associated with that provider session; revoking the
current account-console session clears its cookie.

## Administration and audit

v0.3 has two deliberately separate administration credentials. Non-browser automation uses the independent, deployment-wide `AUTHME_ADMIN_TOKEN`, which remains root-equivalent for the operator API. The browser console at `/admin/` never receives that token. It authenticates through the reserved `authme-admin-console` OIDC client using Authorization Code, PKCE `S256`, state, nonce, and an exact same-origin callback.

An OIDC identity is not sufficient by itself: the user must have an enabled durable administrator grant in the selected realm. Grants carry an explicit permission set and a monotonically increasing version. Production console admission also requires a recent LoA2 result—a passkey or password plus TOTP/recovery—while development mode permits password-only testing. Realm switching runs a new authorization rather than widening an existing session.

The console cookie is a random opaque bearer scoped to `/admin`; only its HMAC digest is stored in PostgreSQL. Its durable record has idle and absolute expiry plus snapshots of the user security version and administrator-grant version. Nodes can therefore authenticate and revoke console sessions without process affinity. Logout deletes the durable record, and account/grant changes make stale records unusable. Unsafe cookie-authenticated calls require the exact public Origin, JSON content type, a session-bound CSRF header, the session realm, the operation's grant permission, and authentication no more than 15 minutes old. Mutating an account that has an administrator grant additionally requires `administrators.manage`.

The console and root bearer share the audited service operations below `/admin/v1`, but root automation is not silently converted into a browser session. The read-only realm configuration catalog returns only explicitly selected client, resource-server, federation, SCIM identifier, extension, storage, and TTL fields; it excludes credentials, tokens, private keys, and deployment secrets. Client configuration remains primarily deployment-owned, and grant CRUD/approvals, complete client/group/role policy editing, and organization delegation are staged.

Administrative mutations synchronously write realm-scoped JSON audit records. Account-security changes, session revocation, and deletion commit their audit with the PostgreSQL mutation; user creation, unlock, and TOTP-enrollment start currently audit immediately after mutation, so an audit-storage failure can produce an ambiguous `5xx` that operators must reconcile. High-volume protocol events use a bounded, sampled writer so unauthenticated traffic cannot create an unbounded database waiter queue; dropped/sampled/write-failure outcomes are metrics. PostgreSQL retention cleanup removes audit rows older than the configured window.

## Cryptographic boundary

AuthMe delegates JOSE processing to the provider and its maintained dependencies. It does not implement signing algorithms. JWT validation and production configuration follow [JWT Best Current Practices, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html), including algorithm allowlists, mutually exclusive validation rules for different JWT kinds, and full issuer/audience/type/time validation.

Each realm has its own logical signing keyring. Production private keys must be supplied from protected secret storage or an envelope-encrypted database representation, never committed to the repository. Rotation uses three states:

1. **Active**: signs newly issued tokens.
2. **Retiring**: remains in JWKS for verification but does not sign new tokens.
3. **Removed**: deleted only after every token it could have signed has expired, including clock skew and caches.

KMS/HSM-backed signing and automated rotation are staged. v0.3 operators are responsible for controlled key injection and rotation.

## Internal boundaries

The source tree is organized around these responsibilities:

- **configuration**: parse, validate, and freeze startup configuration;
- **realm resolution**: resolve path to enabled realm and issuer;
- **provider factory**: create/cache realm-specific `oidc-provider` instances;
- **adapter**: map provider models to durable PostgreSQL records;
- **repositories**: realm, client, user, role, and group persistence;
- **interactions/UI**: authentication, consent, and user-facing error pages;
- **account console**: subject-bound OIDC login, profile/credential actions, verified recovery tokens, and self-service session revocation;
- **administration**: OIDC console login, durable realm grants/sessions, permission checks, safe configuration views, and the root automation API;
- **routes**: compatibility paths plus health and operational endpoints;
- **crypto**: key loading and secret handling, never custom primitives;
- **observability**: structured logs, metrics, correlation, and redaction.

Protocol routes do not query tables directly. They use provider/application interfaces so storage and tenant checks remain centralized.

## Availability and consistency

AuthMe nodes are intended to be stateless between requests. PostgreSQL availability determines authentication availability. Redis availability affects shared throttling, not durable identity state.

v0.3 targets a single PostgreSQL primary, optionally with platform-managed standby/failover. Multi-region active/active writes are not supported. Clock synchronization is required on application and database hosts because token and console-session validity are time-dependent.

The service exposes separate liveness and readiness concepts:

- liveness answers whether the process/event loop can serve requests;
- readiness answers whether required configuration, realm keys, and PostgreSQL are usable.

Readiness must fail during an unsafe partial startup instead of admitting protocol traffic.

## Further reading

- [`oidc-provider` documentation](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [Node.js 22 documentation](https://nodejs.org/download/release/latest-v22.x/docs/api/)
