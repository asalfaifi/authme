# AuthMe architecture

## Status and scope

This document describes the AuthMe v0.2 architecture. In this document:

- **Implemented** means the behavior is part of the v0.2 repository and is expected to be covered by automated tests.
- **Staged** means the architecture reserves a boundary for it, but operators must not depend on it yet.
- **Library capability** means `oidc-provider` can implement the protocol, but AuthMe has not necessarily enabled, configured, tested, or certified it.

AuthMe is a standalone, multi-realm OpenID Provider for Node.js 22. It uses [`oidc-provider` 9.9.1](https://oidc-provider.dev/changelog/#_9-9-1-2026-07-07) for standards-sensitive OAuth 2.0 and OpenID Connect behavior rather than implementing those protocols independently. The upstream project is OpenID and FAPI certified and documents its supported specifications in its [official repository](https://github.com/panva/node-oidc-provider#implemented-specs--features). AuthMe still owns its configuration, interaction UI, storage adapter, tenant isolation, operational controls, and conformance testing.

v0.2 is a secure identity foundation with downstream OAuth/OIDC, upstream OIDC and SAML federation, LDAP/AD authentication, SCIM provisioning, and password/TOTP/passkey credentials. It is not yet a complete replacement for every Keycloak feature. The exact boundary is documented in [keycloak-compatibility.md](keycloak-compatibility.md), [federation-and-provisioning.md](federation-and-provisioning.md), and [roadmap.md](roadmap.md).

## Design goals

1. Preserve standard OIDC behavior and Keycloak-compatible public URLs for ordinary OIDC clients.
2. Isolate realms at the issuer, application, and data layers.
3. Keep every protocol artifact required for correctness in PostgreSQL.
4. Run as a single deployable service before introducing distributed-system complexity.
5. Scale horizontally without relying on process memory for sessions, grants, codes, or tokens.
6. Make unsafe production configuration fail at startup.
7. Keep optional infrastructure, such as Redis, outside the correctness path.

## Explicit non-goals for v0.2

v0.2 does not claim Kerberos/SPNEGO, RADIUS, X.509 login, SAML IdP operation, encrypted or IdP-initiated SAML, inbound LDAP synchronization, SCIM Bulk/full filter grammar, configurable authentication flows, Keycloak Admin REST compatibility, UMA authorization services, multi-site active/active operation, WebAuthn attestation assurance, imported U2F credentials, or OpenID certification of the AuthMe product. These are staged capabilities.

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

The v0.2 compatibility facade exposes these Keycloak-shaped paths:

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
/realms/{realm}/clients-registrations/openid-connect
```

The route facade translates public paths to the provider without changing the advertised issuer. The issuer in discovery, ID tokens, access tokens, authorization responses, and introspection data must be identical. OAuth authorization-server metadata and issuer matching are defined by [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html); Keycloak's endpoint surface is documented in its [OIDC endpoint guide](https://www.keycloak.org/securing-apps/oidc-layers).

Every repository operation is realm-scoped. Compound uniqueness and foreign-key constraints must include the realm identifier where they can prevent a cross-realm reference. PostgreSQL row-level security is a planned defense-in-depth layer, not a substitute for explicit realm predicates. PostgreSQL notes that table owners normally bypass RLS unless it is forced and that referential-integrity checks bypass it; see the [PostgreSQL row-security documentation](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

## Protocol engine

AuthMe pins `oidc-provider` to 9.9.1. It does not fork protocol code. The pin is updated only through a reviewed dependency change with protocol, migration, and conformance tests.

The supported v0.2 profile is deliberately smaller than the upstream library's capability surface:

- OpenID Provider discovery and JWKS publication.
- OAuth Authorization Server metadata at the RFC 8414 path for realm issuers.
- Authorization Code flow.
- PKCE using `S256`.
- Refresh tokens where allowed by client policy.
- Client Credentials for service clients.
- UserInfo.
- Token introspection and revocation.
- RP-initiated logout.
- Back-channel logout.
- Device Authorization Grant.
- Pushed Authorization Requests (PAR).
- DPoP-bound access tokens.
- Dynamic client registration protected by an initial access token.
- RFC 8707 resource indicators for explicitly configured API audiences, with JWT or opaque access-token policy per audience.

Advanced endpoints are consumed from discovery metadata; clients must not guess their paths. [Dynamic registration](https://www.rfc-editor.org/rfc/rfc7591.html) requires a short-lived initial access token issued through the AuthMe administration API and is not an anonymous client-creation API. DPoP clients create a proof for the intended method and URL and handle provider nonce responses where required. PAR request URIs and device/user codes are short-lived provider artifacts persisted through the PostgreSQL adapter.

The v0.2 token-endpoint authentication allowlist is deliberately narrow:
`client_secret_basic` for confidential clients and `none` for public clients.
The provider advertises public and pairwise subject types. Pairwise identifiers
are realm- and sector-bound HMAC values derived with `AUTHME_SUBJECT_SALT`.

An ordinary OIDC access token without a `resource` audience remains opaque and
is usable at UserInfo. A configured RFC 8707 resource produces an
audience-bound token in that resource's declared format. JWT resource tokens
use `typ: at+jwt` and are validated locally using the realm JWKS, issuer,
audience, signature, and time claims. The upstream provider intentionally
rejects JWTs at introspection and revocation; configured opaque resource tokens
can instead be introspected by confidential clients explicitly listed for that
audience and checked online for security-state changes. Offline JWT validators
accept a token until its short expiration unless they operate a denylist.

Implicit flow, Resource Owner Password Credentials, CIBA, JAR, JARM, mTLS, and FAPI profiles are not part of the v0.2 product contract unless a release explicitly enables and tests them. The OAuth Security Best Current Practice requires authorization servers to support PKCE, requires it for public clients, recommends it for confidential clients, and requires exact redirect URI matching; see [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html). PAR is defined by [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html), DPoP by [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), and Device Authorization by [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html).

## Persistence

PostgreSQL is the canonical store for AuthMe configuration and for all `oidc-provider` artifacts that affect protocol correctness. The durable adapter stores, as applicable:

- sessions and interactions;
- authorization codes;
- access and refresh tokens;
- grants and consents;
- replay-detection records;
- device codes, pushed authorization requests, DPoP replay records, and dynamic-registration artifacts;
- client and user data;
- realm configuration and signing material metadata;
- audit and operational events.

Adapter records carry a realm discriminator in addition to the upstream model identifier. Expiration is enforced on reads and by periodic cleanup. One-use values must be consumed atomically; a read followed by an unrelated delete is not sufficient under concurrency. PostgreSQL row locks, uniqueness constraints, or compare-and-update statements provide the serialization point. PostgreSQL documents its transaction and locking semantics in [Transaction Isolation](https://www.postgresql.org/docs/current/transaction-iso.html) and [Explicit Locking](https://www.postgresql.org/docs/current/explicit-locking.html).

Process memory may cache non-sensitive, reconstructable configuration for bounded periods, but it is never the only store for sessions, authorization codes, refresh tokens, grants, or revocation state.

## Redis boundary

Redis is optional and is used only for shared rate-limit counters in v0.2. It is not the source of truth for users, clients, sessions, grants, tokens, or signing keys.

- Without Redis, a single-node deployment uses local rate limiting.
- A multi-node production deployment should configure Redis so limits are enforced across replicas.
- Redis failure must not silently disable all abuse controls. The configured failure policy must be observable and documented for the deployment.
- Rate-limit keys contain opaque realm/subject buckets, not passwords, tokens, email addresses, or raw IP/user combinations that unnecessarily expose personal data.

## Identity and claims

AuthMe owns the account lookup used by `oidc-provider`. A subject identifier is stable within its realm and must not be recycled. Client-visible identity claims are minimized to the scopes and mappers allowed for that client.

Passwords are hashed with Argon2id plus an independent deployment pepper. v0.2 also implements [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)-compatible TOTP as a second factor and one-use recovery codes. TOTP secrets are protected with the field-encryption key and realm/user-bound context; recovery codes are shown once and stored as keyed digests. TOTP is not phishing-resistant.

Fresh passkey registration and passwordless interaction login use the maintained `@simplewebauthn/server` verifier. AuthMe requires discoverable credentials and authenticator user verification, derives non-identifying realm-scoped user handles, checks the exact configured origin and RP hostname, persists credential public keys/counters/transports, and atomically consumes short-lived server-side challenges. Registration requests use `attestation: none`; stored AAGUID/device metadata is descriptive and is not an attestation trust decision. Because realms share one path-based origin, the browser RP ID is common while database credentials, user handles, and challenges remain realm-scoped.

## Identity extensions, federation, and provisioning

Trusted built-in identity modules register through the versioned `authme.identity/v1` contract. An extension declares an `authenticator`, `federation`, or `provisioning` kind plus stable capabilities; the realm registry exposes only enabled entries. This isolates protocol code while keeping extensions compile-time reviewed and deployed with AuthMe. Arbitrary runtime plugin loading is deliberately not part of the trust model.

LDAP/AD authentication uses an exact realm provider configuration, escaped and bounded directory search, a distinct user bind, TLS certificate validation, and an immutable directory subject. OIDC federation uses Authorization Code + PKCE with provider-bound one-use state and nonce, fixed endpoints, strict issuer/signature/audience/subject validation, and no redirect following. SAML federation publishes provider-specific SP metadata/ACS endpoints, binds RelayState to the active OIDC interaction, requires signed Response and Assertion validation, and persists response/assertion replay keys through the realm adapter.

All external identities resolve through the `federated_identities` repository by realm, provider ID, canonical issuer, and upstream subject. Username/email collisions fail closed and require an explicit administration link. JIT account creation is provider opt-in. Upstream callback completion is converted to a short-lived, one-use same-origin handle before finishing the downstream OIDC interaction, so upstream assertions or tokens never enter an AuthMe front-channel URL.

SCIM is a realm-scoped PostgreSQL provisioning surface under `/scim/v2/realms/{realm}`. Its Users and Groups map to the canonical identity tables, use optimistic ETag comparison, synchronize membership, and advance account security/revoke current state on identity changes. Discovery and core `eq` filtering are implemented; Bulk, sorting, arbitrary extension schemas, and the full filter grammar are outside this release. Configuration and endpoint details are in [federation-and-provisioning.md](federation-and-provisioning.md).

For migration compatibility, v0.2 can emit Keycloak-shaped authorization claims:

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

## Administration and audit

v0.2 exposes a small AuthMe administration API protected by a dedicated bearer token. It manages the implemented user/client/bootstrap surface; it is not wire-compatible with the Keycloak Admin REST API and is not a substitute for delegated realm administration.

The administration token is deployment-wide high privilege. It must be supplied through secret management, compared without timing leakage, restricted at the network layer where possible, rotated independently, and excluded from logs. Administrative mutations synchronously write realm-scoped JSON audit records. Account-security changes, session revocation, and deletion commit their audit with the PostgreSQL mutation; user creation, unlock, and TOTP-enrollment start currently audit immediately after their mutation, so an audit-storage failure can produce an ambiguous `5xx` that operators must reconcile. High-volume protocol events use a bounded, sampled writer so unauthenticated traffic cannot create an unbounded database waiter queue; dropped/sampled/write-failure outcomes are metrics. PostgreSQL retention cleanup removes audit rows older than the configured window. Fine-grained administrator identities, roles, approvals, a transactional outbox, and a full console are staged.

## Cryptographic boundary

AuthMe delegates JOSE processing to the provider and its maintained dependencies. It does not implement signing algorithms. JWT validation and production configuration follow [JWT Best Current Practices, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html), including algorithm allowlists, mutually exclusive validation rules for different JWT kinds, and full issuer/audience/type/time validation.

Each realm has its own logical signing keyring. Production private keys must be supplied from protected secret storage or an envelope-encrypted database representation, never committed to the repository. Rotation uses three states:

1. **Active**: signs newly issued tokens.
2. **Retiring**: remains in JWKS for verification but does not sign new tokens.
3. **Removed**: deleted only after every token it could have signed has expired, including clock skew and caches.

KMS/HSM-backed signing and automated rotation are staged. v0.2 operators are responsible for controlled key injection and rotation.

## Internal boundaries

The source tree is organized around these responsibilities:

- **configuration**: parse, validate, and freeze startup configuration;
- **realm resolution**: resolve path to enabled realm and issuer;
- **provider factory**: create/cache realm-specific `oidc-provider` instances;
- **adapter**: map provider models to durable PostgreSQL records;
- **repositories**: realm, client, user, role, and group persistence;
- **interactions/UI**: authentication, consent, and user-facing error pages;
- **routes**: compatibility paths plus health and operational endpoints;
- **crypto**: key loading and secret handling, never custom primitives;
- **observability**: structured logs, metrics, correlation, and redaction.

Protocol routes do not query tables directly. They use provider/application interfaces so storage and tenant checks remain centralized.

## Availability and consistency

AuthMe nodes are intended to be stateless between requests. PostgreSQL availability determines authentication availability. Redis availability affects shared throttling, not durable identity state.

v0.2 targets a single PostgreSQL primary, optionally with platform-managed standby/failover. Multi-region active/active writes are not supported. Clock synchronization is required on application and database hosts because token validity is time-dependent.

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
