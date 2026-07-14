# Keycloak compatibility

## Compatibility promise

AuthMe v0.3 provides a migration-oriented compatibility facade for common Keycloak OpenID Connect clients. It preserves Keycloak-shaped issuer URLs, OIDC endpoint paths, and role claims so many relying parties can switch providers with little or no application code change.

It is not a drop-in replacement for the Keycloak Admin REST API, database, extensions, adapters, SAML surface, or every Keycloak feature. Compatibility means explicitly listed behavior only.

Keycloak's current feature inventory includes OIDC/OAuth, SAML, identity brokering, social login, LDAP/AD federation, Kerberos, admin and account consoles, themes, flexible authentication, passkeys/TOTP/recovery codes, sessions, token mappers, and SPIs; see the official [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/). AuthMe implements a documented subset and stages the rest rather than implying drop-in parity.

## v0.3 compatibility status

| Capability | v0.3 status | Notes |
|---|---|---|
| Realm-shaped issuer | Implemented | `https://host/realms/{realm}` |
| OIDC discovery | Implemented | Keycloak-shaped discovery URL |
| OAuth authorization-server metadata | Implemented | RFC 8414 path for realm issuers; endpoints remain realm-mounted |
| JWKS/certs | Implemented | Public verification keys only |
| Authorization Code | Implemented | PKCE `S256` supported/required by client policy |
| Refresh token | Implemented | Subject to client and scope policy |
| Client Credentials | Implemented | For confidential service clients |
| UserInfo | Implemented | Scope-limited claims |
| Introspection | Implemented | Issuing clients and audience-authorized confidential clients for opaque tokens; JWT access tokens are validated locally |
| Revocation | Implemented | Standard OAuth revocation endpoint |
| RP-initiated logout | Implemented | Exact registered post-logout redirect validation |
| Back-channel logout | Implemented | Standards-based signed logout token delivery |
| Device Authorization Grant | Implemented | Use discovery metadata; do not guess the endpoint |
| Pushed Authorization Requests | Implemented | Provider-issued expiring request URIs |
| DPoP | Implemented | Enabled by client policy; proof validation and replay state are durable |
| Dynamic client registration | Implemented | Requires an AuthMe initial access token |
| TOTP and recovery codes | Implemented | New AuthMe enrollment; existing Keycloak credential import is not guaranteed |
| WebAuthn/passkeys | Implemented baseline | Fresh AuthMe registration and login; no Keycloak credential import or attestation policy |
| Administration console | Implemented, AuthMe-native | Realm-scoped OIDC login, grants, users, credentials, audit, client registration, and safe configuration; not the Keycloak console or theme system |
| Administration API | Implemented, AuthMe-native | Separate root bearer for automation; not Keycloak Admin REST compatible |
| Realm/client role claims | Implemented | Keycloak-shaped JSON claims |
| Groups claim | Implemented baseline | Flat emitted paths; advanced mapping is staged |
| API audiences/JWT access tokens | Implemented baseline | Exact configured RFC 8707 audiences; `typ: at+jwt`; audience-filtered role/group claims |
| Pairwise subjects | Implemented | Realm- and client/sector-bound identifiers |
| Direct Access Grants/password grant | Not supported | Deliberately omitted under current OAuth security guidance |
| Implicit/hybrid flows | Not in v0.3 contract | Upstream capability does not mean enabled AuthMe behavior |
| CIBA/JAR/JARM/mTLS/FAPI | Staged | Library capabilities require AuthMe configuration and conformance gates |
| Keycloak Admin REST API | Not supported | AuthMe administration is a separate API/model |
| Upstream OIDC brokering | Implemented baseline | Fixed-provider Authorization Code + PKCE; collision-safe JIT/admin linking; no social presets |
| SAML 2.0 federation | Implemented SP baseline | SP-initiated signed response/assertion; no encrypted assertions, SLO, IdP-initiated login, or SAML IdP |
| LDAP/Active Directory | Implemented authentication baseline | LDAPS/StartTLS credential validation and mapping; no synchronization or Kerberos |
| SCIM 2.0 | Implemented core baseline | Users/Groups CRUD/PATCH, discovery, core `eq`, pagination, ETags; no Bulk/full filters/extensions |
| Kerberos/SPNEGO | Not supported | No v0.3 implementation |

## URL mapping

The following public paths intentionally match Keycloak's OIDC layout, documented by Keycloak in [OIDC layers](https://www.keycloak.org/securing-apps/oidc-layers):

| Purpose | Keycloak-compatible AuthMe path |
|---|---|
| Issuer | `/realms/{realm}` |
| Discovery | `/realms/{realm}/.well-known/openid-configuration` |
| Authorization | `/realms/{realm}/protocol/openid-connect/auth` |
| Token | `/realms/{realm}/protocol/openid-connect/token` |
| UserInfo | `/realms/{realm}/protocol/openid-connect/userinfo` |
| JWKS | `/realms/{realm}/protocol/openid-connect/certs` |
| Logout | `/realms/{realm}/protocol/openid-connect/logout` |
| Revocation | `/realms/{realm}/protocol/openid-connect/revoke` |
| Introspection | `/realms/{realm}/protocol/openid-connect/token/introspect` |
| Device authorization | `/realms/{realm}/protocol/openid-connect/auth/device` |
| Device user verification | `/realms/{realm}/device` |
| PAR | `/realms/{realm}/protocol/openid-connect/ext/par/request` |
| Dynamic registration | `/realms/{realm}/clients-registrations/openid-connect` |

The legacy Keycloak direct-POST logout format used by old Keycloak adapters is not part of the compatibility promise. Keycloak itself describes that format as non-standard and recommends standards-based logout.

Device Authorization, PAR, DPoP, dynamic registration, and back-channel logout are implemented v0.3 capabilities. The table records AuthMe's configured compatibility routes, but clients must still use discovery metadata as the canonical source for endpoints and advertised authentication methods rather than constructing URLs.

An issuer is an exact security identifier, not a display URL. To migrate without changing client issuer configuration, AuthMe must assume the same external scheme, host, port, and realm path previously used by Keycloak. Reverse-proxy rewrites must not cause discovery and token `iss` values to diverge.

## Claim mapping

AuthMe's compatibility profile emits realm roles, client roles, and group paths in the familiar Keycloak shape when allowed by the client's claim policy:

```json
{
  "sub": "9af751a0-5842-4c56-8f21-6aa4319a3a25",
  "preferred_username": "sam",
  "realm_access": {
    "roles": ["member", "support"]
  },
  "resource_access": {
    "orders-api": {
      "roles": ["orders.read", "orders.refund"]
    }
  },
  "groups": ["/support", "/engineering/platform"]
}
```

Compatibility rules:

- `realm_access.roles` is included in a resource token only when the `roles`
  scope is granted and the audience enables realm roles.
- `resource_access.{client_id}.roles` contains only client-role namespaces
  explicitly selected by the resource audience's claim policy.
- `groups` contains canonical group paths only when `groups` is granted and the
  audience enables group disclosure.
- Standard OIDC claims remain governed by requested scopes and consent/client policy.
- Role names are case-sensitive and should be migrated without normalization surprises.
- Token consumers must tolerate additional standard claims and must not depend on JSON member ordering.

Composite-role expansion, arbitrary Keycloak protocol mappers, authorization-services permissions, lightweight access-token conventions, and every Keycloak built-in role are not guaranteed in v0.3.

## Client mapping

The ordinary Keycloak OIDC client concepts map as follows:

| Keycloak concept | AuthMe v0.3 mapping |
|---|---|
| Client ID | Client identifier, unchanged when possible |
| Valid redirect URIs | Exact redirect URI registrations |
| Valid post logout redirect URIs | Exact post-logout URI registrations |
| Web origins | Explicit CORS origins, never inferred from broad wildcard redirects |
| Public client | Client with no client secret and mandatory PKCE |
| Confidential client | Client authentication configured at token endpoints |
| Service accounts | Client Credentials grant plus assigned client roles/scopes |
| Standard flow | Authorization Code flow |
| Direct access grants | No v0.3 equivalent |
| Client scopes | Explicit OIDC scopes and claim policy; advanced reusable mappers staged |
| Realm/client roles | Separate realm and client-role assignments |

Do not copy a Keycloak client secret into logs, command history, tickets, or migration files. Prefer rotating the secret during migration.

The v0.3 authentication-method profile supports `client_secret_basic` and
`none`. It does not advertise staged methods such as `private_key_jwt`.
Keycloak deployments using another client authentication method must change
the client or wait for the corresponding supported profile.

Keycloak-style API tokens require an explicit AuthMe resource-server entry and
an RFC 8707 `resource` parameter. JWT tokens are validated with the realm JWKS,
exact issuer and configured audience; the upstream provider intentionally
rejects structured JWTs at introspection and revocation. JWT validators observe
account/security changes no later than token expiration unless they maintain an
additional denylist. Configure an opaque resource token for APIs that require
immediate online revocation or authorized introspection.

## Behavior that may require relying-party changes

Even when URLs and claims match, test these behaviors:

- supported signing algorithms and key size;
- access-token format and whether the application incorrectly relies on undocumented token internals;
- token/session lifetimes and refresh rotation;
- audience values;
- CORS behavior;
- logout/session propagation;
- error pages and localization;
- composite-role and custom mapper output;
- Keycloak adapter-specific endpoints or response extensions.

Applications must discover endpoints from the issuer rather than concatenate undocumented paths. Resource servers must validate tokens using standards-based libraries, not Keycloak-internal classes or database access.

## Deliberately unsupported v0.3 surfaces

The following require staged implementations and separate compatibility specifications:

- SAML IdP operation, IdP-initiated login, encrypted assertions, artifact binding, and single logout;
- LDAP/Active Directory synchronization and Kerberos/SPNEGO;
- curated social identity-provider presets and arbitrary broker plugins; upstream OIDC and SAML federation are implemented baselines;
- Keycloak Admin REST and `kcadm` compatibility;
- a self-service account console, complete Keycloak-equivalent policy administration, and Keycloak theme/SPI packages; AuthMe's native administration console is implemented;
- configurable authentication flows, arbitrary required actions, imported WebAuthn/U2F credentials, attestation policy, and X.509; fresh AuthMe passkey, TOTP, and one-use recovery-code enrollment is implemented;
- organizations and invitations;
- SCIM Bulk, sorting, arbitrary extension schemas, and the complete filter grammar; core Users/Groups provisioning is implemented;
- Authorization Services/UMA 2 policy evaluation;
- Keycloak realm JSON import fidelity;
- not-before revocation policies and every protocol mapper.

## Compatibility validation

Every migration should run a client-by-client contract suite that compares:

1. discovery metadata and issuer;
2. authorization redirect/error behavior;
3. token signature, standard claims, audience, and role/group claims;
4. refresh and revocation behavior;
5. UserInfo and introspection authorization;
6. browser session and RP-initiated logout;
7. CORS and native-client redirect behavior where relevant.

The exact AuthMe deployment must also run the [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/). The upstream `oidc-provider` certification is strong evidence for its protocol engine, but it does not certify AuthMe's routes, adapter, interactions, or configuration.
