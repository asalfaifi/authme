# Keycloak compatibility

## Compatibility promise

AuthMe v0.1 provides a migration-oriented compatibility facade for common Keycloak OpenID Connect clients. It preserves Keycloak-shaped issuer URLs, OIDC endpoint paths, and role claims so many relying parties can switch providers with little or no application code change.

It is not a drop-in replacement for the Keycloak Admin REST API, database, extensions, adapters, SAML surface, or every Keycloak feature. Compatibility means explicitly listed behavior only.

Keycloak's current feature inventory includes OIDC/OAuth, SAML, identity brokering, social login, LDAP/AD federation, Kerberos, admin and account consoles, themes, flexible authentication, passkeys/TOTP/recovery codes, sessions, token mappers, and SPIs; see the official [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/). AuthMe stages much of that surface rather than pretending it exists in v0.1.

## v0.1 compatibility status

| Capability | v0.1 status | Notes |
|---|---|---|
| Realm-shaped issuer | Implemented | `https://host/realms/{realm}` |
| OIDC discovery | Implemented | Keycloak-shaped discovery URL |
| JWKS/certs | Implemented | Public verification keys only |
| Authorization Code | Implemented | PKCE `S256` supported/required by client policy |
| Refresh token | Implemented | Subject to client and scope policy |
| Client Credentials | Implemented | For confidential service clients |
| UserInfo | Implemented | Scope-limited claims |
| Introspection | Implemented | Authenticated authorized clients only |
| Revocation | Implemented | Standard OAuth revocation endpoint |
| RP-initiated logout | Implemented | Exact registered post-logout redirect validation |
| Back-channel logout | Implemented | Standards-based signed logout token delivery |
| Device Authorization Grant | Implemented | Use discovery metadata; do not guess the endpoint |
| Pushed Authorization Requests | Implemented | Provider-issued expiring request URIs |
| DPoP | Implemented | Enabled by client policy; proof validation and replay state are durable |
| Dynamic client registration | Implemented | Requires an AuthMe initial access token |
| TOTP and recovery codes | Implemented | New AuthMe enrollment; existing Keycloak credential import is not guaranteed |
| Administration API | Implemented, AuthMe-native | Dedicated bearer token; not Keycloak Admin REST compatible |
| Realm/client role claims | Implemented | Keycloak-shaped JSON claims |
| Groups claim | Implemented baseline | Flat emitted paths; advanced mapping is staged |
| Direct Access Grants/password grant | Not supported | Deliberately omitted under current OAuth security guidance |
| Implicit/hybrid flows | Not in v0.1 contract | Upstream capability does not mean enabled AuthMe behavior |
| CIBA/JAR/JARM/mTLS/FAPI | Staged | Library capabilities require AuthMe configuration and conformance gates |
| Keycloak Admin REST API | Not supported | AuthMe administration is a separate API/model |
| SAML/LDAP/Kerberos/SCIM/brokering | Staged | See [roadmap.md](roadmap.md) |

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

Device Authorization, PAR, DPoP, dynamic registration, and back-channel logout are implemented v0.1 capabilities. The table records AuthMe's configured compatibility routes, but clients must still use discovery metadata as the canonical source for endpoints and advertised authentication methods rather than constructing URLs.

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

- `realm_access.roles` contains realm roles visible to the client.
- `resource_access.{client_id}.roles` contains client-scoped roles visible to the token audience/client policy.
- `groups` contains canonical group paths when the claim is enabled.
- Standard OIDC claims remain governed by requested scopes and consent/client policy.
- Role names are case-sensitive and should be migrated without normalization surprises.
- Token consumers must tolerate additional standard claims and must not depend on JSON member ordering.

Composite-role expansion, arbitrary Keycloak protocol mappers, authorization-services permissions, lightweight access-token conventions, and every Keycloak built-in role are not guaranteed in v0.1.

## Client mapping

The ordinary Keycloak OIDC client concepts map as follows:

| Keycloak concept | AuthMe v0.1 mapping |
|---|---|
| Client ID | Client identifier, unchanged when possible |
| Valid redirect URIs | Exact redirect URI registrations |
| Valid post logout redirect URIs | Exact post-logout URI registrations |
| Web origins | Explicit CORS origins, never inferred from broad wildcard redirects |
| Public client | Client with no client secret and mandatory PKCE |
| Confidential client | Client authentication configured at token endpoints |
| Service accounts | Client Credentials grant plus assigned client roles/scopes |
| Standard flow | Authorization Code flow |
| Direct access grants | No v0.1 equivalent |
| Client scopes | Explicit OIDC scopes and claim policy; advanced reusable mappers staged |
| Realm/client roles | Separate realm and client-role assignments |

Do not copy a Keycloak client secret into logs, command history, tickets, or migration files. Prefer rotating the secret during migration.

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

## Deliberately unsupported v0.1 surfaces

The following require staged implementations and separate compatibility specifications:

- SAML identity provider/service-provider endpoints;
- LDAP/Active Directory user federation and Kerberos/SPNEGO;
- OIDC/SAML/social identity brokering;
- Keycloak Admin REST and `kcadm` compatibility;
- account/admin consoles and Keycloak theme/SPI packages;
- configurable authentication flows, arbitrary required actions, WebAuthn/passkeys, and X.509; basic TOTP and one-use AuthMe recovery codes are implemented;
- organizations and invitations;
- SCIM provisioning;
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
