# Keycloak compatibility

## Compatibility promise

AuthMe v1.0.0-rc.1 provides a migration-oriented compatibility facade for common Keycloak OpenID Connect applications and downstream SAML service providers. It preserves Keycloak-shaped issuer URLs, OIDC endpoint paths, role claims, and the supported exact SAML registration contract so relying parties can migrate through an explicit reconciliation process.

It is not a drop-in replacement for the Keycloak Admin REST API, database, extensions, adapters, complete SAML surface, or every Keycloak feature. Compatibility means explicitly listed behavior only.

Keycloak's current feature inventory includes OIDC/OAuth, SAML, identity brokering, social login, LDAP/AD federation, Kerberos, admin and account consoles, themes, flexible authentication, passkeys/TOTP/recovery codes, sessions, token mappers, and SPIs; see the official [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/). AuthMe implements a documented subset and stages the rest rather than implying drop-in parity.

## v1.0 release-candidate compatibility status

| Capability | Status | Notes |
|---|---|---|
| Realm-shaped issuer | Implemented | `https://host/realms/{realm}` |
| OIDC discovery | Implemented | Keycloak-shaped discovery URL |
| OAuth authorization-server metadata | Implemented | RFC 8414 path for realm issuers; endpoints remain realm-mounted |
| JWKS/certs | Implemented | Public verification keys only |
| Authorization Code | Implemented | PKCE `S256` supported/required by client policy |
| Refresh token | Implemented | Subject to client and scope policy |
| Client Credentials | Implemented | For confidential service clients |
| Client authentication | Implemented | `client_secret_basic`, `client_secret_jwt` (HS256), `private_key_jwt` (RS256, PS256, or ES256), `tls_client_auth`, `self_signed_tls_client_auth`, and `none` |
| UserInfo | Implemented | Scope-limited JSON by default; optional realm-signed JWT per client |
| Introspection | Implemented | JSON by default or optional realm-signed JWT; issuing clients and audience-authorized confidential clients for opaque tokens; JWT access tokens are validated locally |
| Revocation | Implemented | Standard OAuth revocation endpoint |
| RP-initiated logout | Implemented | Exact registered post-logout redirect validation |
| Back-channel logout | Implemented | Standards-based signed logout token delivery |
| Device Authorization Grant | Implemented | Use discovery metadata; do not guess the endpoint |
| CIBA | Implemented in v0.4 | OpenID CIBA Core poll mode for confidential clients; ping and push are not supported |
| Pushed Authorization Requests | Implemented | Provider-issued expiring request URIs |
| JAR | Implemented in v0.4 | Signed `request` objects using registered client public keys; remote client-hosted `request_uri` retrieval is not supported |
| JARM | Implemented in v0.4 | Realm-key-signed `jwt`, `query.jwt`, `fragment.jwt`, and `form_post.jwt` authorization responses |
| DPoP | Implemented | Enabled by client policy; proof validation and replay state are durable |
| mTLS | Implemented in v0.4 | RFC 8705 PKI/self-signed client authentication and `cnf.x5t#S256` certificate-bound access tokens through an explicitly trusted proxy boundary |
| Dynamic client registration | Implemented | Requires an AuthMe initial access token |
| TOTP and recovery codes | Implemented | New AuthMe enrollment; existing Keycloak credential import is not guaranteed |
| WebAuthn/passkeys | Implemented baseline | Fresh AuthMe registration and login; no Keycloak credential import or attestation policy |
| Administration console | Implemented, AuthMe-native | Realm-scoped OIDC login, grants, users, credentials, audit, client registration, and safe configuration; not the Keycloak console or theme system |
| Administration API | Implemented, AuthMe-native | Separate root bearer for automation; not Keycloak Admin REST compatible |
| Realm/client role claims | Implemented | Keycloak-shaped JSON claims |
| Groups and roles | Implemented | Stable nested group paths, group roles, composite realm-role expansion, reusable client scopes, and configured claim mappers |
| API audiences/JWT access tokens | Implemented | Exact configured RFC 8707 audiences; per-client and multi-resource policy; `typ: at+jwt`; audience-filtered scopes and role/group claims |
| Pairwise subjects | Implemented | Realm- and client/sector-bound identifiers |
| Direct Access Grants/password grant | Not supported | Deliberately omitted under current OAuth security guidance |
| Implicit/hybrid flows | Not in product contract | Upstream capability does not mean enabled AuthMe behavior |
| mTLS | Implemented in v0.4 | `tls_client_auth` + `self_signed_tls_client_auth` via trusted proxy; `cnf.x5t#S256` certificate-bound tokens |
| CIBA | Implemented in v0.4 | Poll mode, confidential clients only; ping/push staged |
| FAPI 2.0 | Implemented in v0.4, opt-in | AuthMe `fapi_profile: "2.0"` authorization-code clients require PAR, PKCE `S256`, PS256/ES256 JAR/JARM, DPoP or mTLS token binding, and private-key or mTLS client authentication; AuthMe is not certified |
| Keycloak Admin REST API | Not supported | AuthMe administration is a separate API/model |
| Upstream OIDC brokering | Implemented baseline | Fixed-provider Authorization Code + PKCE; collision-safe JIT/admin linking; organization IdP policy; no social presets |
| SAML 2.0 | Implemented SP and IdP baselines | Upstream SP federation plus downstream IdP metadata, Redirect/POST login, signed Response/Assertion, optional outgoing assertion encryption, opt-in IdP initiation, and redirect SLO; no artifact binding or broker-side decryption |
| LDAP/Active Directory | Implemented | LDAPS/StartTLS credential validation plus bounded import, synchronization, reconciliation, mapped groups/roles, and disable/delete policy; no Kerberos |
| SCIM 2.0 | Implemented | Users/Groups CRUD/PATCH, discovery, Bulk, sorting, supported full core filter grammar, pagination, and ETags; arbitrary extension schemas are not promised |
| Account console | Implemented, AuthMe-native | Profile, password/recovery, email verification, TOTP/recovery codes, passkeys, sessions, and organization invitation acceptance |
| Organizations | Implemented, AuthMe-native | Domains, invitations, memberships/roles, organization IdP policy, and authorization token context |
| Authentication flows | Implemented, AuthMe-native | Client/ACR-selected password, TOTP, passkey, and federation steps with AMR and maximum-age enforcement |
| Signing/operations | Implemented code path | Encrypted backup/restore, HA/load rehearsal, and file/KMS/HSM signing-provider rotation; real hardware/DR drills remain external evidence |
| Kerberos/SPNEGO | Not supported | No implementation |

## Declared reference deployment profiles

The v1 release-candidate compatibility contract is evaluated against three named profiles. These are bounded technical profiles, not claims about an unnamed customer deployment:

| Profile | Required behavior | Critical migration blockers |
|---|---|---|
| **OIDC application estate** | Realm-shaped issuer; Authorization Code + PKCE; refresh and client-credentials grants; standard logout; realm/client roles, nested group paths, client scopes, and claim mappers; PostgreSQL-backed sessions | Direct Access Grant, implicit/hybrid-only clients, Keycloak adapter-specific logout, custom protocol mappers/SPIs, UMA policies, or an issuer/redirect change the applications cannot accept |
| **Enterprise workforce** | OIDC applications plus LDAP/AD import/sync or supported upstream OIDC/SAML federation, SCIM Users/Groups, organizations, MFA/passkeys, native account/admin consoles | Kerberos/SPNEGO, broker-side encrypted SAML assertions, non-portable existing MFA credentials without re-enrollment, arbitrary SCIM extensions, or required Keycloak Admin REST compatibility |
| **Federation hub** | AuthMe downstream SAML IdP with exact registered SP metadata, signed Response/Assertion, optional assertion encryption, supported IdP initiation and redirect SLO, plus the OIDC application profile | SAML artifact binding, SOAP/POST or multi-party logout, arbitrary Keycloak authentication SPIs/themes, or SP behavior outside the registered algorithm/binding contract |

A deployment matches a profile only when `kc:import` reports no unsupported feature used by a critical workload, every emitted reference reconciles, credentials and secrets have an explicit replacement plan, and its relying-party/federation test suite passes against a production-like AuthMe environment. Any listed blocker makes that source deployment out of profile; it must be redesigned, split into a bounded coexistence migration, or remain on Keycloak. This prevents “no critical blocker” from being inferred merely from a successful JSON parse.

`test/keycloak-import.test.js` contains executable minimal exports for all three
profiles and requires a zero-item `unsupportedOrSkipped` report. They prove the
bounded transformer contract, including downstream signed/encrypted SAML
registration; they do not replace a deployment's own inventory, secret/key
replacement, reconciliation, or interoperability evidence.

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
| CIBA backchannel authentication | `/realms/{realm}/protocol/openid-connect/ext/ciba/auth` |
| Dynamic registration | `/realms/{realm}/clients-registrations/openid-connect` |

The legacy Keycloak direct-POST logout format used by old Keycloak adapters is not part of the compatibility promise. Keycloak itself describes that format as non-standard and recommends standards-based logout.

Device Authorization, PAR, DPoP, dynamic registration, and back-channel logout are implemented v0.3 capabilities; JAR, JARM, mTLS, and CIBA poll mode are implemented in v0.4. CIBA clients are confidential, register the CIBA grant and poll delivery mode, and use discovery for the backchannel endpoint and polling interval; Keycloak-specific CIBA extensions, ping, and push are not supported. JAR clients register a public inline `jwks` and one of the advertised `RS256`, `PS256`, or `ES256` request-object algorithms. They may set `require_signed_request_object` when every authorization request for that client must use JAR. The table records AuthMe's configured compatibility routes and response modes, but clients must still use discovery metadata as the canonical source for endpoints, response modes, signing algorithms, and advertised authentication methods rather than constructing URLs or assuming algorithm support.

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

Composite realm roles and AuthMe's documented hardcoded, user-attribute, role, group, and organization claim mappers are implemented. Keycloak script mappers, authorization-services permissions, lightweight access-token conventions, and every Keycloak built-in role are not guaranteed.

## Client mapping

The ordinary Keycloak OIDC client concepts map as follows:

| Keycloak concept | AuthMe v1.0 mapping |
|---|---|
| Client ID | Client identifier, unchanged when possible |
| Valid redirect URIs | Exact redirect URI registrations |
| Valid post logout redirect URIs | Exact post-logout URI registrations |
| Web origins | Explicit CORS origins, never inferred from broad wildcard redirects |
| Public client | Client with no client secret and mandatory PKCE |
| Confidential client | Client authentication configured at token endpoints |
| Service accounts | Client Credentials grant plus assigned client roles/scopes |
| Standard flow | Authorization Code flow |
| Direct access grants | No equivalent |
| Client scopes | Reusable default/optional scopes with configured claim mappers |
| Realm/client roles | Separate realm and client-role assignments |

Do not copy a Keycloak client secret into logs, command history, tickets, or migration files. Prefer rotating the secret during migration.

The authentication-method profile supports `client_secret_basic`,
`client_secret_jwt`, `private_key_jwt`, `tls_client_auth`,
`self_signed_tls_client_auth`, and `none` at the token, introspection, and
revocation endpoints. The mTLS methods are advertised only when their trusted
proxy certificate-header boundary is configured. JWT client assertions use the exact realm issuer or
token endpoint as their audience and a durable one-use `jti`. Asymmetric clients
can register public keys inline with `jwks` or at a constrained HTTPS
`jwks_uri`. Keycloak deployments using another method, including
`client_secret_post`, must change the client authentication configuration.

There is no automatic Keycloak-client switch equivalent to AuthMe's FAPI
marker. A migrated client opts in explicitly with `fapi_profile: "2.0"` and
must be reconfigured as a confidential authorization-code client with
`private_key_jwt`, `tls_client_auth`, or `self_signed_tls_client_auth`. It must
also select exactly one required sender constraint through
`dpop_bound_access_tokens` or
`tls_client_certificate_bound_access_tokens`, register PS256/ES256 verification
keys, use client-authenticated PAR with PKCE `S256` and a signed Request Object,
and verify PS256/ES256 JARM responses. AuthMe forces the PAR, signed Request
Object, and `response_mode=jwt` client policy when the marker is present and
rejects unsupported grants or weak combinations at startup/registration. The
realm must have a matching PS256/ES256 response-signing key. Clients without the
marker retain their existing Keycloak-compatible authorization behavior.

The applicable OpenID Foundation plans are the enabled FAPI2SP OP private key
or MTLS client-authentication combinations crossed with DPoP or MTLS sender
constraining, FAPI2SP OP OpenID Connect, FAPI2MS OP JAR, and FAPI2MS OP JARM.
AuthMe makes no certification claim until those plans pass and the exact build
and deployment are certified. The upstream protocol library's certification is
not AuthMe certification; FAPI-CIBA, client-credentials, and ecosystem-specific
profiles remain outside this compatibility contract.

An RFC 8705 client using `tls_client_auth` registers exactly one expected
certificate subject DN or SAN. A `self_signed_tls_client_auth` client registers
the certificate in public `jwks`/`jwks_uri` `x5c` metadata. Setting
`tls_client_certificate_bound_access_tokens: true` binds issued access tokens
to the presented certificate; JWT tokens carry `cnf.x5t#S256`, and opaque-token
introspection returns the same value. This requires an ingress that performs
mutual TLS, overwrites the configured certificate/verification/forwarding
headers, and connects from an explicitly allowlisted proxy CIDR. It is not
compatible with forwarding an end-user-supplied certificate header through an
ordinary Keycloak-style HTTP proxy configuration.

AuthMe v0.4 clients can register `userinfo_signed_response_alg: RS256` to receive a signed `application/jwt` UserInfo response, as defined by [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0-errata2.html#UserInfoResponse). An authorized resource client can register `introspection_signed_response_alg: RS256` and send `Accept: application/token-introspection+jwt` to receive the signed response defined by [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701.html). Both response types use the realm signing key and are verified with its public JWKS; `none` is rejected. Clients without these opt-ins keep the existing JSON behavior. Signed introspection is a response-format option, not an authorization bypass: the configured opaque-token audience and `introspection_client_ids` policy remains in force.

Keycloak-style API tokens require an explicit AuthMe resource-server entry and
an RFC 8707 `resource` parameter. JWT tokens are validated with the realm JWKS,
exact issuer and configured audience; the upstream provider intentionally
rejects structured JWTs at introspection and revocation. JWT validators observe
account/security changes no later than token expiration unless they maintain an
additional denylist. Configure an opaque resource token for APIs that require
immediate online revocation or authorized introspection.

During migration, `authorized_client_ids` defines which clients may request
each API audience. Multi-resource authorization requests are denied by default;
every resource in an allowed combination must also list the client in
`multi_resource_client_ids`. A multi-resource grant does not produce a
multi-audience access token: the token request selects one granted resource and
the resulting token contains only that audience and that resource's scopes.

## Behavior that may require relying-party changes

Even when URLs and claims match, test these behaviors:

- supported signing algorithms and key size;
- UserInfo and introspection response metadata, media types, and JWT verification;
- access-token format and whether the application incorrectly relies on undocumented token internals;
- token/session lifetimes and refresh rotation;
- audience values;
- CORS behavior;
- logout/session propagation;
- error pages and localization;
- composite-role and custom mapper output;
- Keycloak adapter-specific endpoints or response extensions.

Applications must discover endpoints from the issuer rather than concatenate undocumented paths. Resource servers must validate tokens using standards-based libraries, not Keycloak-internal classes or database access.

## Deliberately unsupported surfaces

The following are outside the v1.0 release-candidate compatibility promise:

- SAML artifact binding, encrypted assertions received by the upstream broker, and POST/SOAP or multi-party logout beyond the implemented IdP baseline;
- Kerberos/SPNEGO and X.509 end-user authentication;
- curated social identity-provider presets and arbitrary broker plugins; upstream OIDC and SAML federation are implemented baselines;
- Keycloak Admin REST and `kcadm` compatibility;
- Keycloak-equivalent UI behavior, Keycloak theme/SPI packages, and arbitrary required-action plugins; AuthMe's native account/admin consoles and documented authentication steps are implemented;
- imported WebAuthn/U2F credentials and attestation policy; fresh AuthMe passkey, TOTP, and one-use recovery-code enrollment is implemented;
- arbitrary SCIM extension schemas beyond the documented core Users/Groups model;
- Authorization Services/UMA 2 policy evaluation;
- byte-for-byte Keycloak realm JSON import fidelity; AuthMe provides a deterministic supported-subset transformation and compatibility report;
- not-before revocation policies, script mappers, and every historical protocol mapper.

## Compatibility validation

Every migration should run a client-by-client contract suite that compares:

1. discovery metadata and issuer;
2. authorization redirect/error behavior;
3. token signature, standard claims, audience, and role/group claims;
4. refresh and revocation behavior;
5. UserInfo and introspection authorization, response format, signature, issuer, audience, and type;
6. browser session and RP-initiated logout;
7. CORS and native-client redirect behavior where relevant.

The exact AuthMe deployment must also run the [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/). The upstream `oidc-provider` certification is strong evidence for its protocol engine, but it does not certify AuthMe's routes, adapter, interactions, or configuration.
