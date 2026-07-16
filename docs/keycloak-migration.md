# Migrating from Keycloak

## Migration principles

A Keycloak-to-AuthMe migration is an issuer and identity migration, not merely a database copy. Plan it as a controlled security change with parallel validation, a rollback window, and an explicit decision for every unsupported Keycloak feature.

Do not point AuthMe at the Keycloak database. The schemas, credential representations, lifecycle rules, and extension models are internal implementation details. Extract through supported Keycloak exports and APIs, transform into AuthMe's model, and validate before cutover. Keycloak documents realm administration and its APIs in the [Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/) and [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html).

## Preconditions

Before scheduling a cutover:

- The required use cases appear as **Implemented** in [keycloak-compatibility.md](keycloak-compatibility.md).
- The target AuthMe release passes its tests and the release gates in [roadmap.md](roadmap.md).
- A production-like compatibility environment uses the intended hostname, proxy, TLS, database, and signing-key configuration.
- Backup and rollback procedures have been exercised.
- Realm owners approve the password/credential migration strategy.
- Every relying party has an owner and a test result.

AuthMe v1.0.0-rc.1 can replace the documented OIDC, SAML SP/IdP, LDAP/AD authentication and synchronization, SCIM core/Bulk/filtering, organization, native administration/account, and supported claim-mapping use cases. A source realm that depends on Kerberos, SAML artifact binding or broker-side decryption, custom authenticator/script mapper SPIs, portable existing WebAuthn credentials, Keycloak Authorization Services, Admin REST wire compatibility, or multi-site active/active writes is not a full-cutover candidate. AuthMe implements fresh passkey/TOTP/recovery enrollment, but not automatic portability of existing Keycloak MFA credentials. Retain Keycloak when seamless credential preservation is mandatory.

## Phase 1: inventory

Capture the source version and, per realm:

- public frontend/issuer URL;
- users, enabled state, verified email state, attributes, and stable Keycloak user ID;
- groups, hierarchy, memberships, realm roles, client roles, composites, and defaults;
- OIDC/SAML clients, client type, secrets/keys, redirects, web origins, scopes, mappers, flows, and service accounts;
- active sessions, offline sessions, consents, and not-before policies;
- password policy, OTP/WebAuthn credentials, required actions, registration and email flows;
- identity providers, LDAP/AD/Kerberos providers, and custom SPIs/themes;
- token algorithms, lifetimes, audiences, pairwise-subject behavior, and custom claims;
- automation using Admin REST, `kcadm`, events, or database queries.

Classify each item as:

1. direct v1.0 mapping;
2. transformable mapping;
3. unsupported/blocked;
4. intentionally retired.

Unowned clients are a migration blocker, not an invitation to assume compatibility.

## Phase 2: choose the public issuer strategy

### Preserve the issuer

The lowest-change cutover gives AuthMe the exact public issuer previously used by Keycloak:

```text
https://login.example.com/realms/acme
```

This requires transferring DNS/load-balancer routing at cutover. Discovery and every token's `iss` claim must remain exactly that value. Preserving the issuer reduces client changes but increases cutover coordination.

### Change the issuer

If AuthMe uses a new hostname or realm path, every relying party and resource server must be updated to trust the new issuer. Tokens from Keycloak and AuthMe are from different security domains even if their users and signing keys look similar. Run both issuers during a bounded transition only when applications intentionally support both.

Never reuse the Keycloak signing private key merely to make a changed issuer appear equivalent. Issuer validation is mandatory.

## Phase 3: preserve subject identity

The OIDC `sub` claim is an application's stable user identifier. Changing it can create duplicate accounts or attach data to the wrong person.

Recommended mapping:

- store the Keycloak user UUID as an immutable migration/external identifier;
- configure the AuthMe subject for migrated users to remain stable where AuthMe's subject policy permits;
- create an explicit old-issuer/old-sub to new-issuer/new-sub mapping when the issuer changes;
- never match or merge accounts solely by mutable email address;
- test pairwise-subject clients separately.

Export this mapping, protect it as personal/security data, and retain it for rollback and reconciliation.

## Phase 4: extract and transform

Use an offline, repeatable migration program. Inputs and transformed outputs must be checksummed and access-controlled. The transform should be idempotent and produce a reconciliation report rather than silently skipping invalid records.

### Realm-export transformation tool

`scripts/kc-import.mjs` transforms one JSON realm representation produced by
`kc.sh export` or Keycloak's partial-export API. It is an offline planning tool:
it does not connect to Keycloak, modify AuthMe, import users into PostgreSQL, or
copy signing keys. Supply the exact future AuthMe origin when the export does
not contain a usable realm `frontendUrl`:

```bash
# Dry run (the default): combined config/report JSON on stdout and text report on stderr.
node scripts/kc-import.mjs ./acme-realm.json \
  --public-url https://login.example.com \
  >./acme-review.json 2>./acme-review.txt

# Write separate files. Existing files are never overwritten.
node scripts/kc-import.mjs ./acme-realm.json \
  --public-url https://login.example.com \
  --write
```

The write form creates `acme-realm.authme.json`,
`acme-realm.compatibility.json`, and `acme-realm.compatibility.txt` beside the
input. Use `--config-out`, `--report-out`, and `--human-report-out` to choose
other paths. `--issuer` can replace `--public-url`, but it must be the exact
AuthMe issuer ending in `/realms/{realm}` with no path prefix. Run `--help` for
the complete syntax.

The AuthMe artifact contains:

- realm name, display name, issuer, and the compatible token/session lifetimes;
- static OIDC clients using the fields accepted by `AUTHME_CLIENTS_JSON`;
- realm/client role inventories, flattened groups, users, and federated links;
- raw LDAP, upstream OIDC, and upstream SAML provider entries matching the
  corresponding `AUTHME_*_PROVIDERS_JSON` input shapes;
- an `environment` object whose `*_JSON` values are structured JSON and must be
  serialized when placed in environment variables.

The artifact is deterministic for identical input and options. It has no
generation timestamp, random identifier, or input-order-dependent report
ordering. A missing/non-UUID Keycloak user ID is replaced with a deterministic
realm-and-username UUID and reported as a subject-continuity warning. Prefer a
full export with the original UUIDs.

Treat both input and config output as restricted identity data. The transformer
does not copy Keycloak client secrets, password hashes, OTP/passkey material,
LDAP bind credentials, IdP client secrets, SMTP credentials, or private keys.
It emits `__ROTATE__` where an otherwise mappable integration requires a new
secret; this value is intentionally too short for AuthMe's production static
client policy. Replace every placeholder through the approved secret channel
before validation or deployment. Reports contain identifiers, source paths,
classifications, and fixed reasons, never source values or secret/key material.

Malformed structure, duplicate identifiers, invalid realm names, and invalid
field types fail the whole transformation with a source path. Unsupported
features are omitted or conservatively transformed and appear in both reports;
an item absent from the report must still be reviewed under the migration
release gates. Partial exports are accepted, but unresolved group paths and
missing source user UUIDs are explicit warnings.

### Transformer compatibility matrix

| Keycloak export item | AuthMe transformation | Classification/required review |
|---|---|---|
| Realm and frontend URL | Lowercase AuthMe realm plus `/realms/{realm}` issuer | Direct when an origin is supplied/present; otherwise issuer warning |
| Access-token/code lifetimes | `AUTHME_ACCESS_TOKEN_TTL_SECONDS` and `AUTHME_AUTHORIZATION_CODE_TTL_SECONDS` | Direct only inside AuthMe's configured ranges |
| SSO idle timeout | `AUTHME_SESSION_TTL_SECONDS` | Warning: Keycloak idle/max/offline policies have different semantics |
| Enabled OIDC public client | `none`, exact redirects/origins, Authorization Code, PKCE `S256` | Direct/warning; every code client must use `S256` |
| Enabled confidential secret client | `client_secret_basic` or supported `client_secret_jwt` metadata | Warning; source secret omitted and rotation required |
| `private_key_jwt` client | Supported algorithm plus exact HTTPS public `jwks_uri` | Direct only with RS256, PS256, or ES256 and usable public JWKS URI |
| Service account | Client Credentials grant | Client grant maps; service-account user/policy needs reconciliation |
| Device grant / CIBA poll | Corresponding AuthMe grant metadata | Direct where source metadata and client authentication are compatible |
| Wildcard/relative redirect or web origin | Not emitted | Unsupported/skipped; replace with reviewed exact URI/origin |
| Direct Access Grant / implicit flow | Not emitted | Unsupported |
| Disabled, bearer-only, SAML, or reserved client | Not emitted as a static OIDC client | Unsupported/skipped; bearer APIs need explicit resource-server policy |
| Realm and client roles | Separate role inventories and user namespaces | Direct for portable role names |
| Composite role | Role name retained; transformer does not emit the composite graph | Warning; create/reconcile the graph through the mutable role API before cutover |
| Nested group | Canonical flattened path such as `/engineering/platform` | Direct path mapping |
| Group role mapping | Retained on group and materialized onto affected users, including ancestors | Warning; AuthMe emits flat user entitlements |
| User profile and assignments | AuthMe user fields, safe attributes, roles, group paths, client roles | Direct; email required and normalized lowercase |
| Password/TOTP/WebAuthn/recovery credential | Transition status only; no credential material | Unsupported/skipped; reset or fresh enrollment required |
| OIDC identity provider | Fixed endpoints, claim names, JIT policy | Warning; new upstream client secret required |
| SAML identity provider | Entity ID, SSO URL, signing certificate, simple attribute mappings | Direct only when complete; advanced/encrypted/IdP-initiated behavior unsupported |
| LDAP provider | TLS endpoint and direct profile attributes | Warning; rotate bind credentials and separately configure/rehearse synchronization policy |
| Role/group and direct profile mapper | Built-in AuthMe claim/profile behavior | Direct where claim semantics match |
| Script, hardcoded, audience, custom, or transform mapper | Not emitted by transformer | Map supported hardcoded/attribute/role/group/organization cases through the claim-mapper API; scripts/custom transforms remain unsupported |
| Sessions, tokens, initial-access tokens, authentication flows, required actions, organizations | Not emitted | Runtime state is intentionally skipped; recreate reviewed flows/organizations through the native API |

Suggested order:

1. realms and immutable identifiers;
2. clients, exact redirect/post-logout URIs, origins, and authentication methods;
3. realm roles and client roles;
4. groups and hierarchy;
5. users and profile attributes;
6. group memberships and role assignments;
7. service-account assignments;
8. approved consents, only if their semantics are identical;
9. credential transition records according to the selected strategy.

Do not import active authorization codes, access tokens, refresh tokens, browser sessions, device codes, login failures, or provider caches. They are ephemeral and coupled to Keycloak's runtime. Users should expect to authenticate again after cutover.

### Claim mapper transformation

For each Keycloak protocol mapper, write the expected claim name, source, type, scope, inclusion in ID/access/UserInfo responses, and audience. Map hardcoded, user-attribute, role, group, and organization cases to AuthMe client/client-scope claim mappers. Recreate and test composite-role graphs separately. Mark scripts, custom SPIs, authorization-service permissions, and unsupported transforms as blockers.

## Phase 5: credentials

### Passwords

AuthMe v1.0 does not promise transparent import of Keycloak password hash records. Treat credential formats as sensitive, versioned implementation details. Choose one reviewed strategy:

1. **Password reset:** import accounts without a password and require a one-use reset through a verified channel. This is the simplest strategy.
2. **Federated transition:** configure Keycloak as an upstream OIDC authority, use immutable-subject links or collision-safe JIT, and move users to a separate verified password-reset/re-enrollment workflow. The broker does not receive or rehash the Keycloak password.
3. **Reviewed hash bridge:** implement a narrowly scoped verifier for the exact exported Keycloak algorithm/parameters, then replace it with AuthMe's current password hash after successful login. This requires its own threat model, test vectors, constant-time review, and removal plan.

Never downgrade the AuthMe password policy to accept plaintext or reversibly encrypted passwords. Never email temporary passwords.

### MFA, passkeys, recovery codes, and federated credentials

AuthMe supports fresh passkey and TOTP enrollment and generates one-use recovery codes. It does not import Keycloak WebAuthn credential keys/counters, TOTP seeds, or recovery codes. Plan authenticated re-enrollment on the AuthMe origin and invalidate the source credential material. Federated links can be recreated through AuthMe's explicit administration API only after reconciling the exact provider issuer and immutable subject; never infer them from email. X.509 mappings have no compatibility guarantee. Defer migration when existing passkeys must be retained without re-enrollment.

### Client secrets

Rotate confidential-client secrets during migration whenever possible. Distribute them through the existing secret-management channel. Do not place source or target secrets in realm export artifacts retained for general troubleshooting.

## Phase 6: rehearsal

Perform at least one full rehearsal from a fresh source export into a fresh AuthMe database.

Reconcile counts and references:

- enabled/disabled users;
- unique usernames/emails according to realm policy;
- clients by type;
- redirect and post-logout URIs;
- roles, groups, memberships, and assignments;
- service accounts;
- imported/blocked claim mappings;
- credential transition state.

Run representative relying-party journeys:

- browser authorization with PKCE;
- server-side confidential client;
- native/public client where supported;
- service-to-service Client Credentials;
- refresh, revocation, UserInfo, introspection, RP/back-channel logout;
- device authorization, PAR, and DPoP for clients that use them;
- dynamic registration with a short-lived initial access token and invalid/expired-token negative cases;
- TOTP enrollment/login and one-time recovery-code consumption;
- role/group authorization;
- disabled user/client and invalid redirect negative cases.

Compare discovery and token claims semantically. Do not compare token strings or JSON member order.

## Phase 7: cutover

1. Announce an authentication maintenance window and user impact.
2. Stop or tightly control identity/client/role changes in Keycloak.
3. Take the final supported export and a protected rollback backup.
4. Run the idempotent migration and reconciliation.
5. Start AuthMe in a non-ready state; validate database, keys, realm issuer, and discovery locally.
6. Switch ingress/DNS according to the issuer strategy.
7. Admit readiness and run synthetic login, token, refresh, service-account, and logout probes.
8. Monitor authentication failures, invalid clients/redirects, token validation failures, database saturation, throttling, and support reports.
9. Keep Keycloak isolated but recoverable during the approved rollback window. Do not let both systems accept conflicting administrative changes.

Existing Keycloak sessions and tokens should be allowed only according to a deliberate dual-trust plan. The simpler safe model is to invalidate old sessions and require login at AuthMe.

## Rollback

Define rollback triggers before cutover, such as:

- token validation failure for a critical client;
- unexplained cross-realm/claim discrepancies;
- sustained authentication failure above threshold;
- database corruption or migration reconciliation failure;
- inability to issue or verify tokens across replicas.

Rollback restores routing to Keycloak and stops AuthMe writes. Reconcile any user or client changes made after cutover before attempting again. A rollback is unsafe if both providers independently accepted password resets or administrative changes without a merge plan.

## Post-cutover

- Revoke unused Keycloak and migration credentials.
- Rotate migration service credentials and temporary client secrets.
- Complete password/MFA enrollment and remove transitional verifiers.
- Archive exports under the approved retention policy, then securely delete them.
- Review audit and failure trends.
- Obtain application-owner signoff.
- Retire Keycloak only after the rollback window, backup requirements, and legal retention obligations are satisfied.

## Migration release gates

- No unclassified source feature or client.
- Stable issuer and subject mapping reviewed.
- Rehearsal is reproducible from clean databases.
- Counts and referential reconciliation pass.
- Every critical relying party passes its compatibility suite.
- OpenID conformance passes for the release configuration.
- Password and MFA transition is approved and communicated.
- Backup restore and rollback rehearsals pass.
- Security review approves migration tooling and export handling.
