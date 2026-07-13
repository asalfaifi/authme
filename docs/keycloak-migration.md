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

AuthMe v0.2 can replace documented upstream OIDC federation, SP-initiated SAML IdP federation, LDAP/AD credential authentication, and core SCIM Users/Groups use cases. A source realm that serves SAML clients, uses Kerberos, encrypted/IdP-initiated SAML, LDAP synchronization, advanced SCIM, custom authenticators, portable existing WebAuthn credentials, Keycloak Authorization Services, organizations, or custom protocol mappers is not a full-cutover candidate. AuthMe implements fresh passkey/TOTP/recovery enrollment, but not automatic portability of existing Keycloak MFA credentials. Retain Keycloak when seamless credential preservation is mandatory.

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

1. direct v0.2 mapping;
2. transformable mapping;
3. staged/blocked;
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

For each Keycloak protocol mapper, write the expected claim name, source, type, scope, inclusion in ID/access/UserInfo responses, and audience. Map simple role/group/attribute cases to AuthMe's v0.2 claim policy. Mark scripts, custom SPIs, composite expansion, authorization-service permissions, and unsupported transforms as blockers.

## Phase 5: credentials

### Passwords

AuthMe v0.2 does not promise transparent import of Keycloak password hash records. Treat credential formats as sensitive, versioned implementation details. Choose one reviewed strategy:

1. **Password reset:** import accounts without a password and require a one-use reset through a verified channel. This is the simplest v0.2 strategy.
2. **Federated transition:** configure Keycloak as an upstream OIDC authority, use immutable-subject links or collision-safe JIT, and move users to a separate verified password-reset/re-enrollment workflow. The v0.2 broker does not receive or rehash the Keycloak password.
3. **Reviewed hash bridge:** implement a narrowly scoped verifier for the exact exported Keycloak algorithm/parameters, then replace it with AuthMe's current password hash after successful login. This requires its own threat model, test vectors, constant-time review, and removal plan.

Never downgrade the AuthMe password policy to accept plaintext or reversibly encrypted passwords. Never email temporary passwords.

### MFA, passkeys, recovery codes, and federated credentials

AuthMe v0.2 supports fresh passkey and TOTP enrollment and generates one-use recovery codes. It does not import Keycloak WebAuthn credential keys/counters, TOTP seeds, or recovery codes. Plan authenticated re-enrollment on the AuthMe origin and invalidate the source credential material. Federated links can be recreated through AuthMe's explicit administration API only after reconciling the exact provider issuer and immutable subject; never infer them from email. X.509 mappings have no v0.2 compatibility guarantee. Defer migration when existing passkeys must be retained without re-enrollment.

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
