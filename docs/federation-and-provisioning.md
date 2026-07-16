# Federation, directory authentication, and provisioning

AuthMe supports realm-scoped LDAP/Active Directory authentication and synchronization, upstream OpenID Connect federation, SAML 2.0 service-provider federation, and SCIM 2.0 Users/Groups provisioning. These integrations are disabled until their corresponding JSON configuration contains a provider or token for a realm.

All four JSON values contain credentials or trust material and belong in the runtime Secret, not the Helm ConfigMap, source control, image, or command-line history:

- `AUTHME_LDAP_PROVIDERS_JSON`
- `AUTHME_OIDC_PROVIDERS_JSON`
- `AUTHME_SAML_PROVIDERS_JSON`
- `AUTHME_SCIM_TOKENS_JSON`

Provider IDs are stable identifiers. Do not reuse an ID for a different authority. AuthMe keys external identities by realm, provider ID, canonical issuer, and immutable upstream subject. Matching email addresses or usernames never auto-link accounts; an administrator must explicitly link a collision.

## LDAP and Active Directory

LDAP authenticates the supplied password by finding exactly one directory entry with a service bind and then binding a separate connection as that entry. Search filters are escaped, searches are bounded to two results, all operations have timeouts, and production connections require LDAPS or StartTLS with certificate validation.

Example:

```json
{
  "master": [{
    "id": "corporate-directory",
    "display_name": "Corporate directory",
    "url": "ldaps://directory.example.com:636",
    "ca_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "bind_dn": "cn=authme,ou=services,dc=example,dc=com",
    "bind_password": "injected-from-secret-manager",
    "user_base_dn": "ou=people,dc=example,dc=com",
    "user_object_class": "person",
    "login_attributes": ["uid", "mail", "userPrincipalName", "sAMAccountName"],
    "username_attribute": "uid",
    "email_attribute": "mail",
    "external_id_attribute": "entryUUID",
    "binary_attributes": [],
    "groups_attribute": "memberOf",
    "sync_enabled": true,
    "sync_filter": "(employeeType=employee)",
    "sync_page_size": 200,
    "sync_groups": true,
    "sync_deletion_policy": "disable",
    "sync_max_deprovision_fraction": 0.2,
    "sync_max_deprovision_count": 100,
    "jit_provisioning": false
  }]
}
```

For Active Directory, choose an immutable external ID such as `objectGUID`; for standards-oriented LDAP servers, `entryUUID` is the usual choice. Text attributes remain text in the external identity key. List an attribute in `binary_attributes` only when the directory schema defines it as binary; AuthMe then requests raw bytes and base64url-encodes them in both synchronization and interactive authentication. For example, an AD configuration using `objectGUID` should set `"binary_attributes": ["objectGUID"]`, while textual `entryUUID` must not be listed. Interactive credential authentication can fall back to a DN when the configured attribute is absent, but synchronization requires a non-empty `external_id_attribute` on every returned entry and fails the run before deletion reconciliation if one is missing. This prevents moves and renames from creating duplicate AuthMe users. When `jit_provisioning` is false, pre-link the external subject through the administration API. When it is true, AuthMe can create a new account only if its username and email do not collide with an existing account.

Plain `ldap://` is accepted only with `start_tls: true`. An insecure loopback exception requires both development mode and `allow_insecure_development: true`; it cannot be enabled in production.

### Import and synchronization

`sync_enabled` is an independent opt-in from interactive JIT. The synchronizer searches `user_base_dn` with subtree scope and combines `(objectClass=<user_object_class>)` with the optional operator-supplied `sync_filter`. It requests only mapped attributes and streams pages through `ldapts`; `sync_page_size` accepts 1–1000 and defaults to 200. Search referrals are not followed because a partial authority view is unsafe for deletion reconciliation.

Mapped name and email fields are updated only on the user already identified by the immutable external subject. `sync_groups: true` makes `groups_attribute` authoritative for the user's AuthMe group paths; setting it to false leaves existing group assignments untouched and creates new directory users without groups. A configured `roles_attribute` similarly makes its values authoritative for realm roles. Username/email collisions are reported in the run count and never auto-linked.

After every page completes, links that existed when the run began but were not observed are considered for reconciliation. `sync_deletion_policy: "disable"` disables the AuthMe account and records this provider as the disable owner. A later observed entry re-enables the account only when that same provider's sync disabled it; an administrator or another source always retains control of its disable decision.

`sync_deletion_policy: "delete"` hard-deletes only an account created by this provider's sync that still has exactly one federated link and has no local password, TOTP/recovery/passkey credential, or administrator grant. Every other candidate is downgraded to disable and counted in `deletionRefused`, so a directory run cannot cascade-delete local credentials, grants, or other identity links.

Reconciliation fails safe when the scan returns zero entries. It also returns `needs_confirmation` without deprovisioning when the missing set exceeds either `sync_max_deprovision_fraction` of the provider's existing links or `sync_max_deprovision_count`. The defaults are 20% and 100 accounts. The JSON result reports the reason plus existing/candidate counts, and the CLI exits nonzero. Directory, TLS, bind, paging, invalid-entry, or pre-reconciliation database failures also skip the deletion phase; successfully committed earlier entry updates remain safe to replay on the next run. Each permitted disable/delete is its own transaction, so a reconciliation failure resumes safely.

Run one realm explicitly, optionally narrowing it to one provider:

```sh
npm run ldap:sync -- --realm master --provider corporate-directory
```

The command requires PostgreSQL and the normal AuthMe production configuration. It emits one credential-free JSON summary per provider and exits nonzero for an outage, local failure, overlapping run, or reconciliation requiring confirmation. See the scheduling and recovery runbook in [production.md](production.md).

## Upstream OpenID Connect / OAuth

AuthMe acts as an OAuth 2.0 Authorization Code + PKCE client to a fixed upstream OpenID Provider. Endpoints are configured explicitly and must use HTTPS outside development loopback; redirects are not followed. The callback validates state, issuer, nonce, signature, algorithm, audience, authorized party, UserInfo subject, and the exact provider-bound callback URL.

```json
{
  "master": [{
    "id": "workforce",
    "display_name": "Workforce SSO",
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
    "token_endpoint": "https://idp.example.com/oauth2/token",
    "jwks_uri": "https://idp.example.com/oauth2/jwks",
    "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
    "client_id": "authme",
    "client_secret": "injected-from-secret-manager",
    "token_endpoint_auth_method": "client_secret_basic",
    "scopes": ["openid", "profile", "email"],
    "signing_algorithms": ["RS256", "PS256", "ES256"],
    "require_issuer_parameter": true,
    "jit_provisioning": false
  }]
}
```

Register this exact callback at the upstream provider:

```text
https://auth.example.com/realms/master/federation/builtin.oidc-federation/workforce/callback
```

This surface is upstream identity federation. AuthMe's downstream OAuth/OIDC authorization-server endpoints remain the endpoints published in realm discovery.

## SAML 2.0 federation

AuthMe is a SAML service provider for SP-initiated sign-in. It generates an AuthnRequest, binds one-use RelayState to the active downstream OIDC interaction, and accepts an HTTP-POST response only at the provider-specific ACS. Both the SAML Response and Assertion must be signed by a configured IdP certificate. Destination, recipient, `InResponseTo`, issuer, audience, time conditions, subject confirmation, response ID, and assertion ID are checked; replay records are durable across replicas.

```json
{
  "master": [{
    "id": "corporate-saml",
    "display_name": "Corporate SAML",
    "idp_entity_id": "https://idp.example.com/saml/metadata",
    "idp_sso_url": "https://idp.example.com/saml/sso",
    "idp_signing_certificates": [
      "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    ],
    "attribute_mapping": {
      "username": "uid",
      "email": "mail",
      "groups": ["groups", "memberOf"],
      "roles": "roles"
    },
    "trust_email": false,
    "jit_provisioning": false
  }]
}
```

Give the IdP the generated metadata URL:

```text
https://auth.example.com/realms/master/federation/builtin.saml-federation/corporate-saml/metadata
```

The ACS is:

```text
https://auth.example.com/realms/master/federation/builtin.saml-federation/corporate-saml/acs
```

SP request/metadata signing can be enabled with `sp_signing_private_key` plus `sp_signing_certificates`. AuthMe currently supports signed SAML responses/assertions, not encrypted assertions, IdP-initiated login, single logout, artifact binding, or operating as a SAML IdP.

## Explicit account linking

List, create, or remove links with the root-protected administration API:

```text
GET    /admin/v1/realms/{realm}/users/{userId}/federated-identities
POST   /admin/v1/realms/{realm}/users/{userId}/federated-identities
DELETE /admin/v1/realms/{realm}/users/{userId}/federated-identities
```

The POST body contains the exact configured `providerId` and `issuer` plus the immutable `externalSubject`. The DELETE body contains `providerId` and `issuer`. For LDAP the issuer is the configured directory URL, for OIDC it is the provider issuer, and for SAML it is the IdP entity ID.

## SCIM 2.0

SCIM requires PostgreSQL even in development mode. Configure independent high-entropy bearer tokens per realm and rotate them through the deployment secret:

```json
{
  "master": [{
    "id": "hr-provisioner",
    "token": "at-least-32-bytes-from-a-cryptographic-random-generator"
  }]
}
```

The realm base URL is:

```text
https://auth.example.com/scim/v2/realms/master
```

AuthMe publishes `ServiceProviderConfig`, `Schemas`, `ResourceTypes`, `Users`, and `Groups`. Users and groups support create, read, replace, patch, delete, `eq` filters on the advertised core fields, pagination, weak ETags, `If-Match`, and `If-None-Match`. Password input is immediately hashed and is never returned. Identity and membership changes advance account security state and revoke affected sessions/grants.

The current SCIM profile does not implement Bulk, sorting, `/Me`, arbitrary extension schemas, or the complete RFC filter grammar. SCIM mutation and application-audit persistence are sequential rather than a single transaction; reconcile the resource before retrying an ambiguous `5xx`.

## Extension boundary and remaining mechanisms

Built-in mechanisms register through the versioned `authme.identity/v1` extension contract as authenticator, federation, or provisioning modules. The registry exposes realm capability discovery and keeps protocol-specific code outside the OIDC core. It is a compile-time trusted-code boundary, not a facility for loading unreviewed JavaScript at runtime.

There is no finite, safe interpretation of “every authentication mechanism.” This release covers passwords, TOTP, recovery codes, WebAuthn/passkeys, LDAP/Active Directory credential validation and synchronization, OIDC/OAuth federation, SAML federation, and SCIM provisioning. Kerberos/SPNEGO, RADIUS, X.509 authentication, email/SMS OTP and magic links, proprietary social-provider presets, SAML IdP operation, LDAP server-side delta/change-log controls, encrypted SAML assertions, and arbitrary runtime plugins remain outside the implemented contract until each receives storage, interaction, threat-model, interoperability, and operational release gates.
