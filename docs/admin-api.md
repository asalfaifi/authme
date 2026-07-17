# Administration API

AuthMe exposes a secure web console at `/admin/` and a small, versioned operator API below `/admin/v1`. The API is not Keycloak Admin REST compatible. Both surfaces use the same audited realm operations, but their credentials and authorization boundaries are deliberately separate.

## Administration console

The console is an AuthMe relying party with the reserved client ID `authme-admin-console`. Sign-in uses Authorization Code with PKCE `S256`, state, nonce, a short-lived signed login transaction, and an exact callback at `/admin/oidc/callback`. The authenticated identity must also have an enabled durable administrator grant in the selected realm.

Production console access requires authentication within the preceding 15 minutes at LoA2: a user-verified passkey, or password plus TOTP/recovery code. Development mode permits password-only console login for local testing. After production bootstrap, use the root automation API over a restricted channel to enroll and confirm TOTP before the administrator's first console login.

The resulting console cookie is an opaque 32-byte bearer value. It is `Secure` in production, `HttpOnly`, `SameSite=Strict`, and scoped to `/admin`. Only an HMAC digest is stored in the durable `admin_sessions` table. Sessions have a maximum eight-hour absolute lifetime, a maximum 30-minute idle lifetime, and snapshots of both the user security version and administrator-grant version. Logout deletes the durable record. Disabling or changing the user, changing/revoking the grant, expiry, or deletion also invalidates the session.

`GET /admin/ui/session` returns the selected realm, safe administrator profile, granted permissions, and a session-bound CSRF value. Console API calls are restricted to that realm. Unsafe requests require all of:

- the exact `AUTHME_PUBLIC_URL` Origin;
- `Content-Type: application/json`;
- the CSRF value in `X-AuthMe-CSRF`;
- the permission associated with the operation.

Switching realm starts a new OIDC authorization and creates a new realm-bound console session. The console never receives `AUTHME_ADMIN_TOKEN` and does not place credentials in HTML, URLs, JavaScript, or browser storage.

Supported grant permissions are `realms.read`, `realms.manage`, `configuration.read`, `clients.read`, `clients.manage`, `roles.manage`, `groups.manage`, `client-scopes.manage`, `authentication-flows.manage`, `organizations.manage`, `signing-keys.manage`, `users.read`, `users.write`, `users.delete`, `credentials.manage`, `sessions.revoke`, `federation.manage`, `clients.register`, `administrators.manage`, `audit.read`, and `metrics.read`; `*` is the wildcard. The bootstrap command creates the first realm administrator with a wildcard grant. There is not yet an approval workflow, so additional grant lifecycle changes remain a controlled operator procedure.

All cookie-session mutations require authentication no more than 15 minutes old. Accounts that already have an administrator grant are additionally protected: password, MFA, passkey, federation, profile, session, and deletion changes require `administrators.manage`, so a narrowly scoped credential operator cannot take over a more privileged administrator. Root automation remains the reviewed break-glass path.

## Root automation authentication

Trusted non-browser automation uses the independent, deployment-wide root credential:

```http
Authorization: Bearer <AUTHME_ADMIN_TOKEN>
```

The root bearer is not a console session and is not reduced by realm grant permissions. Do not put it in a browser, local storage, a URL, or an ordinary application backend. Keep it in secret management, rotate it independently, and restrict `/admin` at the ingress or network-policy layer. Successful and failed responses use `Cache-Control: no-store`; validation and authorization failures use `application/problem+json`.

User identifiers are UUIDs. List endpoints accept decimal `limit` (1–250, default 100) and `offset` (0–10,000,000, default 0); malformed values are rejected instead of silently coerced.

## Realm and user operations

| Method | Path | Result |
|---|---|---|
| `GET` | `/admin/v1/realms` | Configured realm names and issuers |
| `GET` | `/admin/v1/realms/{realm}` | Read mutable realm display/status/settings metadata |
| `PATCH` | `/admin/v1/realms/{realm}` | Change display name, enabled state, or settings; realm slug and issuer remain immutable |
| `GET` | `/admin/v1/realms/{realm}/configuration` | Sanitized, read-only realm configuration catalog |
| `GET` | `/admin/v1/realms/{realm}/users` | Paginated public user records |
| `POST` | `/admin/v1/realms/{realm}/users` | Create a user and password |
| `GET` | `/admin/v1/realms/{realm}/users/{id}` | Read a public user record |
| `PATCH` | `/admin/v1/realms/{realm}/users/{id}` | Change profile, status, roles, or groups and invalidate account state |
| `PUT` | `/admin/v1/realms/{realm}/users/{id}/password` | Reset the password, unlock the account, and invalidate account state |
| `POST` | `/admin/v1/realms/{realm}/users/{id}/unlock` | Clear lockout counters |
| `POST` | `/admin/v1/realms/{realm}/users/{id}/sessions/revoke` | Revoke the account's sessions, grants, and grant-linked artifacts |
| `GET` | `/admin/v1/realms/{realm}/users/{id}/federated-identities` | List external identity links without credentials or assertions |
| `POST` | `/admin/v1/realms/{realm}/users/{id}/federated-identities` | Explicitly link an immutable subject from an enabled provider |
| `DELETE` | `/admin/v1/realms/{realm}/users/{id}/federated-identities` | Remove the link selected by `providerId` and exact `issuer` in the JSON body |
| `DELETE` | `/admin/v1/realms/{realm}/users/{id}` | Delete the user and account-bound provider state; repeated deletes return `204` |

Session revocation increments the account security epoch and deletes current account/grant artifacts atomically in PostgreSQL. An artifact carrying an old epoch is rejected even if a stale copy survives outside the normal deletion path.

Audience-bound JWT access tokens already issued to offline resource servers cannot be recalled from those validators and remain valid until their short expiration unless the resource server maintains a denylist. Use opaque resource tokens when immediate online introspection/revocation is required.

Deletion is realm-scoped and idempotent. The first successful deletion writes `admin.user.deleted`; retries do not create duplicate deletion audit events.

The configuration catalog returns the realm issuer, deployment/storage mode, Redis and dynamic-registration status, TTLs, safe client/resource-server metadata, federation provider metadata, SCIM token identifiers, and extension capabilities. It deliberately excludes client secrets, LDAP bind credentials, upstream client secrets, SAML private keys, SCIM bearer values, private JWK members, cookie/CSRF/password/encryption secrets, and the root token. Treat even this sanitized catalog as privileged operational metadata.

## Tenant realms and application registration

`AUTHME_REALMS` defines the deployment's immutable issuer set. Every configured realm receives a separate provider, issuer, user namespace, client namespace, session/grant namespace, signing-key inventory, federation catalog, audit stream, and administrator login. The console lists all realms visible to the administrator and switching realms performs a new Authorization Code + PKCE login rather than reusing another realm's session.

An OIDC client may set the AuthMe extension metadata `allow_user_registration: true`. During that client's login interaction, AuthMe then offers local account creation in the current realm. The option defaults to false, is not inherited between realms, and is suppressed when an organization context is requested. Registration requires an interaction-bound CSRF token, is independently rate-limited, applies the normal password policy and uniqueness constraints, records `identity.registration.succeeded`, and signs the new account in only when the client's authentication flow accepts password LoA1. AuthMe never silently creates an account from unverified client input.

## Client and authorization-model operations

| Resource | Operations | Notes |
|---|---|---|
| `/realms/{realm}/clients[/{clientId}]` | `GET`, collection `POST`, item `PUT`/`DELETE` | Full OIDC client metadata is validated by the same security policy as startup. Secrets are never returned. Static and reserved clients are immutable. Delete revokes client grants and protocol artifacts. |
| `/realms/{realm}/clients/{clientId}/roles[/{roleName}]` | `GET`, item `PUT`/`DELETE` | Realm-scoped client-role catalog with same-client composite expansion. Deletion reconciles user assignments and dependent composites. |
| `/realms/{realm}/roles[/{roleName}]` | `GET`, item `PUT`/`DELETE` | Supports attributes and composite roles; missing references and cycles are rejected. |
| `/realms/{realm}/groups[/{groupId}]` | `GET`, collection `POST`, item `PATCH`/`DELETE` | Supports parent IDs, canonical paths, existing-role assignment, and cycle prevention. Rename/move rewrites affected user paths and revokes stale sessions. A group with children must be reconciled before deletion. |
| `/realms/{realm}/client-scopes[/{scopeId}]` | `GET`, collection `POST`, item `PATCH`/`DELETE` | Reusable OIDC client scopes. |
| `/realms/{realm}/clients/{clientId}/client-scopes[/{scopeId}]` | `GET`, item `PUT`/`DELETE` | Assign an existing scope to an existing client as `default` or `optional`. |
| `/realms/{realm}/claim-mappers[/{mapperId}]` | `GET`, collection `POST`, item `PATCH`/`DELETE` | Existing-client- or existing-client-scope-owned hardcoded/user-attribute/role/group/organization mappers. |
| `/realms/{realm}/authentication-flows[/{flowId}]` | `GET`, collection `POST`, item `PATCH`/`DELETE` | Required password/passkey/federation primary method; optional password+TOTP required/conditional composition; or alternative primary methods. Requested ACR preference order selects an exact matching custom flow; otherwise the priority default applies only when no ACR was requested, preserving built-in LoA values. Client, AMR, and maximum-age policy are enforced on new and existing sessions. Unexecutable mixed definitions are rejected. |

All paths in this table are below `/admin/v1`. Mutations are realm-scoped and audited. User realm-role, client-role, and group assignments, mapper owners, scope assignments, and flow client references must resolve within the same realm. User creates and updates revalidate those relationships after writing and roll back if concurrent policy deletion made a pre-check stale. A newly stored client is visible to the protocol provider without a restart; deleting it invalidates further client use immediately and atomically removes its scopes, mappers, roles, client-only flow bindings, user role assignments, and affected account grants in PostgreSQL. Deleting a dynamically registered client through its standards registration-management URI performs the same reconciliation and refreshes discovery metadata. Client creation/replacement/deletion and concurrent role, scope-assignment, mapper, and flow writes are serialized with the same owner lifecycle; writes fail closed if the owner disappears, and replacement cannot resurrect a deleted client. Multi-client flow bindings drop the deleted client without becoming global. Client-scope and authentication-flow mutations update discovery metadata immediately.

## Organization and signing-key operations

| Method | Path | Result |
|---|---|---|
| `GET`/`POST` | `/admin/v1/realms/{realm}/organizations` | List or create organizations with non-UUID aliases, domains, IdP allowlists, and attributes |
| `GET`/`PATCH`/`DELETE` | `/admin/v1/realms/{realm}/organizations/{organizationId}` | Read, update, or remove one organization |
| `GET` | `/admin/v1/realms/{realm}/organizations/{organizationId}/members` | List memberships |
| `PUT`/`DELETE` | `/admin/v1/realms/{realm}/organizations/{organizationId}/members/{userId}` | Set membership roles or remove membership |
| `GET`/`POST` | `/admin/v1/realms/{realm}/organizations/{organizationId}/invitations` | List invitations or issue a single-use, email-bound invitation token |
| `DELETE` | `/admin/v1/realms/{realm}/organizations/{organizationId}/invitations/{invitationId}` | Revoke a pending invitation |
| `GET` | `/admin/v1/realms/{realm}/signing-keys` | List public-only active/retiring key inventory and provider references |
| `POST` | `/admin/v1/realms/{realm}/signing-keys/rotate` | Request an overlap-safe provider rotation; roll replicas after rotation |

Invitation plaintext is returned only at creation and is stored as a digest. Acceptance occurs through the authenticated account console, requires the invited email address and an enabled organization, and revokes prior account grants before the new membership is used. Acceptance locks the PostgreSQL user and organization lifecycle; if its audit cannot be committed, the invitation becomes usable again and the exact prior membership is restored. Membership and invitation writes fail closed if their organization or user lifecycle changes concurrently. User deletion cascades organization memberships and federation links; an audit failure restores the user and its memberships before any account grants are revoked. Membership, organization-authentication policy, disablement, and deletion changes revoke affected browser grants. Supplying an `organization` authorization parameter constrains tokens to a current enabled membership, and configured organization IdPs are enforced during federation.

Federated login never links by email or username. The link POST body is:

```json
{
  "providerId": "workforce",
  "issuer": "https://idp.example.com",
  "externalSubject": "immutable-upstream-subject"
}
```

The provider ID and issuer must exactly match an enabled LDAP, OIDC, or SAML provider in that realm. The DELETE body contains only `providerId` and `issuer`; one user can have at most one subject for that provider/issuer pair. These routes are root-equivalent and are audited. Confirm the upstream subject out of band before creating a link.

## MFA and audit operations

| Method | Path | Result |
|---|---|---|
| `POST` | `/admin/v1/realms/{realm}/users/{id}/mfa/totp` | Begin TOTP enrollment and return the one-time provisioning material |
| `POST` | `/admin/v1/realms/{realm}/users/{id}/mfa/totp/confirm` | Atomically confirm enrollment and return one-use recovery codes |
| `DELETE` | `/admin/v1/realms/{realm}/users/{id}/mfa/totp` | Remove TOTP/recovery credentials and invalidate account state |
| `POST` | `/admin/v1/realms/{realm}/users/{id}/passkeys/registration/options` | Create a short-lived, one-use registration ceremony |
| `POST` | `/admin/v1/realms/{realm}/users/{id}/passkeys/registration/verify` | Verify the authenticator response and register the credential |
| `GET` | `/admin/v1/realms/{realm}/users/{id}/passkeys` | List credential metadata without public keys, user handles, or counters |
| `DELETE` | `/admin/v1/realms/{realm}/users/{id}/passkeys/{credentialId}` | Remove one credential and invalidate account state |
| `GET` | `/admin/v1/realms/{realm}/audit` | Paginated realm audit events |
| `POST` | `/admin/v1/realms/{realm}/client-registration-tokens` | Issue a one-use dynamic-registration token when registration is enabled |
| `GET` | `/admin/metrics` | Prometheus metrics (root bearer, or a same-realm console session with `metrics.read`) |

MFA provisioning secrets and recovery codes are returned once. Treat the response as a secret and never log it. Passkey registration is a two-call WebAuthn ceremony: send the returned `publicKey` options to `navigator.credentials.create()` on the exact AuthMe origin, then submit its JSON response with `challengeId` and an optional `name`. A challenge is consumed on the first verification attempt, including a failed attempt. The AuthMe console can mediate this ceremony through its cookie session and CSRF boundary; other browser code must never receive `AUTHME_ADMIN_TOKEN`.

Passkey registration/deletion, other account-security changes, session revocation, and deletion commit their audit with the PostgreSQL mutation. User creation, unlock, and TOTP-enrollment start audit immediately after mutation; if one of those requests returns `5xx`, reconcile the resource before retrying because the mutation may have committed. AuthMe does not provide Keycloak Admin REST compatibility, arbitrary administrator approval workflows, or a general transactional outbox.
