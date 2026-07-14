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

Supported grant permissions are `realms.read`, `configuration.read`, `users.read`, `users.write`, `users.delete`, `credentials.manage`, `sessions.revoke`, `federation.manage`, `clients.register`, `administrators.manage`, `audit.read`, and `metrics.read`; `*` is the wildcard. The bootstrap command creates the first realm administrator with a wildcard grant. There is not yet a grant-management API or approval workflow, so additional grant lifecycle changes remain a controlled operator procedure.

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

Passkey registration/deletion, other account-security changes, session revocation, and deletion commit their audit with the PostgreSQL mutation. User creation, unlock, and TOTP-enrollment start audit immediately after mutation; if one of those requests returns `5xx`, reconcile the resource before retrying because the mutation may have committed. The v0.3 administration plane does not yet provide grant CRUD/approval workflows, organization-scoped delegation, a transactional outbox, complete mutable client/group/role/policy administration, self-service credential recovery, or an account console.
