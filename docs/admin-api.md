# Administration API

AuthMe exposes a small, versioned operator API below `/admin/v1`. It is intended for trusted automation on a restricted management network. It is not Keycloak Admin REST compatible and it is not yet a delegated administration plane.

## Authentication and response rules

Every request requires the deployment-wide root credential:

```http
Authorization: Bearer <AUTHME_ADMIN_TOKEN>
```

Do not put this token in a browser, local storage, a URL, or an ordinary application backend. Restrict `/admin` at the ingress or network-policy layer. Successful and failed responses use `Cache-Control: no-store`; validation and authorization failures use `application/problem+json`.

User identifiers are UUIDs. List endpoints accept decimal `limit` (1–250, default 100) and `offset` (0–10,000,000, default 0); malformed values are rejected instead of silently coerced.

## Realm and user operations

| Method | Path | Result |
|---|---|---|
| `GET` | `/admin/v1/realms` | Configured realm names and issuers |
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
| `GET` | `/admin/metrics` | Prometheus metrics (currently protected by the same root credential) |

MFA provisioning secrets and recovery codes are returned once. Treat the response as a secret and never log it. Passkey registration is a two-call WebAuthn ceremony: send the returned `publicKey` options to `navigator.credentials.create()` on the exact AuthMe origin, then submit its JSON response with `challengeId` and an optional `name`. A challenge is consumed on the first verification attempt, including a failed attempt. Do not expose `AUTHME_ADMIN_TOKEN` to browser code; a trusted same-origin enrollment service must mediate this admin-managed flow until a self-service account console exists.

Passkey registration/deletion, other account-security changes, session revocation, and deletion commit their audit with the PostgreSQL mutation. User creation, unlock, and TOTP-enrollment start audit immediately after mutation; if one of those requests returns `5xx`, reconcile the resource before retrying because the mutation may have committed. The v0.2 operator API does not yet provide administrator identities, realm-scoped RBAC, approvals, a transactional outbox, self-service credential recovery, or independently scoped metrics credentials.
