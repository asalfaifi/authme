# AuthMe

AuthMe is a standalone, multi-realm OpenID Connect identity server with Keycloak-shaped OIDC URLs. It provides a secure OIDC foundation—users, clients, sessions, consent, MFA, administration, audit, and deployment—without running or wrapping Keycloak.

> **Current status:** v0.3 is production-oriented, but it is not yet a complete replacement for every Keycloak feature and is not an independently OpenID-certified product. Read the exact [compatibility matrix](docs/keycloak-compatibility.md) before migrating a production realm.

AuthMe uses the current OpenID/FAPI-certified [`oidc-provider`](https://github.com/panva/node-oidc-provider) engine for standards-sensitive protocol and cryptographic behavior. The realm model, PostgreSQL adapter, identity store, interaction UI, MFA, administration API, audit system, hardening, deployment, and Keycloak migration layer are AuthMe.

## What works

- Realm issuers at `https://host/realms/{realm}` with Keycloak-compatible endpoint paths.
- Authorization Code with mandatory PKCE `S256`; implicit and password grants are excluded.
- Short-lived access tokens, rotating refresh tokens, and token-family revocation on replay.
- Client Credentials, Device Authorization, PAR, DPoP, UserInfo, introspection, revocation, RP-initiated logout, and back-channel logout.
- PostgreSQL-backed provider state with atomic one-use artifact consumption and realm isolation.
- Argon2id passwords, account lockout, TOTP replay prevention, one-use recovery codes, and user-verified WebAuthn passkeys.
- Realm-scoped LDAP/Active Directory authentication with LDAPS/StartTLS, bounded searches, configurable mappings, and collision-safe JIT provisioning.
- Upstream OpenID Connect federation with Authorization Code + PKCE and strict state, nonce, issuer, signature, audience, and callback validation.
- SAML 2.0 SP federation with signed Response/Assertion validation, exact audience/recipient/request binding, durable replay protection, and generated metadata.
- PostgreSQL-backed SCIM 2.0 Users/Groups provisioning with discovery, PATCH/PUT/CRUD, core `eq` filters, pagination, ETags, and session invalidation.
- Realm/client roles, groups, and Keycloak-shaped `realm_access` and `resource_access` claims.
- Explicit RFC 8707 API audiences with signed JWT access tokens, audience-filtered claims, and optional opaque-token introspection.
- Secure administration console at `/admin/`, realm-scoped administrator grants, a separately bearer-protected automation API, structured audit events, health endpoints, and Prometheus metrics.
- Optional Redis-backed shared rate limiting, non-root container, read-only runtime filesystem, and fail-closed production configuration.
- Dynamic registration only when explicitly enabled and protected by an independent initial-access token.

The v0.3 boundary still excludes Kerberos/SPNEGO, RADIUS, X.509 login, inbound LDAP synchronization, encrypted/IdP-initiated SAML, SAML IdP operation, SCIM Bulk and the complete filter grammar, UMA, configurable authentication flows, a self-service account console, complete mutable realm/client/group/role policy administration, and Keycloak Admin REST compatibility. Passkeys support fresh AuthMe enrollment and sign-in, but not imported Keycloak WebAuthn credentials or attestation-policy enforcement. See [federation and provisioning](docs/federation-and-provisioning.md) and the [roadmap](docs/roadmap.md).

## Run locally

Requirements: Node.js 22.12 or newer.

```bash
npm ci
AUTHME_DEV_MODE=true npm start
```

Then open the discovery document:

```text
http://127.0.0.1:3000/realms/master/.well-known/openid-configuration
```

The development administration console is at:

```text
http://127.0.0.1:3000/admin/
```

Development mode creates ephemeral signing/sealing material and an in-memory store. It also creates these deliberately development-only credentials:

| Item | Value |
|---|---|
| User | `admin` |
| Password | `AuthMe-Change-Me-Now-2026!` |
| Administrator grant | Realm-scoped wildcard grant, development only |
| Browser client | `authme-dev` |
| Client secret | `authme-dev-secret-change-me` |
| Redirect URI | `http://127.0.0.1:3001/callback` |
| Service client | `authme-dev-service` |
| Service secret | `authme-dev-service-secret-change-me` |

Never expose development mode or these credentials to a shared network.

Run all local validation:

```bash
npm test
npm run smoke
npm run check
```

The ordinary suite may skip PostgreSQL-only cases when `DATABASE_URL` is absent. Release validation must provide a migrated test database and run `npm run test:postgres`; that command fails when PostgreSQL is missing or unreachable and does not accept skipped durability/concurrency tests as evidence.

The smoke test performs real authorization-code and device flows and verifies OIDC/RFC 8414 metadata, protected one-use registration, explicit-claim consent, PKCE, signed ID and audience-bound access tokens, filtered API claims, delegated opaque-token introspection, UserInfo boundaries, refresh rotation, replay-family revocation, revocation, atomic TOTP enrollment, MFA enforcement, and one-use recovery codes.

## OIDC paths

For realm `master`, the issuer is `https://auth.example.com/realms/master`.

| Purpose | Path |
|---|---|
| Discovery | `/realms/master/.well-known/openid-configuration` |
| OAuth metadata | `/.well-known/oauth-authorization-server/realms/master` |
| Authorization | `/realms/master/protocol/openid-connect/auth` |
| Token | `/realms/master/protocol/openid-connect/token` |
| UserInfo | `/realms/master/protocol/openid-connect/userinfo` |
| JWKS | `/realms/master/protocol/openid-connect/certs` |
| Introspection | `/realms/master/protocol/openid-connect/token/introspect` |
| Revocation | `/realms/master/protocol/openid-connect/revoke` |
| Logout | `/realms/master/protocol/openid-connect/logout` |
| Device authorization | `/realms/master/protocol/openid-connect/auth/device` |
| PAR | `/realms/master/protocol/openid-connect/ext/par/request` |

Always consume the discovered endpoint values instead of constructing URLs in a client.

## Production with Compose

1. Copy `.env.example` to `.env` and replace every placeholder with independent random material.
2. Set the exact external HTTPS URL and realms. Issuers are immutable identifiers; changing one logs every client and user out.
3. Generate one private JWKS file per realm.
4. Apply migrations before starting the service.
5. Bootstrap the first administrator, then start AuthMe behind a TLS ingress.

```bash
cp .env.example .env
# Edit .env completely before continuing.
set -a; . ./.env; set +a
npm ci
make keys
docker compose --env-file .env up -d postgres
docker compose --env-file .env run --rm authme npm run db:migrate
read -rsp 'Initial AuthMe password: ' AUTHME_BOOTSTRAP_PASSWORD; echo
export AUTHME_BOOTSTRAP_PASSWORD
docker compose --env-file .env run --rm -e AUTHME_BOOTSTRAP_PASSWORD authme npm run bootstrap:user
unset AUTHME_BOOTSTRAP_PASSWORD
docker compose --env-file .env up --build -d authme
```

Passing a bootstrap password through an environment variable may still expose it to privileged host operators. Prefer your orchestrator's secret injection, rotate the password after first login, and remove the bootstrap value immediately.

The image runs as an unprivileged user with dropped capabilities and a read-only filesystem. PostgreSQL is mandatory outside development mode. Redis is optional and carries shared rate-limit state only:

```bash
docker compose --env-file .env --profile cache up --build -d
```

Do not publish AuthMe directly without a correctly configured HTTPS reverse proxy. Review the full [production runbook](docs/production.md), [architecture](docs/architecture.md), and [threat model](docs/threat-model.md).

## Kubernetes and OpenShift

The production [Helm chart](charts/authme/README.md) supports Kubernetes and OpenShift restricted security constraints. It includes a hardened multi-replica Deployment, migration hook, Service, PDB, HPA, topology spreading, NetworkPolicy, optional Ingress/OpenShift Route, optional ServiceMonitor, external Secret/ConfigMap references, and deterministic release validation. PostgreSQL and Redis remain external operator-managed services.

```bash
./scripts/check-helm.sh
helm upgrade --install authme ./charts/authme --namespace authme --create-namespace \
  --set image.repository=ghcr.io/asalfaifi/authme \
  --set image.digest='sha256:replace-with-an-immutable-digest' \
  --set config.publicUrl=https://auth.example.com \
  --set runtimeSecret.existingSecret=authme-runtime \
  --set jwks.existingSecret=authme-jwks
```

Create the runtime and per-realm JWKS Secrets before installation. The migration hook blocks an application rollout when the schema cannot be upgraded, but Helm cannot roll back an already committed database migration; follow the chart's expand/migrate/contract upgrade guidance.

## Essential configuration

| Variable | Purpose |
|---|---|
| `AUTHME_PUBLIC_URL` | Exact external HTTPS origin; no query or fragment. |
| `AUTHME_REALMS` | Comma-separated lowercase realm names. |
| `DATABASE_URL` | PostgreSQL connection URL; required in production. |
| `REDIS_URL` | Optional shared rate-limit backend. |
| `AUTHME_JWKS_DIR` | Directory containing private `{realm}.json` JWK sets. |
| `AUTHME_COOKIE_KEYS` | At least two comma-separated 32-byte-or-longer rotation keys. |
| `AUTHME_CSRF_SECRET` | Independent 32-byte-or-longer CSRF signing secret. |
| `AUTHME_PASSWORD_PEPPER` | Independent password/recovery-code pepper. |
| `AUTHME_SUBJECT_SALT` | Independent salt for pairwise subject identifiers. |
| `AUTHME_FIELD_ENCRYPTION_KEY` | Base64url-encoded 32-byte AES-GCM key for MFA secrets. |
| `AUTHME_ADMIN_TOKEN` | Independent root bearer for automation below `/admin/v1` and `/admin/metrics`; never used by the browser console. |
| `AUTHME_CLIENTS_JSON` | Static clients, as an object keyed by realm. |
| `AUTHME_RESOURCE_SERVERS_JSON` | Explicit API audiences, scopes, authorized clients, claim policy, and token format by realm. |
| `AUTHME_LDAP_PROVIDERS_JSON` | Realm LDAP/AD endpoints, credentials, mappings, and JIT policy. |
| `AUTHME_OIDC_PROVIDERS_JSON` | Realm upstream OIDC endpoints, client credentials, mappings, and JIT policy. |
| `AUTHME_SAML_PROVIDERS_JSON` | Realm SAML IdP trust, certificates, mappings, and JIT policy. |
| `AUTHME_SCIM_TOKENS_JSON` | Independent SCIM bearer credentials by realm; enables the SCIM surface and requires PostgreSQL. |
| `AUTHME_ENABLE_DYNAMIC_REGISTRATION` | Enables registration only when set to `true`; short-lived tokens are then issued by the admin API. |
| `AUTHME_TRUST_PROXY` | Trust exactly one proxy hop when true; configure only behind that proxy. |
| `AUTHME_AUDIT_RETENTION_DAYS` | Delete audit events older than this many days; defaults to 90. |
| `AUTHME_WEBAUTHN_CHALLENGE_TTL_SECONDS` | One-use passkey ceremony lifetime, 60–300 seconds; defaults to 300. |

Example static-client shape:

```json
{
  "master": [{
    "client_id": "my-app",
    "client_secret": "inject-this-from-a-secret-store",
    "token_endpoint_auth_method": "client_secret_basic",
    "redirect_uris": ["https://app.example.com/oidc/callback"],
    "post_logout_redirect_uris": ["https://app.example.com/"],
    "web_origins": ["https://app.example.com"],
    "response_types": ["code"],
    "grant_types": ["authorization_code", "refresh_token"]
  }]
}
```

Redirect URIs are validated exactly by the protocol engine. Do not use wildcards.
Browser CORS access is denied unless the client has an exact origin in
`web_origins`; redirect and post-logout URIs are never treated as implicit CORS
permissions. Production web origins must use HTTPS and contain no path, query,
fragment, credentials, or wildcard.
The v0.3 client-authentication profile supports `client_secret_basic` for
confidential clients and `none` for public clients. Public clients still use
PKCE `S256`; staged methods such as `private_key_jwt` are not advertised.

API access tokens require an explicit resource-server entry and a matching
`resource` authorization parameter. For example:

```json
{
  "master": [{
    "audience": "https://api.example.com/orders",
    "scopes": ["orders.read", "roles", "groups"],
    "authorized_client_ids": ["my-app"],
    "introspection_client_ids": ["orders-api"],
    "role_client_ids": ["orders-api"],
    "include_realm_roles": true,
    "include_groups": true,
    "access_token_format": "jwt"
  }]
}
```

JWT resource tokens use `typ: at+jwt` and are validated locally with the
realm JWKS, exact issuer, and configured audience. `oidc-provider` deliberately
does not introspect or remotely revoke structured JWT access tokens. They remain
valid at an offline validator until their short expiration unless the resource
server maintains an additional denylist. Set `access_token_format` to `opaque`
when an API requires immediate online revocation or introspection, and list its
confidential client ID in `introspection_client_ids`.

## Administration console and API

Open `/admin/` to use the AuthMe administration console. The console signs in through a reserved AuthMe OIDC client using Authorization Code with PKCE `S256`, state, and nonce. Access also requires an enabled, durable administrator grant for the selected realm. Production console login requires recent LoA2 authentication: a passkey or a password plus TOTP/recovery code. Password-only console login is accepted only in development mode.

The browser receives an opaque `HttpOnly`, `SameSite=Strict` cookie that is `Secure` in production; its digest and expiry are stored durably. Sessions are pinned to one realm and to snapshots of both the account security version and administrator-grant version. Security changes, grant changes, expiry, or logout invalidate the server-side session. Unsafe authenticated console API requests additionally require the exact configured Origin, JSON content type, and a session-bound CSRF header.

The console grant is separate from `AUTHME_ADMIN_TOKEN`. Never copy the root token into browser code, HTML, local storage, or a console configuration. Bootstrap creates the first durable wildcard grant; subsequent grant provisioning remains an operator-controlled lifecycle action. The safe read-only configuration catalog at `/admin/v1/realms/{realm}/configuration` reports clients, resource servers, federation, SCIM identifiers, extensions, storage mode, and TTLs without returning client secrets, bind credentials, SCIM tokens, private keys, or deployment secrets.

The current console manages the implemented user, credential, session-revocation, federated-identity, registration-token, audit, and configuration-catalog surfaces. It is not a complete Keycloak-style policy editor: client configuration is primarily deployment configuration, group/role definition CRUD is not complete, administrator approvals and organization delegation are staged, and there is no self-service account console.

### Root automation API

The AuthMe-native API is intentionally small and is not Keycloak Admin REST compatible. Non-browser automation authenticates with `Authorization: Bearer $AUTHME_ADMIN_TOKEN`. Treat that credential as deployment-wide root authority and keep the management surface network-restricted.

```bash
curl -H "Authorization: Bearer $AUTHME_ADMIN_TOKEN" \
  https://auth.example.com/admin/v1/realms

curl -X POST \
  -H "Authorization: Bearer $AUTHME_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  https://auth.example.com/admin/v1/realms/master/users \
  --data '{"username":"alice","email":"alice@example.com","password":"replace-with-a-strong-secret","roles":["member"]}'
```

User listing/updating/deletion, session and grant revocation, account unlock, password reset, TOTP enrollment/confirmation/removal, passkey registration/list/removal, explicit federated-identity linking, the safe configuration catalog, and audit listing are under `/admin/v1/realms/{realm}`. Prometheus metrics are protected at `/admin/metrics`. Health probes are public at `/health/live` and `/health/ready`. See the exact [administration API contract](docs/admin-api.md).

When dynamic registration is enabled, issue a short-lived initial access token through `POST /admin/v1/realms/{realm}/client-registration-tokens`; the token is returned once and authorizes exactly one request to the discovered registration endpoint.

## Migrating from Keycloak

Start with the [compatibility matrix](docs/keycloak-compatibility.md), then follow the staged [migration guide](docs/keycloak-migration.md). Do not point AuthMe at a Keycloak database, assume credential formats are portable, or cut over a realm that depends on a staged feature.

## Security and contributing

Read [SECURITY.md](SECURITY.md) before exposing a deployment. Security-sensitive changes should include a regression test and account for realm isolation, replay, redirect validation, issuer stability, secret handling, and audit behavior.

AuthMe is licensed under the [MIT License](LICENSE).
