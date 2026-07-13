# Production operations

## Production status

AuthMe v0.1 is a production-oriented OIDC foundation, not a declaration of complete Keycloak parity or an independently certified identity product. A deployment is production-ready only after the exact build, configuration, proxy, database adapter, interactions, and operational controls pass the release gates below.

The protocol engine is [`oidc-provider` 9.9.1](https://oidc-provider.dev/changelog/#_9-9-1-2026-07-07), whose upstream project publishes OpenID/FAPI certifications and supported profiles. That certification does not automatically extend to AuthMe or a particular deployment.

## Supported topology

```text
Internet
   |
TLS load balancer / ingress
   |
one or more identical AuthMe Node.js 22 replicas
   |
PostgreSQL primary with managed backup/standby

optional Redis: shared rate-limit counters only
```

v0.1 supports a single writable PostgreSQL authority. Multi-site active/active writes are not supported. Do not distribute realms across independent databases behind one issuer without a designed consistency and failover model.

## Base requirements

- A supported, patched Node.js 22 release; see the [Node.js 22 documentation](https://nodejs.org/download/release/latest-v22.x/docs/api/).
- PostgreSQL with transactional storage, backups, adequate connection capacity, and synchronized time.
- TLS from the user agent to the trusted ingress. Use TLS to PostgreSQL/Redis when traffic crosses an untrusted network.
- A fixed public origin and stable realm issuer paths.
- Protected signing keys and application/database secrets.
- Reliable DNS and NTP/time synchronization.
- Centralized structured logs, metrics, and alerts.

Do not use development defaults, generated ephemeral keys, plaintext HTTP issuers, wildcard redirects, default credentials, or an in-memory provider adapter in production.

## Configuration management

Treat configuration as immutable deployment input. The runtime should validate required values at startup and refuse readiness when unsafe or contradictory.

Production configuration must define, using the names supported by the current executable:

- fixed external scheme/host/base URL;
- trusted proxy count or explicit proxy networks;
- PostgreSQL connection and bounded pool settings;
- realm configuration source;
- signing key/JWKS source and cookie/session secrets;
- enabled grant types and signing algorithms;
- token, code, interaction, and session lifetimes;
- device, PAR, DPoP, dynamic-registration, and back-channel logout client policies;
- allowed CORS policy;
- optional Redis endpoint and limiter failure policy;
- log level/format and metrics exposure;
- secure cookie behavior;
- email/reset configuration if those flows are enabled.

Secrets belong in a secret manager or mounted secret file with restrictive permissions. Avoid environment-variable exposure where the platform includes environments in diagnostics, but never commit secrets to files or images. Fail startup when an example/default secret is detected.

The v0.1 executable recognizes these security-critical inputs:

| Setting | Production requirement |
|---|---|
| `AUTHME_PUBLIC_URL` | Exact externally visible HTTPS origin |
| `AUTHME_REALMS` | Comma-separated immutable realm slugs |
| `DATABASE_URL` | Required PostgreSQL connection |
| `AUTHME_JWKS_DIR` | Read-only directory containing realm JWK sets |
| `AUTHME_COOKIE_KEYS` | At least two independent values, newest first, each at least 32 bytes |
| `AUTHME_CSRF_SECRET` | Independent random value of at least 32 bytes |
| `AUTHME_PASSWORD_PEPPER` | Independent random value of at least 32 bytes |
| `AUTHME_SUBJECT_SALT` | Independent stable random value of at least 32 bytes |
| `AUTHME_FIELD_ENCRYPTION_KEY` | Base64url-encoded 32-byte key for TOTP/field encryption |
| `AUTHME_ADMIN_TOKEN` | Independent high-entropy bearer administration token |
| `AUTHME_TRUST_PROXY` | Enable only behind the intended trusted proxy topology |
| `AUTHME_CLIENTS_JSON` | Reviewed static clients grouped by configured realm |
| `AUTHME_ENABLE_DYNAMIC_REGISTRATION` | Off by default; enable only with protected token issuance and monitoring |
| `REDIS_URL` | Optional shared limiter; protect as a credential when present |

Changing `AUTHME_SUBJECT_SALT` can change derived subject identifiers; changing `AUTHME_FIELD_ENCRYPTION_KEY` without a data re-encryption plan can make encrypted TOTP secrets unreadable. Back up and rotate both through a reviewed runbook.

## Reverse proxy and TLS

- The proxy must preserve the request path and must not rewrite one realm into another.
- Only explicitly trusted proxy hops may supply forwarded scheme/host/client address information.
- The advertised issuer comes from fixed configuration, not an arbitrary `Host` header.
- Redirect HTTP to HTTPS at the outer edge; do not expose production protocol endpoints over plaintext.
- Apply request header/body/URL limits and slow-client timeouts at both ingress and application layers.
- Preserve a correlation ID or have AuthMe generate one; never accept it as authorization input.

After deployment, retrieve discovery through the public ingress and confirm that `issuer`, authorization, token, UserInfo, JWKS, revocation, introspection, and logout URLs all use the intended external origin and realm.

## PostgreSQL

PostgreSQL is in the authentication correctness path. Use a dedicated database and least-privilege runtime role. A separate migration role may own DDL.

Operational rules:

- Run migrations as an explicit release step, once, under an advisory lock where supported.
- Back up before schema changes and verify that the target application can run against the migrated schema.
- Bound each AuthMe replica's connection pool so the combined maximum remains below database capacity with headroom for migrations and operations.
- Configure statement, lock, and idle transaction timeouts.
- Monitor connections, transaction latency, deadlocks, lock waits, storage growth, replication lag, and failed cleanup.
- Schedule expiry cleanup for provider artifacts; cleanup must be bounded and indexed.
- Use point-in-time recovery where available and perform restore drills.

One-use artifact consumption depends on database concurrency controls. PostgreSQL describes transaction isolation in its [official documentation](https://www.postgresql.org/docs/current/transaction-iso.html). Do not weaken atomic redemption to improve benchmark numbers.

### Row-level security

If PostgreSQL RLS is enabled as defense-in-depth, use a runtime role that cannot bypass it and consider `FORCE ROW LEVEL SECURITY`. Test backups with an appropriate administrative role: PostgreSQL warns that filtered RLS backups can silently omit rows unless handled correctly. See [Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

## Redis

Redis is optional for shared rate limiting. It must not contain canonical sessions, grants, authorization codes, tokens, users, clients, or signing keys in v0.1.

For multi-replica deployments:

- prefer shared Redis-backed counters over independent per-node limits;
- use authentication, TLS/network isolation, timeouts, and bounded retries;
- set counter TTLs and a memory policy appropriate for ephemeral counters;
- alert on latency/errors and on limiter fallback;
- choose and document fail-closed or conservative local fallback for sensitive endpoints;
- never silently fall back to unlimited traffic.

## Signing keys and secrets

### Initial provisioning

Generate signing keys using a reputable cryptographic tool or managed key service. Inject private JWK material through protected deployment secrets. Only public members appear in JWKS responses. Use distinct key material per environment and preferably per realm.

### Rotation runbook

1. Generate/import the new key and unique `kid` without removing the old public key.
2. Publish both keys and verify JWKS from every replica/public ingress.
3. Make the new key active for signing.
4. Verify newly issued tokens use the new `kid` and both old/new tokens validate.
5. Keep the previous public key published for at least the longest token lifetime plus clock skew, caches, and operational margin.
6. Remove the retired key only after validation telemetry confirms it is no longer required.
7. Record the change in the security audit trail.

Emergency compromise rotation is different: activate a clean key, revoke affected sessions/grants as supported, shorten trust in the compromised key, notify resource servers, and follow the incident plan.

Rotate database, Redis, cookie, client, and administrative secrets independently. A signing-key rotation must not force reuse of unrelated secrets.

### Password and MFA secrets

v0.1 hashes passwords with Argon2id using 64 MiB memory, three iterations, parallelism one, a 32-byte hash, a per-password salt supplied by the library, and `AUTHME_PASSWORD_PEPPER`. Recalibrate resource cost on deployment hardware without weakening it silently. The implementation follows the Argon2id family standardized in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).

TOTP secrets are encrypted with AES-256-GCM using `AUTHME_FIELD_ENCRYPTION_KEY` and contextual associated data. Recovery codes are keyed digests and are consumed once. Protect the encryption key and password pepper separately from the PostgreSQL backup. Restore drills must include both.

v0.1 accepts one active password pepper and one active field-encryption key. Replacing either value without migrating the dependent records locks users out: the pepper participates in password verification and recovery-code digests, while the field key decrypts TOTP secrets. Use a tested offline rehash/re-encryption or credential re-enrollment plan; do not rotate these values as an uncoordinated ordinary restart.

## Administration and dynamic registration

The v0.1 administration API uses `AUTHME_ADMIN_TOKEN`. Treat it as deployment-wide root-equivalent for the exposed API:

- restrict the route at ingress/network level where feasible;
- never expose it to a browser or store it in local storage;
- rotate it through the secret manager and restart/roll replicas safely;
- alert on repeated failures and audit all successful mutations;
- use a distinct short-lived initial access token for dynamic client registration instead of distributing the administration token.

Initial access tokens must be short-lived and delivered out of band. AuthMe v0.1 does not attach fine-grained policies to these tokens, so treat each one as permission to submit any client metadata accepted by the protocol engine. Review every dynamically registered redirect/logout URI and authentication method. Revoke suspicious clients immediately.

## Cookies and browser security

Production interaction/session cookies must be Secure, HttpOnly, explicitly SameSite, scoped as narrowly as compatible with realm interactions, and rotated after authentication. Sensitive responses use `Cache-Control: no-store`.

Interaction pages should set:

- a restrictive Content Security Policy, including `frame-ancestors`;
- `X-Content-Type-Options: nosniff`;
- an appropriate referrer policy;
- HSTS at the public TLS boundary after domain readiness is confirmed.

Do not store access, refresh, or ID tokens in browser local storage as part of AuthMe's own interaction UI.

## Observability

### Health

- **Liveness** checks process/event-loop health and does not depend on every downstream service.
- **Readiness** requires valid startup configuration, usable realm signing configuration, and PostgreSQL connectivity.
- Redis health should affect readiness only according to the declared limiter failure policy.

Do not expose stack traces, configuration, dependency credentials, or realm secrets in health responses.

### Metrics

Monitor at minimum:

- HTTP request count, latency, status, and bounded route label;
- authorization/token/UserInfo/introspection/revocation/logout outcomes;
- device authorization/polling, PAR, DPoP replay/nonce, dynamic registration, and back-channel logout outcomes;
- authentication success/failure/throttle/lockout counts;
- database pool utilization, query latency, errors, cleanup lag;
- Redis limiter latency/errors/fallback state;
- event-loop lag, memory, CPU, restarts, and readiness;
- active sessions/artifact counts where collection is efficient and privacy-safe.

Do not use user IDs, emails, authorization codes, tokens, full redirect URIs, or unbounded client values as metric labels.

### Logs and audit

Use structured JSON logs with timestamps, severity, correlation ID, realm, event name, outcome, and safe client identifiers. Redact authorization headers, cookies, passwords, secrets, codes, tokens, private keys, reset URLs, and protocol request bodies. Protect and audit access to security logs.

High-volume protocol events pass through a fixed-capacity asynchronous writer. Repeated errors are sampled, overload is shed and counted in `authme_protocol_audit_events_total`, and accepted work is drained during graceful shutdown. Administrative and identity security events bypass that best-effort queue and are written synchronously. `AUTHME_AUDIT_RETENTION_DAYS` defaults to 90; choose an explicit privacy/incident-response period, monitor cleanup lag, and export events to tamper-evident storage when policy requires longer retention.

## Scaling and capacity

Scale AuthMe replicas horizontally only after confirming that all protocol artifacts use PostgreSQL. Use graceful shutdown: stop readiness, allow in-flight requests to finish within a bound, then close HTTP and database connections.

Capacity tests should include:

- login and consent interactions;
- authorization-code redemption races;
- refresh-heavy workloads;
- device polling and verification;
- PAR submission/authorization and DPoP proof verification/replay;
- authenticated dynamic-registration bursts;
- Client Credentials bursts;
- introspection load;
- expired-artifact cleanup;
- database failover and temporary Redis failure;
- key rotation while traffic is active.

Do not autoscale solely on CPU; database pool pressure, latency, and event-loop lag matter. Adding replicas without database capacity can reduce availability.

## Backup and recovery

Back up:

- PostgreSQL, including realm/client/user/provider artifacts and migration history;
- signing keys or the external KMS references needed to recover them;
- immutable deployment configuration and secret-manager metadata;
- migration tooling/version and release image digest.

Encrypt backups, isolate backup credentials, define retention/deletion, and test restoration into an isolated environment. A database backup without the corresponding signing keys cannot resume the same issuer cleanly; signing keys without the database are insufficient to restore grants and sessions.

Recovery objectives must state whether active sessions must survive. If not, deliberately revoke/invalidate them rather than accidentally accepting inconsistent state.

## Upgrade procedure

1. Read Node.js, `oidc-provider`, database-driver, and AuthMe release/security notes.
2. Build from the lockfile and record image digest/SBOM.
3. Back up and rehearse migrations.
4. Run unit, integration, browser, replay, cross-realm, and OpenID conformance tests.
5. Deploy to a production-like environment with real ingress behavior.
6. Use a canary or rolling release only if old/new versions are schema and artifact compatible.
7. Watch protocol errors, token verification, database pressure, and readiness.
8. Retain a tested rollback image and schema plan.

Never roll back application code across an irreversible database migration without an explicit downgrade plan.

## Incident response

Maintain runbooks for:

- signing-key compromise;
- client-secret compromise;
- credential stuffing;
- suspected cross-realm disclosure;
- database/backup compromise;
- token leakage;
- dependency vulnerability;
- issuer/DNS/certificate failure;
- PostgreSQL or Redis outage.

Preserve relevant audit data, rotate affected secrets, revoke sessions/grants where applicable, communicate to relying parties, and document the recovery. Do not place leaked tokens or credentials into tickets while investigating.

## Production release gate

The release owner must record evidence for all of the following:

- clean reproducible build from the lockfile;
- supported patched Node.js 22 and reviewed dependency audit;
- database migration and clean-install tests;
- full automated test suite, including concurrent replay and cross-realm isolation;
- device-flow, PAR, DPoP, protected dynamic-registration, back-channel logout, TOTP, and recovery-code negative/concurrency tests;
- [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/) against the release configuration;
- public-ingress issuer/discovery/JWKS validation;
- TLS, trusted-proxy, cookie, CSP, CORS, redirect, and cache-header review;
- key rotation and database restore drills;
- load/soak and dependency-failure tests;
- secret/container/SBOM scans;
- updated threat model and compatibility documentation;
- independent security review before a broad production claim.
