# AuthMe security policy

AuthMe is identity infrastructure. Treat every deployment, configuration change, dependency update, and migration as security-sensitive.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include live credentials, tokens, user data, signing keys, or exploit details in public logs.

Use GitHub's **Report a vulnerability** flow in the repository Security tab to open a private security advisory. Include:

- affected commit or release;
- deployment topology and relevant configuration with secrets removed;
- minimal reproduction steps;
- expected and observed behavior;
- security impact and whether exploitation has been observed;
- any suggested mitigation.

You should receive an acknowledgement through the advisory within two business days. The maintainers target initial severity triage within five business days, a mitigation plan within ten business days for confirmed critical/high issues, and a coordinated fix as quickly as safe validation and rollout permit. These are response targets, not a guarantee. If private advisories are unavailable, contact the repository owner through a private GitHub channel before sharing details.

## Supported versions

| Release line | Security support |
|---|---|
| `1.0.x` release candidates and final releases | Supported until 12 months after a superseding stable major release |
| Latest `main` | Best effort; not a release artifact |
| `0.x` | Unsupported after the first `1.0.0-rc.1` publication |

Only the newest patch in a supported line receives fixes. Operators must upgrade to that patch before requesting a backport. A release candidate remains subject to breaking fixes before `1.0.0`; external certification, penetration testing, hardware rotation, and regional-failover evidence are release gates rather than implied support claims.

## Security boundary

AuthMe v1.0.0-rc.1 is a code-complete identity platform for the capabilities explicitly listed in the compatibility matrix. It is not an independently OpenID-certified distribution and has not completed the external release gates in `MILESTONES.md`. The upstream protocol engine's certification does not automatically certify AuthMe or an operator's deployment.

The implemented and staged boundaries are documented in:

- [Threat model](docs/threat-model.md)
- [Production runbook](docs/production.md)
- [Keycloak compatibility](docs/keycloak-compatibility.md)
- [Federation and provisioning](docs/federation-and-provisioning.md)
- [Roadmap and release gates](docs/roadmap.md)
- [External evidence and stable-promotion procedure](docs/external-release-gates.md)

Do not use AuthMe as a replacement where Kerberos/SPNEGO, RADIUS, X.509 end-user login, SAML artifact binding, broker-side assertion decryption, imported WebAuthn credentials, UMA/Authorization Services, Keycloak Admin REST/SPI/theme compatibility, or multi-site active/active writes are required. Treat the exact baseline documented for each implemented mechanism as the supported boundary.

## Operator responsibilities

A secure production deployment requires operators to:

- terminate modern TLS at a trusted ingress and set the exact immutable external issuer URL;
- keep PostgreSQL, Redis, administration endpoints, metrics, and private keys off untrusted networks;
- restrict AuthMe egress to reviewed IdP/directory endpoints and protect LDAP bind, OIDC client, SAML key/certificate, and SCIM token material;
- generate independent high-entropy values for every documented secret and rotate them deliberately;
- keep at least two cookie signing keys during rotation and retain verification keys while issued tokens may still be valid;
- use exact registered redirect/logout URIs and confidential-client authentication where appropriate;
- run migrations as a controlled job before application rollout;
- disable development mode and development credentials;
- protect and back up the database and signing/encryption keys, and regularly test restoration;
- synchronize system clocks and monitor login failures, token replay, administrative actions, latency, errors, database health, and key expiry;
- patch Node.js, the base image, PostgreSQL, Redis, and npm dependencies promptly;
- run unit, smoke, migration, container, dependency-audit, and protocol-conformance gates on the exact release artifact;
- verify the release checksums, authenticated signing-key fingerprint, GitHub attestations, and deployed image digest before rollout;
- protect candidate/release Actions behind an independently reviewed `release` environment and signed stable tags;
- review log and proxy configuration so authorization headers, cookies, codes, tokens, passwords, MFA material, and client secrets are never recorded.

`AUTHME_ADMIN_TOKEN` is a bootstrap-grade global administration credential. Store it in a secret manager, restrict access to the administration routes at the network layer, rotate it on suspected exposure, and do not treat it as delegated RBAC.

## Development and dependency policy

- Never commit `.env`, `.local/jwks`, private JWK members, database dumps, or production fixtures.
- Avoid implementing OAuth/OIDC/JWT cryptography directly when a reviewed protocol primitive exists.
- Pin protocol-critical dependency ranges conservatively and review changelogs before updates.
- Run `npm audit --omit=dev --audit-level=high`, but do not treat a clean advisory scan as a security review.
- Add regression tests for authorization, authentication, isolation, parsing, replay, race, or secret-handling fixes.
- Run independent penetration testing and OpenID conformance testing before a high-risk deployment.

## Incident response

If compromise is suspected, preserve evidence and determine which boundary was affected. Depending on scope, actions may include disabling ingress, rotating the administration and client credentials, revoking grants/sessions, replacing cookie and field-encryption material, rotating realm signing keys with an overlap window, forcing user password/MFA recovery, and restoring from a verified backup. Changing an issuer is a last-resort migration, not a normal key-rotation mechanism.
