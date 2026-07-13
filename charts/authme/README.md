# AuthMe Helm chart

This chart deploys AuthMe on Kubernetes or OpenShift with an external
PostgreSQL database and an optional external Redis service. It intentionally
does not bundle either data service: identity infrastructure should use an
operator-managed or managed database with independent backups, availability,
and lifecycle controls.

The chart includes:

- a two-replica Deployment, ClusterIP Service, startup/readiness/liveness
  probes, rolling-update policy, topology spreading, resources, and a PDB;
- a blocking `pre-install,pre-upgrade` database migration Job;
- optional Ingress, OpenShift Route, HPA, NetworkPolicy, and ServiceMonitor;
- non-secret configuration in a ConfigMap and references to pre-created
  runtime/JWKS Secrets;
- restricted security contexts: non-root, read-only root filesystem, all
  capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp,
  no service-account token, and a memory-backed writable `/tmp`;
- OpenShift restricted-SCC support without requesting a privileged SCC or
  fixing the runtime UID/GID.

## Prerequisites

- Kubernetes 1.27+ or a supported OpenShift release with a compatible
  Kubernetes API;
- Helm 3 or 4;
- an AuthMe image accessible to the cluster (pin a digest in production);
- external PostgreSQL reachable from the namespace;
- optional external Redis when shared rate limiting is required;
- one private JWKS file for each configured realm.

PostgreSQL and Redis transport security, credentials, network paths, backup,
restore, and failover are operator responsibilities.

## Required Secrets

Create the Secrets before installing the release. The migration hook runs
before normal Helm resources are created, so an in-release Secret cannot safely
satisfy it. Prefer External Secrets, Sealed Secrets, SOPS, or your platform's
secret integration. The following commands only illustrate the expected keys;
putting literal production secrets in shell history is unsafe.

Any Secret named in `imagePullSecrets` must also exist before the migration
hook starts.

The Secret named by `runtimeSecret.existingSecret` is loaded with `envFrom` and
should contain:

| Key | Required | Purpose |
|---|---:|---|
| `DATABASE_URL` | yes | External PostgreSQL connection URL |
| `REDIS_URL` | no | External Redis connection URL |
| `AUTHME_COOKIE_KEYS` | yes | Comma-separated cookie rotation keys |
| `AUTHME_CSRF_SECRET` | yes | CSRF signing secret |
| `AUTHME_PASSWORD_PEPPER` | yes | Password/recovery-code pepper |
| `AUTHME_SUBJECT_SALT` | yes | Stable subject derivation salt |
| `AUTHME_FIELD_ENCRYPTION_KEY` | yes | Base64url AES-256 key |
| `AUTHME_ADMIN_TOKEN` | yes | Root-equivalent administration token |
| `AUTHME_CLIENTS_JSON` | no | Static client configuration by realm |
| `AUTHME_RESOURCE_SERVERS_JSON` | no | Resource-server audiences, scopes, and client policy |
| `AUTHME_LDAP_PROVIDERS_JSON` | no | Realm LDAP/Active Directory provider credentials and mappings |
| `AUTHME_OIDC_PROVIDERS_JSON` | no | Realm upstream OIDC provider endpoints and client credentials |
| `AUTHME_SAML_PROVIDERS_JSON` | no | Realm SAML IdP trust, certificates, mappings, and optional SP key |
| `AUTHME_SCIM_TOKENS_JSON` | no | Raw high-entropy SCIM bearer tokens by realm; protect and rotate as Secret data |

Illustrative creation:

```bash
kubectl -n authme create secret generic authme-runtime \
  --from-literal=DATABASE_URL='postgresql://...' \
  --from-literal=AUTHME_COOKIE_KEYS='key-one,key-two' \
  --from-literal=AUTHME_CSRF_SECRET='...' \
  --from-literal=AUTHME_PASSWORD_PEPPER='...' \
  --from-literal=AUTHME_SUBJECT_SALT='...' \
  --from-literal=AUTHME_FIELD_ENCRYPTION_KEY='...' \
  --from-literal=AUTHME_ADMIN_TOKEN='...' \
  --from-literal=AUTHME_CLIENTS_JSON='{"master":[]}'
```

The Secret named by `jwks.existingSecret` is mounted as a directory. Its key
names must be `{realm}.json`:

```bash
kubectl -n authme create secret generic authme-jwks \
  --from-file=master.json=./private-jwks/master.json
```

Secret files use mode `0444` by default so an OpenShift-assigned arbitrary UID
can read them inside the isolated pod. The volume remains read-only and is
visible only to the AuthMe container. Tighten the mode only when the chosen SCC
or pod identity still has read access.

## Install

Create a small environment-specific values file:

```yaml
image:
  repository: registry.example.com/security/authme
  digest: sha256:replace-with-immutable-image-digest

config:
  publicUrl: https://login.example.com
  realms:
    - master

runtimeSecret:
  existingSecret: authme-runtime

jwks:
  existingSecret: authme-jwks

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: login.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: login-example-com-tls
      hosts:
        - login.example.com
```

Then render and install:

```bash
helm lint charts/authme -f authme-production.yaml
helm template authme charts/authme -n authme -f authme-production.yaml > rendered.yaml
helm upgrade --install authme charts/authme \
  --namespace authme --create-namespace \
  --values authme-production.yaml \
  --atomic --wait --timeout 10m
helm test authme --namespace authme
```

`config.publicUrl` is the issuer origin. It must exactly match the externally
visible HTTPS origin before clients are registered. Changing it later changes
every realm issuer.

## Migration and upgrade safety

The `authme-migrate` Job is a Helm `pre-install,pre-upgrade` hook. It reads only
`DATABASE_URL` from the pre-created runtime Secret, obtains AuthMe's migration
advisory lock, verifies checksums of previously applied migrations, and blocks
the release when migration fails. Successful hook Jobs are deleted; failed Jobs
remain for diagnosis.

Before an upgrade:

1. back up PostgreSQL and the corresponding JWKS/secret material;
2. verify that new migrations are forward-compatible with the currently
   running AuthMe version because old pods stay live while the pre-upgrade hook
   runs;
3. pin and verify the new image digest;
4. render and review the chart, then perform the upgrade;
5. verify discovery, login, token refresh, revocation, and logout externally.

`helm rollback` rolls back Kubernetes objects, not the database schema. Do not
assume `--atomic` reverses a migration. If a release introduces a migration
that is not backward compatible, use a separately reviewed expand/migrate/
contract rollout instead of the automatic hook.

To inspect a failed hook:

```bash
kubectl -n authme get job authme-migrate
kubectl -n authme logs job/authme-migrate
```

Set `migration.enabled=false` only when migrations are run by a separate,
controlled release job using the exact same image and `npm run db:migrate`.

## OpenShift

When Helm is connected to OpenShift, the chart detects the SCC API and omits
fixed `runAsUser`, `runAsGroup`, and `fsGroup` values. Set `openshift.enabled`
for offline rendering or GitOps validation:

```bash
helm template authme charts/authme -n authme \
  --set openshift.enabled=true \
  --set route.enabled=true \
  --set route.host=login.apps.example.com
```

The pod still declares `runAsNonRoot`, `RuntimeDefault` seccomp, a read-only
root filesystem, no privilege escalation, and zero Linux capabilities. The
restricted SCC supplies the runtime identity. No custom SCC, root UID, host
mount, host network, or service-account token is required.

For a native edge-terminated Route:

```yaml
openshift:
  enabled: true
route:
  enabled: true
  host: login.apps.example.com
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
```

Keep `config.trustProxy=true` behind an Ingress or Route, and ensure the public
URL remains HTTPS.

## Scaling and availability

The default is two replicas, a PDB with `minAvailable: 1`, zone/hostname
topology spreading, and a zero-unavailable rolling update. HPA is optional:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 6
```

Each application replica currently opens a bounded PostgreSQL pool. Confirm
database capacity before raising replicas or HPA limits. Configure external
Redis for shared rate limits before relying on multi-replica abuse controls.

## NetworkPolicy

The default NetworkPolicy selects only server pods, permits ingress only on the
named HTTP port, and permits all egress. Egress is open because the chart cannot
infer DNS, PostgreSQL, Redis, SMTP, or telemetry destinations. Replace it with
cluster-specific rules rather than guessing service CIDRs. Migration hooks are
not selected by the server policy; apply namespace-level egress policy that
still permits migrations to reach PostgreSQL.

If an Ingress controller or monitoring stack is restricted by source namespace
or pod selectors, customize `networkPolicy.ingress`. Disable the chart policy
only when an equivalent namespace/platform policy exists.

## Metrics

Enable `serviceMonitor.enabled` only when the Prometheus Operator CRDs are
installed. AuthMe currently exposes metrics at `/admin/metrics` behind the same
root-equivalent administration bearer token. The ServiceMonitor reads it from
the configured Secret:

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: kube-prometheus-stack
  authorization:
    secretName: authme-runtime
    secretKey: AUTHME_ADMIN_TOKEN
```

Restrict access to Prometheus and the Secret. A future dedicated metrics
credential should replace this shared administration credential.
When `serviceMonitor.namespace` differs from the release namespace, copy or
externally synchronize the authorization Secret into the ServiceMonitor's
namespace; Prometheus Operator Secret selectors are namespace-local.

## External configuration and secret rotation

Set `config.existingConfigMap` to use an externally managed ConfigMap containing
the `AUTHME_*` non-secret variables. Because Helm cannot inspect changes to an
external object, update `config.checksum` during a change to roll pods.

The same applies to `runtimeSecret.checksum` and `jwks.checksum`:

```bash
helm upgrade authme charts/authme -n authme -f authme-production.yaml \
  --set-string runtimeSecret.checksum='rotation-2026-07-13'
```

JWKS rotation needs an overlap window: publish the old and new public keys,
activate the new signer, retain the old verification key longer than all token
lifetimes and caches, and remove it only after validation. A checksum rollout
only restarts pods; it does not make an unsafe key transition safe.

## Validation

The repository includes `ci/all-values.yaml` to exercise optional templates:

```bash
helm lint charts/authme
helm lint charts/authme -f charts/authme/ci/all-values.yaml
helm template authme charts/authme -n authme >/tmp/authme.yaml
helm template authme charts/authme -n authme \
  -f charts/authme/ci/all-values.yaml >/tmp/authme-all.yaml
helm template authme charts/authme -n authme \
  --set openshift.enabled=true --set route.enabled=true >/tmp/authme-ocp.yaml
```

Run a schema validator such as kubeconform against rendered built-in resources
in CI, plus server-side dry-run against the actual target cluster so optional
CRDs and admission policy are checked.
