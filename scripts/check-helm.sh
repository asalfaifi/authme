#!/usr/bin/env bash
set -euo pipefail

if ! command -v helm >/dev/null 2>&1; then
  echo "error: Helm is required to validate the AuthMe chart" >&2
  exit 127
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_dir}/.." && pwd)"
chart="${repository_root}/charts/authme"
all_values="${chart}/ci/all-values.yaml"

if [[ ! -f "${chart}/Chart.yaml" || ! -f "${all_values}" ]]; then
  echo "error: AuthMe chart or all-values fixture is missing" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/authme-helm.XXXXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT

fail() {
  echo "error: $*" >&2
  exit 1
}

assert_contains() {
  local pattern="$1"
  local file="$2"
  local description="$3"
  grep -Eq -- "${pattern}" "${file}" || fail "${description}"
}

assert_minimum_count() {
  local pattern="$1"
  local minimum="$2"
  local file="$3"
  local description="$4"
  local count
  count="$(grep -Ec -- "${pattern}" "${file}" || true)"
  (( count >= minimum )) || fail "${description} (found ${count}, expected at least ${minimum})"
}

render_reproducibly() {
  local name="$1"
  shift
  local first="${work_dir}/${name}.yaml"
  local second="${work_dir}/${name}.repeat.yaml"

  helm template authme "${chart}" --namespace authme "$@" >"${first}"
  helm template authme "${chart}" --namespace authme "$@" >"${second}"
  cmp -s -- "${first}" "${second}" || fail "${name} render is not deterministic"
  printf '%s\n' "${first}"
}

echo "Using $(helm version --short)"
helm lint "${chart}" --strict
helm lint "${chart}" --strict --values "${all_values}"

default_render="$(render_reproducibly default)"
all_render="$(render_reproducibly all --values "${all_values}")"
openshift_render="$(render_reproducibly openshift \
  --api-versions security.openshift.io/v1 \
  --set openshift.enabled=true \
  --set route.enabled=true \
  --set route.host=login.apps.example.test)"

assert_contains '^kind: Deployment$' "${default_render}" "default render is missing the Deployment"
assert_contains '^kind: Job$' "${default_render}" "default render is missing the migration Job"
assert_contains '^kind: PodDisruptionBudget$' "${default_render}" "default render is missing the PDB"
assert_contains '^kind: NetworkPolicy$' "${default_render}" "default render is missing the NetworkPolicy"

for kind in HorizontalPodAutoscaler Ingress Route ServiceMonitor; do
  assert_contains "^kind: ${kind}$" "${all_render}" "all-values render is missing ${kind}"
done

assert_contains '^kind: Route$' "${openshift_render}" "OpenShift render is missing the Route"
if grep -Eq -- '^[[:space:]]+(runAsUser|runAsGroup|fsGroup):' "${openshift_render}"; then
  fail "OpenShift render contains a fixed UID, GID, or fsGroup"
fi

# Deployment, migration Job, and Helm test Pod must all retain the restricted
# baseline when OpenShift supplies their runtime identity.
assert_minimum_count '^[[:space:]]+runAsNonRoot: true$' 3 "${openshift_render}" "runAsNonRoot is not set on every pod"
assert_minimum_count '^[[:space:]]+type: RuntimeDefault$' 3 "${openshift_render}" "RuntimeDefault seccomp is not set on every pod"
assert_minimum_count '^[[:space:]]+privileged: false$' 3 "${openshift_render}" "privileged=false is not set on every container"
assert_minimum_count '^[[:space:]]+allowPrivilegeEscalation: false$' 3 "${openshift_render}" "privilege escalation is not disabled on every container"
assert_minimum_count '^[[:space:]]+readOnlyRootFilesystem: true$' 3 "${openshift_render}" "read-only root filesystem is not set on every container"
assert_minimum_count '^[[:space:]]+- ALL$' 3 "${openshift_render}" "Linux capabilities are not dropped on every container"
assert_minimum_count '^[[:space:]]+automountServiceAccountToken: false$' 3 "${openshift_render}" "service-account token automount is not disabled on every pod"

echo "Helm release gate passed: strict lint, deterministic renders, optional resources, and OpenShift restricted security."
