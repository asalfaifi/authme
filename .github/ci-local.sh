#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${1:-}" == "test" ]] || exit 0

suffix="${GITHUB_RUN_ID:-local}-$$"
postgres_container="universal-ci-authme-postgres-${suffix}"
redis_container="universal-ci-authme-redis-${suffix}"

cleanup() {
  docker rm -f "$postgres_container" "$redis_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

started=false
for _ in {1..5}; do
  cleanup
  if docker run --detach --rm --name "$postgres_container" \
      --env POSTGRES_DB=authme_test \
      --env POSTGRES_USER=authme \
      --env POSTGRES_PASSWORD=authme-ci-only \
      --publish 127.0.0.1::5432 postgres:17-alpine >/dev/null && \
    docker run --detach --rm --name "$redis_container" \
      --publish 127.0.0.1::6379 redis:7.4-alpine >/dev/null; then
    started=true
    break
  fi
  sleep 2
done
[[ "$started" == "true" ]]

for _ in {1..60}; do
  if docker exec "$postgres_container" pg_isready -U authme -d authme_test >/dev/null 2>&1 && \
    docker exec "$redis_container" redis-cli ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker exec "$postgres_container" pg_isready -U authme -d authme_test >/dev/null
docker exec "$redis_container" redis-cli ping >/dev/null

postgres_port="$(docker port "$postgres_container" 5432/tcp | awk -F: 'NR == 1 {print $NF}')"
redis_port="$(docker port "$redis_container" 6379/tcp | awk -F: 'NR == 1 {print $NF}')"

export DATABASE_URL="postgresql://authme:authme-ci-only@127.0.0.1:${postgres_port}/authme_test"
export REDIS_URL="redis://127.0.0.1:${redis_port}/0"
export AUTHME_SMOKE_DATABASE_URL="$DATABASE_URL"
export AUTHME_JWKS_DIR="${RUNNER_TEMP:-/tmp}/authme-jwks-${suffix}"
export AUTHME_COOKIE_KEYS="$(openssl rand -hex 32),$(openssl rand -hex 32)"
export AUTHME_CSRF_SECRET="$(openssl rand -hex 32)"
export AUTHME_PASSWORD_PEPPER="$(openssl rand -hex 32)"
export AUTHME_SUBJECT_SALT="$(openssl rand -hex 32)"
export AUTHME_FIELD_ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export AUTHME_ADMIN_TOKEN="$(openssl rand -hex 32)"
export AUTHME_SMOKE_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"

mkdir -p "$AUTHME_JWKS_DIR"
npm run keys:generate
npm run db:migrate
npm run test:postgres
npm run smoke
