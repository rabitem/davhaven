#!/usr/bin/env bash
# Smoke test of the container image (the `image` job of release.yml, PLAN 3.7): the image starts, becomes ready on /readyz and
# passes one scenario, and it does so the way the deployment runs it: as the image's non-root user with a read-only
# root filesystem and no capabilities, in production mode, connected to the database as the runtime role of
# docs/operations/database.md (an owner role migrates; the server's role is NOSUPERUSER NOBYPASSRLS and owns nothing).
#
#   scripts/image-smoke.sh IMAGE
#
# Needs docker, curl and python3 on the host and nothing else. The script is self-contained and safe on a shared build
# host: it makes a private Docker network without any route to the outside (the container has no mail relay to talk to
# and no HTTP egress), starts a throw-away PostgreSQL in it (the `postgres` image, POSTGRES_IMAGE, default `postgres:18`,
# which is also the SQL client) and runs the server in the network namespace of that container, so the database is
# `127.0.0.1` for the server, as it is on the host a deployment runs on. Nothing is published and no port of the host is
# used, so concurrent runs and the services of the host cannot collide with it; the script reaches the listeners by the
# address of the container. Every container has a memory, CPU and process limit. The network and the containers are
# removed at the end, whatever happens; if the script is killed, the label (DAVHAVEN_SMOKE_LABEL) finds them.
#
# What it checks, in order:
#   1. the image's metadata: the user, the HEALTHCHECK and the mandatory revision label;
#   2. `--version`, and that production mode refuses a configuration for the right reason: the memory store (with keys)
#      and a missing key ring (with the PostgreSQL store), each named in the error;
#   3. `migrate` with the owner role and `admin bootstrap` with the runtime role as one-off containers;
#   4. `serve`: readiness through the binary itself (`healthcheck`, what the HEALTHCHECK runs) and through /readyz,
#      which says the database is healthy (the role is bound by row-level security: a superuser or the owner would make
#      production refuse to start), then scripts/smoke-scenario.sh (provision a user, write over DAV, read through the
#      API and the other way round, and the isolation of a second tenant), and /metrics;
#   5. `admin purge-audit` with the owner role, and a SIGTERM that ends the container with exit status 0 after the log
#      says it stopped.
set -euo pipefail

image="${1:?usage: image-smoke.sh IMAGE}"
postgres_image="${POSTGRES_IMAGE:-postgres:18}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Names are unique per run: the Docker daemon of a shared host sees the containers of every job on it.
name="davhaven-smoke-$$"
network="${name}"
db="${name}-db"
tenant="smoke"
domain="smoke.example"
other_tenant="other"
other_domain="other.example"
owner="smoke_owner"
runtime="smoke_app"
database="smoke_db"
# Everything the script creates carries this label (the workflow passes one that names the run), so that a step that runs
# even after this script was killed can remove all of it: containers, the network, volumes.
label="${DAVHAVEN_SMOKE_LABEL:-davhaven.smoke=$$}"
# What every container of the test gets: limits (the server and the database are small and the test is short) and the label.
common=(--memory 1g --memory-swap 1g --cpus 2 --pids-limit 512 --label "${label}")

# psql DATABASE ARGS...: the SQL client, as the superuser of the throw-away database (the local socket of its container).
psql() {
  local target="$1"
  shift
  docker exec "${db}" psql --no-psqlrc --set ON_ERROR_STOP=1 --quiet --username postgres --dbname "${target}" "$@"
}

cleanup() {
  docker rm --force "${name}" >/dev/null 2>&1 || true
  docker rm --force "${db}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -rf "${keys:-}"
}
trap cleanup EXIT

fail() {
  echo "image smoke test failed: $*" >&2
  if docker inspect "${name}" >/dev/null 2>&1; then
    echo "--- container log:" >&2
    docker logs "${name}" >&2 || true
  fi
  exit 1
}

echo "network: private, without a route to the outside; database: a throw-away PostgreSQL"
docker network create --internal --label "${label}" "${network}" >/dev/null
# The data directory is in memory (nothing to clean up, no disk of the host is written), and the superuser is reached
# over the local socket of the container only.
docker run --detach --name "${db}" --network "${network}" "${common[@]}" --tmpfs /var/lib/postgresql \
  --env POSTGRES_PASSWORD=smoke "${postgres_image}" -c fsync=off >/dev/null
ready=false
for _ in $(seq 1 60); do
  if docker exec "${db}" pg_isready --username postgres --dbname postgres >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
"${ready}" || fail "the database did not become ready within 60 s"
# The address of the container in the private network: the listeners of the server are reached through it.
address="$(docker inspect --format "{{(index .NetworkSettings.Networks \"${network}\").IPAddress}}" "${db}")"
[ -n "${address}" ] || fail "the database container has no address in the private network"

echo "database: an owner role, a runtime role and a database, as in docs/operations/database.md"
psql postgres --command "CREATE ROLE ${owner} LOGIN PASSWORD '${owner}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
psql postgres --command "CREATE ROLE ${runtime} LOGIN PASSWORD '${runtime}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
psql postgres --command "CREATE DATABASE ${database} OWNER ${owner}"
psql "${database}" --command "
  REVOKE ALL ON SCHEMA public FROM PUBLIC;
  ALTER SCHEMA public OWNER TO ${owner};
  GRANT USAGE ON SCHEMA public TO ${runtime};
  ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${runtime};
  ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ${runtime};"
runtime_url="postgres://${runtime}:${runtime}@127.0.0.1:5432/${database}"
owner_url="postgres://${owner}:${owner}@127.0.0.1:5432/${database}"

# The configuration of the container is the environment alone, plus one key file: the processes of the smoke test
# (bootstrap, serve) share their credentials only through the key ring, so it must be the same file. The container runs
# in production mode: the server connects as the runtime role, and the owner's URL is given only to the one-off
# containers that migrate and purge the audit log.
keys="$(mktemp -d)"
chmod 755 "${keys}"
head -c 48 /dev/urandom | base64 --wrap=0 >"${keys}/key"
chmod 644 "${keys}/key"
key_ring=(--volume "${keys}:/keys:ro" --env "DAVHAVEN_SECURITY__KEYS=[{id=\"smoke\",secret_file=\"/keys/key\"}]")
settings=(
  "${key_ring[@]}"
  --env DAVHAVEN_SERVER__PUBLIC_BASE_URL=https://calendar.example.org
  --env DAVHAVEN_PLUGIN__MAIL_TRANSPORT__SMTP__HOST=smtp.invalid
  --env "DAVHAVEN_DATABASE__URL=${runtime_url}"
  --env DAVHAVEN_DATABASE__MIGRATE_ON_START=false
)
hardening=("${common[@]}" --network "container:${db}" --read-only --cap-drop ALL --security-opt no-new-privileges)

# davhaven ARGS...: a one-off container with the runtime role.
davhaven() {
  docker run --rm "${hardening[@]}" "${settings[@]}" "${image}" "$@"
}

# davhaven_as_owner ARGS...: a one-off container that also holds the owner's credentials (migrations, audit purge).
davhaven_as_owner() {
  docker run --rm "${hardening[@]}" "${settings[@]}" --env "DAVHAVEN_DATABASE__MIGRATION_URL=${owner_url}" "${image}" "$@"
}

echo "image: metadata"
[ "$(docker inspect --format '{{.Config.User}}' "${image}")" = "65532:65532" ] || fail "the image does not run as 65532:65532"
docker inspect --format '{{json .Config.Healthcheck.Test}}' "${image}" | grep --quiet 'healthcheck' \
  || fail "the image has no HEALTHCHECK that runs 'davhaven healthcheck'"
[ -n "$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${image}")" ] \
  || fail "the image has no org.opencontainers.image.revision label"

echo "image: --version and the rules of production mode, each refused for its own reason"
docker run --rm "${common[@]}" --network none "${image}" --version | grep --quiet '^davhaven ' || fail "--version does not print the version"
# Signing keys but the memory store: the store is what production refuses.
if refused="$(docker run --rm "${common[@]}" --network "container:${db}" "${key_ring[@]}" --env DAVHAVEN_SERVER__PUBLIC_BASE_URL=https://calendar.example.org \
  --env DAVHAVEN_PLUGINS__STORE=memory "${image}" config check 2>&1)"; then
  fail "production mode accepted the memory store"
fi
grep --quiet 'plugins.store' <<<"${refused}" || fail "the memory store was refused for another reason: ${refused}"
# The PostgreSQL store but no key ring: the keys are what production requires.
if refused="$(docker run --rm "${common[@]}" --network "container:${db}" --env DAVHAVEN_SERVER__PUBLIC_BASE_URL=https://calendar.example.org \
  --env DAVHAVEN_PLUGINS__STORE=postgres --env "DAVHAVEN_DATABASE__URL=${runtime_url}" "${image}" config check 2>&1)"; then
  fail "production mode accepted a configuration without signing keys"
fi
grep --quiet 'at least one key' <<<"${refused}" || fail "the missing key ring was refused for another reason: ${refused}"

echo "image: migrate (owner role) and bootstrap (runtime role)"
davhaven_as_owner migrate
token="$(davhaven admin bootstrap --tenant "${tenant}" --display-name Smoke --login-domain "${domain}" --print-token)"
case "${token}" in
  dvh_pat_*) ;;
  *) fail "admin bootstrap did not print a token" ;;
esac
other_token="$(davhaven admin bootstrap --tenant "${other_tenant}" --display-name Other --login-domain "${other_domain}" --print-token)"
case "${other_token}" in
  dvh_pat_*) ;;
  *) fail "admin bootstrap did not print a token for the second tenant" ;;
esac

echo "image: serve"
# The internal and the ops listener bind to the loopback address by default, which only the container itself reaches; the
# private network is what keeps them from anybody else here, so they listen on every address of the container.
docker run --detach --name "${name}" "${hardening[@]}" "${settings[@]}" \
  --env DAVHAVEN_SERVER__LISTENERS__INTERNAL__BIND=0.0.0.0:8081 --env DAVHAVEN_SERVER__LISTENERS__OPS__BIND=0.0.0.0:9090 \
  "${image}" serve >/dev/null
ready=false
for _ in $(seq 1 90); do
  if [ "$(docker inspect --format '{{.State.Running}}' "${name}")" != "true" ]; then
    fail "the container stopped before it was ready"
  fi
  if docker exec "${name}" /usr/local/bin/davhaven healthcheck >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
"${ready}" || fail "the container did not become ready within 90 s"
readiness="$(curl --fail --silent --show-error "http://${address}:9090/readyz")"
echo "${readiness}"
grep --quiet '"name":"database","status":"healthy"' <<<"${readiness}" \
  || fail "the database is not healthy under the runtime role: ${readiness}"

echo "image: scenario"
DAVHAVEN_PUBLIC_URL="http://${address}:8080" DAVHAVEN_INTERNAL_URL="http://${address}:8081" \
  DAVHAVEN_TENANT="${tenant}" DAVHAVEN_DOMAIN="${domain}" DAVHAVEN_OTHER_TENANT="${other_tenant}" \
  DAVHAVEN_OTHER_TOKEN="${other_token}" "${here}/smoke-scenario.sh" "${token}" || fail "the scenario failed"
# The output is read into a variable first: `grep --quiet` stops at the first match, which would make curl fail with
# "Failure writing output" (and the pipeline fail with it, under pipefail) once the body is larger than a pipe buffer.
metrics="$(curl --fail --silent --show-error "http://${address}:9090/metrics")"
grep --quiet '^davhaven_http_requests_total' <<<"${metrics}" || fail "/metrics does not show the requests of the scenario"

echo "image: audit retention (owner role)"
purged="$(davhaven_as_owner admin purge-audit)"
grep --quiet 'audit events removed' <<<"${purged}" || fail "admin purge-audit did not report: ${purged}"

echo "image: SIGTERM"
docker stop --time 30 "${name}" >/dev/null
[ "$(docker inspect --format '{{.State.ExitCode}}' "${name}")" = "0" ] || fail "the container did not exit with status 0 on SIGTERM"
server_log="$(docker logs "${name}" 2>&1)"
grep --quiet '"message":"stopped"' <<<"${server_log}" || fail "the log does not say that the server stopped"

echo "image smoke test passed"
