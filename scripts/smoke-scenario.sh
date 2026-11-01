#!/usr/bin/env bash
# One scenario against a running Davhaven, over HTTP only (curl and python3): provision a user through the
# management API, let a DAV client write an event with the user's app password, read it back through the API with
# the user's own token, write a second event through the API and read it over DAV.
#
# The image smoke test (scripts/image-smoke.sh) runs it against the container; it works against any instance whose
# tenant exists and whose administration token you hold:
#
#   DAVHAVEN_TENANT=acme DAVHAVEN_DOMAIN=acme.example scripts/smoke-scenario.sh "$(cat admin-token)"
#
# Environment (defaults are the listeners of the default configuration on this host):
#   DAVHAVEN_PUBLIC_URL    DAV and web listener   (http://127.0.0.1:8080)
#   DAVHAVEN_INTERNAL_URL  management API listener (http://127.0.0.1:8081)
#   DAVHAVEN_TENANT        slug of the tenant     (smoke)
#   DAVHAVEN_DOMAIN        login domain of the tenant (smoke.example)
#   DAVHAVEN_OTHER_TENANT  slug of a second tenant: when set, the scenario also checks that the two tenants see nothing of
#                           each other (404); DAVHAVEN_OTHER_TOKEN is the administration token of that tenant
#
# It creates the user `smoke-olivia` and leaves it in place; running it twice against one tenant fails on the
# second run because the app password label and the events exist already, which is fine for a throw-away instance.
set -euo pipefail

token="${1:?usage: smoke-scenario.sh ADMIN_TOKEN}"
public="${DAVHAVEN_PUBLIC_URL:-http://127.0.0.1:8080}"
internal="${DAVHAVEN_INTERNAL_URL:-http://127.0.0.1:8081}"
tenant="${DAVHAVEN_TENANT:-smoke}"
domain="${DAVHAVEN_DOMAIN:-smoke.example}"
user="smoke-olivia"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() {
  echo "scenario failed: $*" >&2
  exit 1
}

# request METHOD URL [curl arguments...]: prints the HTTP status, leaves the body in ${work}/body.
request() {
  local method="$1" url="$2"
  shift 2
  curl --silent --show-error --max-time 30 --output "${work}/body" --write-out '%{http_code}' \
    --request "${method}" "$@" "${url}"
}

# json PATH: a member of the JSON body of the last request; PATH is dot separated, numbers index lists.
json() {
  python3 - "${work}/body" "$1" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[int(part)] if isinstance(value, list) else value[part]
print(value)
PY
}

# path_of URL: the path of a `dav_url`, which the API builds from `server.public_base_url` and which therefore names the
# public address of the deployment, not the one this script talks to.
path_of() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *)
      local rest="${1#*://}"
      printf '/%s' "${rest#*/}"
      ;;
  esac
}

# expect EXPECTED ACTUAL WHAT
expect() {
  if [ "$1" != "$2" ]; then
    echo "--- response body:" >&2
    cat "${work}/body" >&2
    echo >&2
    fail "$3: expected HTTP $1, got $2"
  fi
}

# contains TEXT WHAT: the last body contains TEXT.
contains() {
  grep --quiet --fixed-strings -- "$1" "${work}/body" || {
    echo "--- response body:" >&2
    cat "${work}/body" >&2
    echo >&2
    fail "$2: the body does not contain '$1'"
  }
}

api="${internal}/api/v1/tenants/${tenant}"
admin=(--header "Authorization: Bearer ${token}" --header "Content-Type: application/json")

echo "discovery: the well-known redirect and the DAV challenge"
expect 301 "$(request GET "${public}/.well-known/caldav")" "the well-known redirect"
expect 401 "$(request PROPFIND "${public}/dav/principals/${tenant}/${user}/" --header 'Depth: 0')" "an anonymous PROPFIND"
expect 401 "$(request GET "${api}/principals")" "an anonymous API request"

echo "provisioning: a user, an app password and a personal API token"
expect 201 "$(request PUT "${api}/principals/${user}" "${admin[@]}" \
  --data "{\"kind\":\"user\",\"display_name\":\"Olivia\",\"email\":\"${user}@${domain}\"}")" "creating the user"
expect 201 "$(request POST "${api}/principals/${user}/app-passwords" "${admin[@]}" --data '{"label":"smoke"}')" \
  "creating the app password"
password="$(json password)"
expect 201 "$(request POST "${api}/api-tokens" "${admin[@]}" \
  --data "{\"kind\":\"principal\",\"principal\":\"${user}\",\"label\":\"smoke\",\"scopes\":[\"calendars:read\",\"events:read\",\"events:write\"]}")" \
  "creating the API token"
own="$(json secret)"
personal=(--header "Authorization: Bearer ${own}" --header "Content-Type: application/json")
login="${user}@${domain}"

expect 200 "$(request GET "${api}/principals/${user}/calendars" "${personal[@]}")" "listing the calendars"
slug="$(json items.0.slug)"
collection="$(path_of "$(json items.0.dav_url)")"

echo "DAV: log in with the app password, write an event"
expect 207 "$(request PROPFIND "${public}/dav/principals/${tenant}/${user}/" --user "${login}:${password}" \
  --header 'Depth: 0' --header 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><displayname/></prop></propfind>')" "the principal PROPFIND"
contains "Olivia" "the principal PROPFIND"
expect 401 "$(request PROPFIND "${public}/dav/principals/${tenant}/${user}/" --user "${login}:not-the-password" \
  --header 'Depth: 0')" "a wrong password"

printf 'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Davhaven//smoke//EN\r\nBEGIN:VEVENT\r\nUID:smoke-kickoff@example.org\r\nDTSTAMP:20270301T100000Z\r\nDTSTART:20270302T100000Z\r\nDTEND:20270302T110000Z\r\nSUMMARY:Kickoff\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n' \
  >"${work}/kickoff.ics"
expect 201 "$(request PUT "${public}${collection}kickoff.ics" --user "${login}:${password}" \
  --header 'Content-Type: text/calendar; charset=utf-8' --data-binary "@${work}/kickoff.ics")" "the DAV PUT"

echo "API: the event is there; write another one"
expect 200 "$(request GET "${api}/principals/${user}/calendars/${slug}/objects" "${personal[@]}")" "listing the events"
[ "$(json items.0.summary)" = "Kickoff" ] || fail "the API does not show the event the DAV client wrote"
expect 201 "$(request PUT "${api}/principals/${user}/calendars/${slug}/objects/by-key/from-the-api" "${personal[@]}" \
  --data '{"summary":"From the API","start":{"date_time":"2027-03-03T10:00:00Z"},"end":{"date_time":"2027-03-03T11:00:00Z"}}')" \
  "the API write"
dav_url="$(path_of "$(json dav_url)")"

echo "DAV: the event of the API is there"
expect 200 "$(request GET "${public}${dav_url}" --user "${login}:${password}")" "the DAV GET"
contains "SUMMARY:From the API" "the DAV GET"

# Tenant isolation (ENGINEERING_RULES R4): with a second tenant, the resources of this one are invisible to it, whatever its
# credentials are, and the other way round: 404, and nothing of the other tenant's data in the body.
if [ -n "${DAVHAVEN_OTHER_TENANT:-}" ]; then
  other="${DAVHAVEN_OTHER_TENANT}"
  other_token="${DAVHAVEN_OTHER_TOKEN:?DAVHAVEN_OTHER_TOKEN is the administration token of the other tenant}"
  echo "isolation: '${other}' and '${tenant}' see nothing of each other"
  expect 404 "$(request GET "${api}/principals/${user}" --header "Authorization: Bearer ${other_token}")" \
    "the administration token of another tenant on a user of this one"
  if grep --quiet --fixed-strings -- "Olivia" "${work}/body"; then fail "the 404 for another tenant leaks the user"; fi
  expect 404 "$(request GET "${internal}/api/v1/tenants/${other}/principals" "${admin[@]}")" \
    "the administration token of this tenant on another tenant"
  expect 404 "$(request PROPFIND "${public}/dav/principals/${other}/${user}/" --user "${login}:${password}" \
    --header 'Depth: 0')" "a DAV login of this tenant on the principal path of another"
  expect 404 "$(request GET "${public}/dav/calendars/${other}/${user}/${slug}/kickoff.ics" --user "${login}:${password}")" \
    "a DAV login of this tenant on a calendar path of another"
fi

echo "scenario passed"
