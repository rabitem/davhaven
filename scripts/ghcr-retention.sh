#!/usr/bin/env bash
# Retention of the container images in GHCR (PLAN 4.5), run by .github/workflows/ghcr-retention.yml.
#
# A package version is one image manifest (a digest) with any number of tags. The rules decide per version:
#
#   keep   every version with a release tag (any tag that is neither `main-<sha>` nor the legacy `deployed-<date>`: `1.2.3`);
#   keep   the newest KEEP_MAIN versions with a `main-<sha>` tag (default 30);
#   keep   every version younger than KEEP_DAYS days, whatever its tags, untagged ones included (default 30);
#   delete everything else.
#
# The rules need nothing from outside this repository: no deployment repository has to tag what it ran, so none needs write
# access to the package. The price is the usual one of a pinned digest: an image of a `main-*` build that is neither among the
# newest KEEP_MAIN nor younger than KEEP_DAYS days is gone from the registry, so a deployment that must be able to pull its
# image for longer runs a release (a `v*` tag, which stays for ever) or redeploys within that window. A `deployed-YYYYMMDD` tag
# that an earlier convention put on a version does not keep it.
#
# Environment: OWNER (the user or organisation that owns the package), PACKAGE (default `davhaven`), GH_TOKEN (needs
# `packages: write`), DRY_RUN (`true` lists and deletes nothing; default `true`), MAX_DELETIONS (default 100: a run that
# would delete more stops without deleting anything), NOW (epoch seconds, for tests), VERSIONS_FILE (a JSON array of
# package versions instead of the API, for tests).
#
#   scripts/ghcr-retention.sh --self-test   checks the rules against sample data and needs nothing else
set -euo pipefail

keep_main="${KEEP_MAIN:-30}"
keep_days="${KEEP_DAYS:-30}"
max_deletions="${MAX_DELETIONS:-100}"
dry_run="${DRY_RUN:-true}"

# The versions to delete, as JSON lines {id, created_at, tags}. Input: the JSON array of versions of the packages API.
select_deletions() {
  local now="$1"
  jq --compact-output --argjson now "${now}" --argjson keep_main "${keep_main}" --argjson keep_days "${keep_days}" '
    def tags: (.metadata.container.tags // []);
    def is_main: any(tags[]; startswith("main-"));
    def is_release: any(tags[]; (startswith("main-") or startswith("deployed-")) | not);
    def age_days: ($now - (.created_at | fromdateiso8601)) / 86400;
    . as $all
    | ([$all[] | select(is_main)] | sort_by(.created_at) | reverse | .[:$keep_main] | map(.id)) as $newest_main
    | $all[]
    | select(
        (is_release | not)
        and ((.id | IN($newest_main[])) | not)
        and (age_days >= $keep_days)
      )
    | {id, created_at, tags: tags}
  '
}

self_test() {
  local hour=3600 now=1793000000 # 2026-10-26
  local dir
  dir="$(mktemp -d)"
  trap 'rm -rf "${dir}"' RETURN
  # One version of the sample: its id, its age in hours and its tags.
  sample() {
    local id="$1" age_hours="$2"
    shift 2
    local tags="" tag
    for tag in "$@"; do tags="${tags:+${tags},}\"${tag}\""; done
    local created
    created="$(date -u -d "@$((now - age_hours * hour))" +%Y-%m-%dT%H:%M:%SZ)"
    printf '{"id":%s,"created_at":"%s","metadata":{"container":{"tags":[%s]}}}' "${id}" "${created}" "${tags}"
  }
  # Runs the rules over the versions that the function `$1` prints, and checks which ones they delete.
  expect() {
    local name="$1" want="$2" builder="$3" got
    {
      echo "["
      "${builder}"
      echo "]"
    } >"${dir}/versions.json"
    got="$(select_deletions "${now}" <"${dir}/versions.json" | jq --slurp --compact-output 'map(.id) | sort')"
    if [ "${got}" != "${want}" ]; then
      echo "self-test failed (${name}): the rules delete ${got}, expected ${want}" >&2
      return 1
    fi
  }

  # Forty builds, two a day for twenty days (ids 1..40, newest first) and twenty more, one a day from 31 days on (41..60):
  # the newest 30 stay by their count, the ten that follow stay because they are younger than 30 days, the twenty that are
  # older than both go. Around them: a release stays however old it is, also when it has a main tag as well; a tag that is
  # unknown to the rules counts as a release; the legacy `deployed-` tag keeps nothing; young versions stay whatever they are
  # (untagged, deployed-tagged, odd), old untagged ones go.
  mixed() {
    local i
    for i in $(seq 1 40); do
      sample "${i}" "$((i * 12))" "main-sha${i}"
      echo ","
    done
    for i in $(seq 41 60); do
      sample "${i}" "$(((i - 10) * 24))" "main-sha${i}"
      echo ","
    done
    sample 100 9600 "1.2.3"; echo ","                                 # a release stays however old it is
    sample 101 9600 "main-old" "1.0.0"; echo ","                      # a release that also has a main tag stays
    sample 102 4800 "main-old2" "deployed-20260301"; echo ","        # old, beyond the newest 30, deployed-tagged: goes
    sample 103 48 "deployed-20261024"; echo ","                       # young, only a legacy tag: stays by age
    sample 104 120; echo ","                                          # a fresh untagged version stays
    sample 105 2160; echo ","                                         # an old untagged version goes
    sample 106 9600 "staging"; echo ","                               # a tag the rules do not know is treated like a release
    sample 107 719                                                    # untagged and an hour short of 30 days: only its age keeps it
  }
  expect "mixed" "[41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,102,105]" mixed || return 1
  # The cut-off is exact: 30 days is no longer young, 30 days minus an hour still is. No build is kept by its count here
  # (KEEP_MAIN=0) and none carries a release tag, so that only the age rule decides, for tagged and untagged versions alike.
  boundary() {
    sample 1 720 "main-sha1"; echo ","
    sample 2 719 "main-sha2"; echo ","
    sample 3 719; echo ","
    sample 4 720
  }
  local saved_keep_main="${keep_main}"
  keep_main=0
  expect "the age limit is 30 days" "[1,4]" boundary || return 1
  keep_main="${saved_keep_main}"
  # Few builds are all kept, however old: the count and not the age keeps the newest ones.
  few() {
    local i
    for i in $(seq 1 5); do
      sample "${i}" "$((24 * 100 * i))" "main-sha${i}"
      if [ "${i}" -lt 5 ]; then echo ","; fi
    done
  }
  expect "few old builds" "[]" few || return 1
  echo "self-test passed"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

owner="${OWNER:?OWNER names the user or organisation that owns the package}"
package="${PACKAGE:-davhaven}"
now="${NOW:-$(date -u +%s)}"

if [ -n "${VERSIONS_FILE:-}" ]; then
  versions="$(cat "${VERSIONS_FILE}")"
else
  kind="$(gh api "/users/${owner}" --jq '.type')"
  case "${kind}" in
    Organization) base="/orgs/${owner}/packages/container/${package}" ;;
    *) base="/users/${owner}/packages/container/${package}" ;;
  esac
  versions="$(gh api --paginate "${base}/versions?per_page=100" | jq --slurp 'add // []')"
fi

total="$(jq 'length' <<<"${versions}")"
mapfile -t doomed < <(select_deletions "${now}" <<<"${versions}")
count="${#doomed[@]}"
echo "${package}: ${total} versions, ${count} to delete (dry run: ${dry_run})"
for entry in "${doomed[@]}"; do
  jq --raw-output '"  \(.id)  \(.created_at)  \(.tags | join(","))"' <<<"${entry}"
done

if [ "${count}" -eq 0 ]; then
  exit 0
fi
if [ "${count}" -ge "${total}" ]; then
  echo "refusing to delete every version of the package: the rules are wrong or the listing is incomplete" >&2
  exit 1
fi
if [ "${count}" -gt "${max_deletions}" ]; then
  echo "refusing to delete ${count} versions in one run (MAX_DELETIONS is ${max_deletions})" >&2
  exit 1
fi
if [ "${dry_run}" != "false" ]; then
  echo "dry run: nothing was deleted"
  exit 0
fi
for entry in "${doomed[@]}"; do
  id="$(jq --raw-output '.id' <<<"${entry}")"
  gh api --method DELETE "${base}/versions/${id}" >/dev/null
  echo "deleted version ${id}"
done
