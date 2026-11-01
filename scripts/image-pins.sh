#!/usr/bin/env bash
# Container image pins (PLAN 4.5, ENGINEERING_RULES R11 and R18).
#
# The images of the workflows (`container:` and `services:` of the jobs, the BuildKit image of the release) and of the Dockerfile
# are pinned by digest: `rust:1.99.1-bookworm@sha256:...`. Dependabot keeps the Dockerfile current, but its docker ecosystem does
# not read the images of a workflow, so those digests would stay where they were put. This script is the check that they do not:
# the weekly workflow `image-pins.yml` runs `check`, and when it fails it shows the patch that `update` makes in its summary, which a
# person reviews and lands as a pull request (the job reads the repository and nothing more, so it opens no pull request itself).
#
#   scripts/image-pins.sh list        every pin, as `file:line  image@digest`
#   scripts/image-pins.sh agree       the same `name:tag` carries the same digest everywhere (offline; part of the `checks` job)
#   scripts/image-pins.sh check       every pin against its registry: fails for a tag that points to another digest now (needs curl
#                                     and jq; anonymous access to the registries is enough)
#   scripts/image-pins.sh update      rewrites the stale pins in place; review the diff, the tags themselves stay as they are
#   scripts/image-pins.sh --self-test checks the parsing and the rules against sample text and needs nothing else
#
# Environment: PIN_FILES (the files to read, default: the workflows and the Dockerfile of the checkout), REGISTRY_DIGEST_COMMAND
# (a command that prints the digest of the image `name:tag` it is given, instead of asking the registry; for tests).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# `name:tag@sha256:digest`, with an optional registry host and any number of path components.
pin_pattern='[a-z0-9][a-z0-9._-]*(:[0-9]+)?(/[a-z0-9._-]+)*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}'

files() {
  if [ -n "${PIN_FILES:-}" ]; then
    # shellcheck disable=SC2086 # a list of paths on purpose
    printf '%s\n' ${PIN_FILES}
  else
    find "${root}/.github/workflows" -maxdepth 1 -name '*.yml' | sort
    [ ! -f "${root}/Dockerfile" ] || printf '%s\n' "${root}/Dockerfile"
  fi
}

# Every pin as `file<TAB>line<TAB>name:tag<TAB>digest`.
pins() {
  local file
  while IFS= read -r file; do
    # `grep -no` prints `line:match`; the match itself contains colons, so the line number is split off at the first one.
    grep -nEo "${pin_pattern}" "${file}" | while IFS=: read -r line match; do
      printf '%s\t%s\t%s\t%s\n' "${file}" "${line}" "${match%@sha256:*}" "${match##*@sha256:}"
    done || true
  done < <(files)
}

# The images that are pinned to more than one digest, with the places of each digest.
disagreements() {
  pins | awk -F '\t' -v root="${root}/" '
    {
      where = $1; sub(root, "", where)
      key = $3 SUBSEP $4
      if (!(key in places)) { variants[$3]++ }
      places[key] = places[key] " " where ":" $2
    }
    END {
      for (key in places) {
        split(key, parts, SUBSEP)
        if (variants[parts[1]] > 1) { printf "%s@sha256:%s at%s\n", parts[1], parts[2], places[key] }
      }
    }' | sort
}

agree() {
  local found
  found="$(disagreements)"
  if [ -n "${found}" ]; then
    echo "The same image is pinned to different digests; run scripts/image-pins.sh update (or edit by hand):" >&2
    echo "${found}" >&2
    return 1
  fi
  echo "image pins agree: $(pins | wc -l | tr -d ' ') pins of $(pins | cut -f3 | sort -u | wc -l | tr -d ' ') images"
}

# The digest the registry gives to `name:tag` now (the manifest list, as `docker pull` resolves it).
registry_digest() {
  local image="$1"
  if [ -n "${REGISTRY_DIGEST_COMMAND:-}" ]; then
    ${REGISTRY_DIGEST_COMMAND} "${image}"
    return
  fi
  local name="${image%:*}" tag="${image##*:}" registry repository
  case "${name}" in
    */*)
      if [[ "${name%%/*}" == *.* || "${name%%/*}" == *:* || "${name%%/*}" == localhost ]]; then
        registry="${name%%/*}"
        repository="${name#*/}"
      else
        registry="registry-1.docker.io"
        repository="${name}"
      fi
      ;;
    *)
      registry="registry-1.docker.io"
      repository="library/${name}"
      ;;
  esac
  local accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
  local url="https://${registry}/v2/${repository}/manifests/${tag}"
  local headers token=""
  headers="$(curl --silent --head --location --retry 3 --header "Accept: ${accept}" "${url}" || true)"
  if grep -qiE '^HTTP/[0-9.]+ 401' <<<"${headers}"; then
    # The anonymous token the registry names in its challenge.
    local challenge realm service scope
    challenge="$(grep -i '^www-authenticate:' <<<"${headers}" | head -n 1 | tr -d '\r')"
    realm="$(sed -nE 's/.*realm="([^"]*)".*/\1/p' <<<"${challenge}")"
    service="$(sed -nE 's/.*service="([^"]*)".*/\1/p' <<<"${challenge}")"
    scope="$(sed -nE 's/.*scope="([^"]*)".*/\1/p' <<<"${challenge}")"
    token="$(curl --silent --fail --retry 3 --get --data-urlencode "service=${service}" \
      --data-urlencode "scope=${scope:-repository:${repository}:pull}" "${realm}" | jq -r '.token // .access_token')"
    headers="$(curl --silent --head --location --retry 3 --header "Accept: ${accept}" \
      --header "Authorization: Bearer ${token}" "${url}")"
  fi
  local digest
  digest="$(grep -i '^docker-content-digest:' <<<"${headers}" | head -n 1 | tr -d '\r' | awk '{print $2}')"
  case "${digest}" in
    sha256:*) printf '%s\n' "${digest#sha256:}" ;;
    *)
      echo "no digest from ${registry} for ${name}:${tag}" >&2
      return 1
      ;;
  esac
}

# Every stale pin as `name:tag<TAB>pinned<TAB>current`, once per image and digest.
stale() {
  local image pinned current
  while IFS=$'\t' read -r image pinned; do
    current="$(registry_digest "${image}")" || return 1
    if [ "${current}" != "${pinned}" ]; then
      printf '%s\t%s\t%s\n' "${image}" "${pinned}" "${current}"
    fi
  done < <(pins | cut -f3,4 | sort -u)
}

check() {
  local found
  found="$(stale)" || return 1
  if [ -z "${found}" ]; then
    echo "every pinned image is current"
    return 0
  fi
  {
    echo "Pinned images whose tag points to another digest now:"
    while IFS=$'\t' read -r image pinned current; do
      printf '  %s\n    pinned  sha256:%s\n    current sha256:%s\n' "${image}" "${pinned}" "${current}"
    done <<<"${found}"
    echo "Run scripts/image-pins.sh update, review the diff and open a pull request."
  } | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}" >&2
  return 1
}

# `text` as a regular expression that matches exactly that text: the `.` of `1.99.1` is a dot, not any character.
regex_escape() {
  printf '%s' "$1" | sed -e 's/[].[\*^$|]/\\&/g'
}

update() {
  local found file image pinned current
  found="$(stale)" || return 1
  [ -n "${found}" ] || { echo "every pinned image is current"; return 0; }
  while IFS=$'\t' read -r image pinned current; do
    while IFS= read -r file; do
      sed -i.bak "s|$(regex_escape "${image}")@sha256:${pinned}|${image}@sha256:${current}|g" "${file}"
      rm -f "${file}.bak"
    done < <(files)
    echo "${image}: sha256:${pinned} -> sha256:${current}"
  done <<<"${found}"
}

self_test() {
  local dir
  dir="$(mktemp -d)"
  trap 'rm -rf "${dir}"' RETURN
  local a="1111111111111111111111111111111111111111111111111111111111111111"
  local b="2222222222222222222222222222222222222222222222222222222222222222"
  local c="3333333333333333333333333333333333333333333333333333333333333333"
  cat >"${dir}/one.yml" <<EOF
jobs:
  build:
    container:
      image: rust:1.99.1-bookworm@sha256:${a}
    services:
      postgres:
        image: postgres:18@sha256:${b}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: docker run gcr.io/distroless/cc-debian13:nonroot@sha256:${c} ghcr.io/example/tool:v1@sha256:${c}
EOF
  cp "${dir}/one.yml" "${dir}/two.yml"
  export PIN_FILES="${dir}/one.yml ${dir}/two.yml"
  [ "$(pins | wc -l | tr -d ' ')" = 8 ] || { echo "self-test: expected 8 pins, got $(pins | wc -l)" >&2; return 1; }
  [ "$(pins | cut -f3 | sort -u | wc -l | tr -d ' ')" = 4 ] || { echo "self-test: expected 4 images" >&2; return 1; }
  pins | cut -f3 | grep -qx 'gcr.io/distroless/cc-debian13:nonroot' || { echo "self-test: a registry host is part of the name" >&2; return 1; }
  agree >/dev/null || { echo "self-test: identical pins must agree" >&2; return 1; }
  sed -i.bak "s|rust:1.99.1-bookworm@sha256:${a}|rust:1.99.1-bookworm@sha256:${b}|" "${dir}/two.yml" && rm -f "${dir}/two.yml.bak"
  if agree >/dev/null 2>&1; then echo "self-test: different digests of one image must not agree" >&2; return 1; fi
  # The registry stand-in answers `c` for everything: every pin of `a` and `b` is stale, the ones of `c` are not.
  cat >"${dir}/registry.sh" <<EOF
#!/usr/bin/env bash
echo "${c}"
EOF
  chmod +x "${dir}/registry.sh"
  export REGISTRY_DIGEST_COMMAND="${dir}/registry.sh"
  if check >/dev/null 2>&1; then echo "self-test: stale pins must fail the check" >&2; return 1; fi
  [ "$(stale | wc -l | tr -d ' ')" = 3 ] || { echo "self-test: expected 3 stale pins, got $(stale | wc -l)" >&2; return 1; }
  update >/dev/null
  check >/dev/null || { echo "self-test: after the update every pin must be current" >&2; return 1; }
  agree >/dev/null || { echo "self-test: after the update the pins must agree" >&2; return 1; }
  grep -q "rust:1.99.1-bookworm@sha256:${c}" "${dir}/one.yml" || { echo "self-test: the update rewrote the first file" >&2; return 1; }
  # The `.` of a version is a dot and nothing else: the pin of an image that differs in that place is another image's, and is not
  # rewritten when the first one is (here the registry says `a` for the one with the letters, which is current, and `c` for the rest).
  printf 'image: rust:1x99x1-bookworm@sha256:%s\nimage: rust:1.99.1-bookworm@sha256:%s\n' "${a}" "${a}" >"${dir}/three.yml"
  cat >"${dir}/registry-dots.sh" <<EOF
#!/usr/bin/env bash
case "\$1" in rust:1x99x1-bookworm) echo "${a}" ;; *) echo "${c}" ;; esac
EOF
  chmod +x "${dir}/registry-dots.sh"
  PIN_FILES="${dir}/three.yml" REGISTRY_DIGEST_COMMAND="${dir}/registry-dots.sh" update >/dev/null \
    || { echo "self-test: the update of similar names failed" >&2; return 1; }
  grep -q "rust:1x99x1-bookworm@sha256:${a}" "${dir}/three.yml" || { echo "self-test: the dots of a name matched any character" >&2; return 1; }
  grep -q "rust:1.99.1-bookworm@sha256:${c}" "${dir}/three.yml" || { echo "self-test: the pin that was stale was not rewritten" >&2; return 1; }
  grep -q 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' "${dir}/one.yml" || { echo "self-test: an action pin was touched" >&2; return 1; }
  echo "image-pins self-test passed"
}

case "${1:-}" in
  list) pins | awk -F '\t' '{ sub(".*/", "", $1); printf "%s:%s  %s@sha256:%s\n", $1, $2, $3, $4 }' ;;
  agree) agree ;;
  check) check ;;
  update) update ;;
  --self-test) self_test ;;
  *)
    echo "usage: scripts/image-pins.sh list|agree|check|update|--self-test" >&2
    exit 2
    ;;
esac
