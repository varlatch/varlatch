#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Proceeds only when a version is known to be unpublished: the release
# workflow's go-image runs it before it builds, as a version's image is
# pushed once (go/image/README.md). It exits 0 only on two explicit answers:
#
# - the releases API answers 404 "Not Found" for the tag (GET
#   /repos/<repo>/releases/tags/<tag>);
# - after a successful token exchange with the registry (200 and a token),
#   the registry answers 404 for the exact manifest tag with one error,
#   MANIFEST_UNKNOWN: the package exists, the tag does not. The package
#   must exist already (ghcr.io/varlatch/varlatchd holds the TypeScript
#   line's images); a registry that does not know the package is not an
#   answer about the tag, and stops it.
#
# Anything else stops it (exit 1): a release or a tag that exists, and
# every answer that does not say "not found" (401, 403, 429, 5xx, a 404
# from the token endpoint, a 404 with other or more error codes, a body it
# cannot read, a transfer curl did not complete, no answer). Transient
# answers are retried by curl first. A draft release is invisible to the
# releases API; the release workflow creates none.
#
# Usage: check-unpublished.sh --repo <owner/name> --tag <tag> --image <host/name> --version <version>
#          [--api <url>] [--registry <url>]
# GH_TOKEN authenticates to both (as GITHUB_ACTOR on the registry). --api
# defaults to GITHUB_API_URL or https://api.github.com, --registry to
# https://<host of --image>.
set -euo pipefail

usage() { echo "usage: check-unpublished.sh --repo <owner/name> --tag <tag> --image <host/name> --version <version> [--api <url>] [--registry <url>]" >&2; exit 64; }
repo='' tag='' image='' version='' api=${GITHUB_API_URL:-https://api.github.com} registry=''
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --repo) repo=$2 ;;
    --tag) tag=$2 ;;
    --image) image=$2 ;;
    --version) version=$2 ;;
    --api) api=$2 ;;
    --registry) registry=$2 ;;
    *) usage ;;
  esac
  shift 2
done
if [ -z "$repo" ] || [ -z "$tag" ] || [ -z "$image" ] || [ -z "$version" ]; then usage; fi
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || usage
[[ "$tag" =~ ^[A-Za-z0-9_.+-]+$ ]] || usage
[[ "$version" =~ ^[A-Za-z0-9_.-]+$ ]] || usage
[[ "$image" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+$ ]] || usage
[ -n "${GH_TOKEN:-}" ] || { echo "check-unpublished: GH_TOKEN is not set" >&2; exit 64; }
host=${image%%/*} name=${image#*/}
registry=${registry:-https://$host}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stop() { printf 'check-unpublished: %s\n' "$*" >&2; exit 1; }

# request <what> <curl config> <curl args...>: one request, each with its
# own response file, so nothing from an earlier answer is ever read as this
# one's. Sets $status and $body only for a transfer curl completed (exit 0,
# the whole body, an HTTP status); anything else stops, naming <what> and
# curl's error. Credentials go through curl's config on stdin, never its
# arguments.
status='' body=''
request() {
  local what=$1 config=$2 out rc=0
  shift 2
  body=$(mktemp "$work/body.XXXXXX")
  local err; err=$(mktemp "$work/err.XXXXXX")
  out=$(printf '%s\n' "$config" | curl -sS -K - --retry 2 --retry-delay 3 --max-time 60 \
    -o "$body" -w '%{http_code}' "$@" 2> "$err") || rc=$?
  [ "$rc" = 0 ] || stop "cannot tell $what: the request did not complete (curl exit $rc: $(tail -1 "$err"))"
  [[ "$out" =~ ^[1-5][0-9][0-9]$ ]] || stop "cannot tell $what: no HTTP status"
  status=$out
}
# The start of a body, for a diagnostic; never used for the token endpoint.
said() { head -c 300 "$body" | tr '\n' ' '; }

# The GitHub release.
request "whether $tag has a GitHub release" "header = \"Authorization: Bearer $GH_TOKEN\"" \
  -H 'Accept: application/vnd.github+json' "$api/repos/$repo/releases/tags/$tag"
case "$status" in
  200) stop "$tag already has a GitHub release: a published version is never pushed again" ;;
  404) jq -e '.message == "Not Found"' "$body" > /dev/null 2>&1 \
         || stop "cannot tell whether $tag has a GitHub release: 404 without the API's \"Not Found\": $(said)" ;;
  *) stop "cannot tell whether $tag has a GitHub release: HTTP $status: $(said)" ;;
esac
echo "check-unpublished: $tag has no GitHub release"

# The registry tag: a pull token first (its answers are never printed),
# then the exact manifest tag.
request "whether $image:$version exists (token exchange)" "user = \"${GITHUB_ACTOR:-token}:$GH_TOKEN\"" \
  "$registry/token?scope=repository:$name:pull&service=$host"
[ "$status" = 200 ] || stop "cannot tell whether $image:$version exists: the registry's token endpoint answered HTTP $status"
token=$(jq -r 'if (.token | type) == "string" and .token != "" then .token else empty end' "$body" 2> /dev/null) || token=''
rm -f "$body"
[ -n "$token" ] || stop "cannot tell whether $image:$version exists: the registry's token endpoint gave no token"
request "whether $image:$version exists" "header = \"Authorization: Bearer $token\"" \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  "$registry/v2/$name/manifests/$version"
case "$status" in
  200) stop "$image:$version is already in the registry: an earlier run pushed it. Re-run only the failed jobs to resume that run (go/image/README.md)." ;;
  404) jq -e '(.errors | type) == "array" and [.errors[].code] == ["MANIFEST_UNKNOWN"]' "$body" > /dev/null 2>&1 \
         || stop "cannot tell whether $image:$version exists: 404 without exactly MANIFEST_UNKNOWN: $(said)" ;;
  *) stop "cannot tell whether $image:$version exists: HTTP $status: $(said)" ;;
esac
echo "check-unpublished: $image:$version is not in the registry"
