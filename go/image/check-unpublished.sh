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
# answers are retried by curl first. A draft release (which an interrupted
# "gh release create" can leave) is not published, and the tag's endpoint
# does not show it: go/image/README.md says what to check for one.
#
# Credentials: tracing is off before any is read, whatever the caller set;
# they are never exported to the programs run here and never arguments;
# and a diagnostic is an HTTP status or curl's exit code, never a response
# or curl's own message.
#
# Usage: check-unpublished.sh --repo <owner/name> --tag <tag> --image <host/name> --version <version>
#          [--api <url>] [--registry <url>]
# GH_TOKEN authenticates to both (as GITHUB_ACTOR on the registry). --api
# defaults to GITHUB_API_URL or https://api.github.com, --registry to
# https://<host of --image>.
# First of all: no tracing (xtrace, verbose) and no automatic export, which
# a caller's "bash -x" or SHELLOPTS may have on. Then no export attribute a
# caller gave to the names that hold credentials below (a function's local
# inherits it).
set +xva
unset -v gh_token token config
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
gh_token=$GH_TOKEN
unset -v GH_TOKEN
host=${image%%/*} name=${image#*/}
registry=${registry:-https://$host}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stop() { printf 'check-unpublished: %s\n' "$*" >&2; exit 1; }

# request <what> <curl config> <curl args...>: one request, each with its
# own response file, so nothing from an earlier answer is ever read as this
# one's. Sets $status and $body only for a transfer curl completed (exit 0,
# the whole body, an HTTP status); anything else stops, naming <what> and
# curl's exit code. Credentials go through curl's config on stdin, never
# its arguments, and no other curl config is read (-q).
status='' body=''
request() {
  local what=$1 config=$2 out rc=0
  shift 2
  body=$(mktemp "$work/body.XXXXXX")
  out=$(printf '%s\n' "$config" | curl -q -s -K - --retry 2 --retry-delay 3 --max-time 60 \
    -o "$body" -w '%{http_code}' "$@" 2> /dev/null) || rc=$?
  [ "$rc" = 0 ] || stop "cannot tell $what: the request did not complete (curl exit $rc)"
  [[ "$out" =~ ^[1-5][0-9][0-9]$ ]] || stop "cannot tell $what: no HTTP status"
  status=$out
}
# Whether the body is exactly one JSON document, an object for which the jq
# condition holds.
answers() { jq -es "length == 1 and (.[0] | type == \"object\" and ($1))" "$body" > /dev/null 2>&1; }

# The GitHub release.
request "whether $tag has a GitHub release" "header = \"Authorization: Bearer $gh_token\"" \
  -H 'Accept: application/vnd.github+json' "$api/repos/$repo/releases/tags/$tag"
case "$status" in
  200) stop "$tag already has a GitHub release: a published version is never pushed again" ;;
  404) answers '.message == "Not Found"' \
         || stop "cannot tell whether $tag has a GitHub release: HTTP 404 without exactly the API's \"Not Found\"" ;;
  *) stop "cannot tell whether $tag has a GitHub release: HTTP $status" ;;
esac
echo "check-unpublished: $tag has no GitHub release"

# The registry tag: a pull token first, then the exact manifest tag. A
# token is taken only in the characters a bearer token has (RFC 6750), as
# it becomes a line of curl's config.
request "whether $image:$version exists (token exchange)" "user = \"${GITHUB_ACTOR:-token}:$gh_token\"" \
  "$registry/token?scope=repository:$name:pull&service=$host"
[ "$status" = 200 ] || stop "cannot tell whether $image:$version exists: the registry's token endpoint answered HTTP $status"
answers '.token | type == "string"' \
  || stop "cannot tell whether $image:$version exists: the registry's token endpoint gave no token (HTTP 200)"
token=$(jq -r '.token' "$body" 2> /dev/null) || token=''
rm -f "$body"
[[ "$token" =~ ^[A-Za-z0-9._~+/=-]+$ ]] \
  || stop "cannot tell whether $image:$version exists: the registry's token endpoint gave no token (HTTP 200)"
request "whether $image:$version exists" "header = \"Authorization: Bearer $token\"" \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  "$registry/v2/$name/manifests/$version"
case "$status" in
  200) stop "$image:$version is already in the registry: an earlier run pushed it. Re-run only the failed jobs to resume that run (go/image/README.md)." ;;
  404) answers '(.errors | type) == "array" and [.errors[].code] == ["MANIFEST_UNKNOWN"]' \
         || stop "cannot tell whether $image:$version exists: HTTP 404 without exactly MANIFEST_UNKNOWN" ;;
  *) stop "cannot tell whether $image:$version exists: HTTP $status" ;;
esac
echo "check-unpublished: $image:$version is not in the registry"
