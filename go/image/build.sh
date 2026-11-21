#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the single-container image (go/image/Dockerfile) from a directory
# of Go release assets, as go/release/build-assets.sh writes it.
#
#   build.sh --version <version> --assets <dir> --tag <image> --platforms <list> (--load | --check)
#
#   --load    one platform, loaded into the local Docker (tests, the
#             conformance target)
#   --check   every platform built, nothing kept (a pull request)
#
# Nothing here pushes, signs or publishes: the release workflow does, from
# the same assets.
set -euo pipefail

stop() { printf 'image build: %s\n' "$*" >&2; exit 1; }
version='' assets='' tag='' platforms='' mode=''
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=${2:-}; shift 2 ;;
    --assets) assets=${2:-}; shift 2 ;;
    --tag) tag=${2:-}; shift 2 ;;
    --platforms) platforms=${2:-}; shift 2 ;;
    --load | --check) mode=$1; shift ;;
    *) stop "unknown option $1" ;;
  esac
done
[ -n "$version" ] && [ -n "$assets" ] && [ -n "$tag" ] && [ -n "$platforms" ] && [ -n "$mode" ] || stop "usage: build.sh --version <v> --assets <dir> --tag <image> --platforms <list> (--load | --check)"
[[ "$version" =~ ^[0-9A-Za-z.+-]+$ ]] || stop "not a version: $version"
IFS=, read -ra list <<< "$platforms"
[ "$mode" != --load ] || [ "${#list[@]}" -eq 1 ] || stop "--load takes one platform"
for p in "${list[@]}"; do
  case "$p" in linux/amd64 | linux/arm64) ;; *) stop "not a platform the image is built for: $p" ;; esac
  arch=${p#linux/}
  for f in "varlatchd-$version-linux-$arch" "varlatch-$version-linux-$arch"; do
    [ -f "$assets/$f" ] || stop "$assets has no $f"
  done
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
out=(--output type=cacheonly)
[ "$mode" != --load ] || out=(--load)
docker buildx build --file "$repo/go/image/Dockerfile" --build-context "assets=$assets" \
  --build-arg "VERSION=$version" --platform "$platforms" --tag "$tag" "${out[@]}" "$repo"
