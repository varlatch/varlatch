#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the single-container image (go/image/Dockerfile) from a directory
# of Go release assets, as go/release/build-assets.sh writes it.
#
#   build.sh --version <version> --assets <dir> --tag <image> --platforms <list> (--load | --check)
#   build.sh ... --push --metadata-file <file> [--sbom]
#
#   --load    one platform, loaded into the local Docker (tests, the
#             conformance target)
#   --check   every platform built, nothing kept (a pull request)
#   --push    every platform built and pushed as one index under --tag,
#             with a build-provenance attestation (mode=max), and an SBOM
#             attestation with --sbom; the digest goes to --metadata-file
#             (buildx's metadata, containerimage.digest). Only the release
#             workflow pushes (.github/workflows/release.yml, go-image),
#             from the release's own assets; it signs what it pushed.
set -euo pipefail

stop() { printf 'image build: %s\n' "$*" >&2; exit 1; }
version='' assets='' tag='' platforms='' mode='' metadata='' sbom=false
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=${2:-}; shift 2 ;;
    --assets) assets=${2:-}; shift 2 ;;
    --tag) tag=${2:-}; shift 2 ;;
    --platforms) platforms=${2:-}; shift 2 ;;
    --metadata-file) metadata=${2:-}; shift 2 ;;
    --sbom) sbom=true; shift ;;
    --load | --check | --push) mode=$1; shift ;;
    *) stop "unknown option $1" ;;
  esac
done
[ -n "$version" ] && [ -n "$assets" ] && [ -n "$tag" ] && [ -n "$platforms" ] && [ -n "$mode" ] || stop "usage: build.sh --version <v> --assets <dir> --tag <image> --platforms <list> (--load | --check | --push --metadata-file <file> [--sbom])"
if [ "$mode" = --push ]; then
  [ -n "$metadata" ] || stop "--push needs --metadata-file"
else
  if [ -n "$metadata" ] || [ "$sbom" = true ]; then stop "--metadata-file and --sbom go with --push"; fi
fi
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
case "$mode" in
  --load) out=(--load) ;;
  --push) out=(--push --provenance=mode=max "--sbom=$sbom" --metadata-file "$metadata") ;;
esac
docker buildx build --file "$repo/go/image/Dockerfile" --build-context "assets=$assets" \
  --build-arg "VERSION=$version" --platform "$platforms" --tag "$tag" "${out[@]}" "$repo"
