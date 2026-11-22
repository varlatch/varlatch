#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The Go release assets (ADR-0059 Decision 8; internal docs/design/
# go-step6.md, slice 6.1a), built into one directory with their SHA256SUMS:
#
#   varlatch-<version>-<os>-<arch>[.exe]   the CLI: linux, darwin, windows;
#                                          amd64, arm64
#   varlatchd-<version>-linux-<arch>       the server: amd64, arm64, with
#                                          the dashboard embedded
#   install.sh, install.ps1                the installers, stamped with
#                                          <version>
#   varlatchd.service                      the systemd unit
#   varlatchd.conf.example                 the documented configuration
#   release.json                           the manifest: the version and
#                                          go/release/release.json's
#                                          rollback-safety declaration
#                                          (slice 6.6a)
#   SHA256SUMS                             every file above, one line each
#
# These are the names install.sh and install.ps1 fetch; check-assets.sh
# checks them. Nothing here publishes, signs or uploads anything: the
# release workflow signs SHA256SUMS and publishes; go.yml runs this as a
# dry run.
#
# Usage: build-assets.sh --version <version> --out <directory> [--dry-run]
#
#   --dry-run   allow varlatchd to embed the placeholder dashboard (a
#               release refuses: it needs `go generate ./server/web` run on
#               this commit first, with a clean checkout)
#
# Builds are static (CGO off) and reproducible from the commit: -trimpath,
# no VCS stamp, no build ID, and the version set through
# go/lib/buildinfo.Version.
set -euo pipefail

stop() { printf 'build-assets: %s\n' "$*" >&2; exit 1; }

version='' out='' dry_run=no
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || stop "--version needs a value"; version=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || stop "--out needs a value"; out=$2; shift 2 ;;
    --dry-run) dry_run=yes; shift ;;
    *) stop "unknown option $1" ;;
  esac
done
[ -n "$version" ] || stop "--version is required"
[ -n "$out" ] || stop "--out is required"
# A release version, as the tag names it without its v (1.2.3, 1.2.3-rc.1):
# go/lib/release's versionPattern exactly, so no number has a leading zero.
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$ ]] \
  || stop "not a release version: $version"

# The toolchain on PATH builds the release, never one go.mod would download.
export GOTOOLCHAIN=local
printf 'toolchain: %s\n' "$(go version)"

here=$(cd "$(dirname "$0")" && pwd)
gomod=$(cd "$here/.." && pwd)
install_dir=$gomod/install

# varlatchd embeds the dashboard go generate staged; a release needs it
# built from exactly this commit, from sources with no change.
record=$gomod/server/web/dist/.build.json
if [ "$dry_run" = no ]; then
  [ -f "$record" ] || stop "no dashboard build in go/server/web/dist (run go generate ./server/web first)"
  head=$(git -C "$gomod" rev-parse HEAD)
  grep -q "\"commit\": *\"$head\"" "$record" || stop "the dashboard in go/server/web/dist was not built from $head"
  grep -q '"clean": *true' "$record" || stop "the dashboard in go/server/web/dist was built from changed sources"
fi

mkdir -p "$out"
[ -z "$(ls -A "$out")" ] || stop "$out is not empty"
out=$(cd "$out" && pwd)

ldflags="-s -w -buildid= -X github.com/varlatch/varlatch/go/lib/buildinfo.Version=$version"
build() { # build <command> <os> <arch> <file>
  # GOFLAGS cleared, so the environment adds no build tag to a release.
  (cd "$gomod" && GOFLAGS='' CGO_ENABLED=0 GOOS=$2 GOARCH=$3 go build -trimpath -buildvcs=false \
    -ldflags "$ldflags" -o "$out/$4" "./cmd/$1")
  printf 'built %s\n' "$4"
}

for os in linux darwin windows; do
  for arch in amd64 arm64; do
    ext=''
    [ "$os" != windows ] || ext=.exe
    build varlatch "$os" "$arch" "varlatch-$version-$os-$arch$ext"
  done
done
for arch in amd64 arm64; do
  build varlatchd linux "$arch" "varlatchd-$version-linux-$arch"
done

# The installers carry the version they install (@VARLATCH_VERSION@,
# exactly once in each).
stamp() { # stamp <file>
  [ "$(grep -o '@VARLATCH_VERSION@' "$install_dir/$1" | wc -l)" -eq 1 ] \
    || stop "$1 does not hold @VARLATCH_VERSION@ exactly once"
  sed "s/@VARLATCH_VERSION@/$version/" "$install_dir/$1" > "$out/$1"
  printf 'stamped %s\n' "$1"
}
stamp install.sh
stamp install.ps1
cp "$install_dir/varlatchd.service" "$install_dir/varlatchd.conf.example" "$out/"

# The manifest (ADR-0059 Decision 8): go/release/release.json, checked
# against this build's schema version, with the release's version. A
# declaration that does not hold stops the build.
(cd "$gomod" && CGO_ENABLED=0 go run ./server/db/releasecheck manifest --version "$version") > "$out/release.json"
printf 'wrote release.json\n'

# One line per file, in byte order of the names, as sha256sum writes them.
(
  cd "$out"
  export LC_ALL=C
  files=()
  # The glob is expanded before SHA256SUMS exists, so it never lists itself.
  for f in *; do files+=("$f"); done
  sha256sum "${files[@]}" > SHA256SUMS
)
printf 'wrote SHA256SUMS (%s files)\n' "$(wc -l < "$out/SHA256SUMS")"
