#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks a directory build-assets.sh wrote, before anything is signed or
# published (internal docs/design/go-step6.md, slice 6.1a):
#
# - exactly the files a release attaches, no more and no fewer: every name
#   install.sh and install.ps1 fetch for every platform they accept, the
#   unit and the example configuration, and SHA256SUMS;
# - SHA256SUMS lists each of them exactly once (as the installers read it)
#   with its true hash;
# - each binary is an executable for its platform (ELF, Mach-O or PE), and
#   the ones this machine can run report the version;
# - the installers are stamped with the version;
# - release.json is a manifest of format 2 for the version, declaring what
#   the release does to a migration's rollback window: reversibleTo the
#   last TypeScript release (0.23.1), or endsRollbackWindow, exactly one
#   (internal docs/design/go-step7.md decision 17).
#
# With --image <reference> (the release workflow's go-release, once the
# container image is pushed and signed): varlatchd-image.txt too, holding
# exactly that reference, which names this version's tag of a varlatchd
# image and its index digest. With --sboms as well: the image's SBOMs as
# release files, one per architecture (an image built on a self-hosted
# runner has no SBOM attestation).
#
# Usage: check-assets.sh <directory> <version> [--image <reference> [--sboms]]
set -euo pipefail

fail=0
bad() { printf 'check-assets: %s\n' "$*" >&2; fail=1; }

usage() { echo "usage: check-assets.sh <directory> <version> [--image <reference> [--sboms]]" >&2; exit 64; }
[ $# -ge 2 ] || usage
dir=$1 version=$2
shift 2
image='' sboms=false
while [ $# -gt 0 ]; do
  case "$1" in
    --image) [ $# -ge 2 ] || usage; image=$2; shift 2 ;;
    --sboms) sboms=true; shift ;;
    *) usage ;;
  esac
done
[ "$sboms" = false ] || [ -n "$image" ] || usage
cd "$dir"

expected=()
for os in linux darwin windows; do
  for arch in amd64 arm64; do
    ext=''
    [ "$os" != windows ] || ext=.exe
    expected+=("varlatch-$version-$os-$arch$ext")
  done
done
expected+=("varlatchd-$version-linux-amd64" "varlatchd-$version-linux-arm64"
  install.sh install.ps1 varlatchd.service varlatchd.conf.example release.json)
if [ -n "$image" ]; then
  expected+=(varlatchd-image.txt)
  [ "$sboms" = false ] || expected+=("sbom-varlatchd-$version-linux-amd64.spdx.json" "sbom-varlatchd-$version-linux-arm64.spdx.json")
fi

# Exactly these files and SHA256SUMS.
want=$(printf '%s\n' "${expected[@]}" SHA256SUMS | LC_ALL=C sort)
shopt -s dotglob nullglob
present=(*)
have=$(printf '%s\n' "${present[@]}" | LC_ALL=C sort)
[ "$want" = "$have" ] || bad "the files are not the release's:"$'\n'"$(diff <(echo "$want") <(echo "$have") || true)"

# Each listed exactly once with its hash, read as the installers read it.
for f in "${expected[@]}"; do
  [ -f "$f" ] || continue
  hash=$(awk -v name="$f" '
    length($1) == 64 && $1 ~ /^[0-9a-f]+$/ && ($2 == name || $2 == "*" name) { hash = $1; n++ }
    END { if (n == 1) print hash; else exit 1 }
  ' SHA256SUMS) || { bad "SHA256SUMS does not list $f exactly once"; continue; }
  [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$hash" ] || bad "$f does not match SHA256SUMS"
done
[ "$(wc -l < SHA256SUMS)" = "${#expected[@]}" ] || bad "SHA256SUMS lists other files too"

# The executable format of each binary, by its first bytes.
magic() { od -An -tx1 -N4 "$1" | tr -d ' \n'; }
for f in varlatch-*-linux-* varlatchd-*-linux-*; do
  [ "$(magic "$f")" = 7f454c46 ] || bad "$f is not an ELF executable"
done
for f in varlatch-*-darwin-*; do
  [ "$(magic "$f")" = cffaedfe ] || bad "$f is not a 64-bit Mach-O executable"
done
for f in varlatch-*-windows-*.exe; do
  [ "$(magic "$f" | cut -c1-4)" = 4d5a ] || bad "$f is not a PE executable"
done

# The binaries this machine runs report the version.
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) host=linux-amd64 ;;
  Linux-aarch64) host=linux-arm64 ;;
  *) host='' ;;
esac
if [ -n "$host" ]; then
  [ "$(./"varlatch-$version-$host" --version)" = "varlatch $version" ] || bad "varlatch-$version-$host does not report $version"
  [ "$(./"varlatchd-$version-$host" --version)" = "varlatchd $version" ] || bad "varlatchd-$version-$host does not report $version"
fi

# The installers install this version.
grep -q '@VARLATCH_VERSION@' install.sh install.ps1 && bad "an installer is not stamped"
grep -qx "VARLATCH_RELEASE='$version'" install.sh || bad "install.sh is not stamped with $version"
grep -q "^ *\$VarlatchRelease = '$version'\$" install.ps1 || bad "install.ps1 is not stamped with $version"

# The image: its record is the reference given, a varlatchd image's tag of
# this version with its index digest, on one line; its SBOM files are the
# SPDX 2.3 documents the release workflow writes.
if [ -n "$image" ]; then
  case "$image" in
    ghcr.io/*/varlatchd:"$version"@sha256:*) ;;
    *) bad "$image is not a varlatchd image of $version on ghcr.io" ;;
  esac
  [[ "${image##*@sha256:}" =~ ^[0-9a-f]{64}$ ]] || bad "$image does not end in an index digest"
  if ! [ "$(cat varlatchd-image.txt 2> /dev/null)" = "$image" ] || ! [ "$(wc -l < varlatchd-image.txt)" = 1 ]; then
    bad "varlatchd-image.txt does not hold exactly $image"
  fi
  if [ "$sboms" = true ]; then
    for arch in amd64 arm64; do
      jq -e '.spdxVersion == "SPDX-2.3" and (.packages | type) == "array" and (.packages | length) > 0' "sbom-varlatchd-$version-linux-$arch.spdx.json" > /dev/null \
        || bad "sbom-varlatchd-$version-linux-$arch.spdx.json is not an SPDX 2.3 document listing packages"
    done
  fi
fi

# The manifest names this version (go/lib/release's format 2; its rules are
# releasecheck's, which wrote it), and says what the release does to a
# migration's rollback window (internal docs/design/go-step7.md decision
# 17): reversible to the last TypeScript release, or ending the window.
# A release that says neither fails here, so none ends the window unsaid.
if [ -f release.json ]; then
  jq -e --arg v "$version" '.manifestVersion == 2 and .version == $v and (.schemaVersion | type) == "number" and (.rollbackSafe | type) == "boolean"' release.json > /dev/null \
    || bad "release.json is not a manifest of format 2 for $version"
  # Both keys present (jq reads a missing key as null, which Go refuses),
  # then exactly one of the two declarations.
  jq -e 'has("reversibleTo") and has("endsRollbackWindow") and ((.reversibleTo == "0.23.1" and .endsRollbackWindow == false) or (.reversibleTo == null and .endsRollbackWindow == true))' release.json > /dev/null \
    || bad "release.json declares neither reversibleTo 0.23.1 nor endsRollbackWindow: a release keeps the migration's rollback window or says it ends it"
fi

[ "$fail" = 0 ] && printf 'check-assets: %s files of %s checked\n' "${#expected[@]}" "$version"
exit "$fail"
