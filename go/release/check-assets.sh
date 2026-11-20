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
# - the installers are stamped with the version.
#
# Usage: check-assets.sh <directory> <version>
set -euo pipefail

fail=0
bad() { printf 'check-assets: %s\n' "$*" >&2; fail=1; }

[ $# -eq 2 ] || { echo "usage: check-assets.sh <directory> <version>" >&2; exit 64; }
dir=$1 version=$2
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
  install.sh install.ps1 varlatchd.service varlatchd.conf.example)

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

[ "$fail" = 0 ] && printf 'check-assets: %s files of %s checked\n' "${#expected[@]}" "$version"
exit "$fail"
