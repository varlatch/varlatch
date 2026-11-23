#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks the attestations of a pushed varlatchd image, by its index digest,
# for linux/amd64 and linux/arm64:
#
# - a build-provenance attestation: an SLSA predicate (v1's buildDefinition
#   or v0.2's buildType), not merely an entry; buildx renders a platform
#   with none as {}, which is refused;
# - an SBOM: an SPDX predicate attested in the image, listing packages; or,
#   for an image built where BuildKit could not attest one (a self-hosted
#   runner), the release file sbom-varlatchd-<version>-linux-<arch>.spdx.json
#   from --sbom-dir, whose bytes must match its one line in --sums (a
#   SHA256SUMS whose signature the caller verified), an SPDX 2.3 document
#   listing packages.
#
# The release workflow runs it before publishing (go-release), the
# published-release workflow after, and verify-release.md shows it.
#
# Usage: check-attestations.sh <name>@sha256:<digest> <version> [--sbom-dir <dir> --sums <SHA256SUMS>]
set -euo pipefail

usage() { echo "usage: check-attestations.sh <name>@sha256:<digest> <version> [--sbom-dir <dir> --sums <SHA256SUMS>]" >&2; exit 64; }
[ $# -ge 2 ] || usage
image=$1 version=$2
shift 2
sbomdir='' sums=''
while [ $# -gt 0 ]; do
  case "$1" in
    --sbom-dir) [ $# -ge 2 ] || usage; sbomdir=$2; shift 2 ;;
    --sums) [ $# -ge 2 ] || usage; sums=$2; shift 2 ;;
    *) usage ;;
  esac
done
{ [ -n "$sbomdir" ] && [ -n "$sums" ]; } || { [ -z "$sbomdir" ] && [ -z "$sums" ]; } || usage
[[ "$image" =~ ^[a-z0-9./-]+@sha256:[0-9a-f]{64}$ ]] || { echo "check-attestations: $image is not an image by its digest" >&2; exit 64; }

fail=0
bad() { printf 'check-attestations: %s\n' "$*" >&2; fail=1; }

# One attestation's predicate for one platform, as buildx renders it ({}
# when there is none); a registry that does not answer fails the check.
predicate() {
  local out
  if ! out=$(docker buildx imagetools inspect "$image" --format "{{ json (index .$1 \"linux/$2\") }}" 2>&1); then
    printf 'check-attestations: reading the %s of linux/%s failed: %s\n' "$1" "$2" "${out##*$'\n'}" >&2
    return 1
  fi
  printf '%s' "$out"
}

for arch in amd64 arm64; do
  provenance=$(predicate Provenance "$arch") || { fail=1; continue; }
  if ! jq -e '(.SLSA | type) == "object" and ((.SLSA.buildDefinition.buildType // .SLSA.buildType // "") | type == "string" and startswith("https://"))' <<< "$provenance" > /dev/null; then
    bad "no build-provenance predicate for linux/$arch"
  fi
  sbom=$(predicate SBOM "$arch") || { fail=1; continue; }
  if jq -e '(.SPDX | type) == "object" and (.SPDX.spdxVersion | type == "string" and startswith("SPDX-")) and (.SPDX.packages | type == "array" and length > 0)' <<< "$sbom" > /dev/null; then
    continue
  fi
  file="sbom-varlatchd-$version-linux-$arch.spdx.json"
  if [ -z "$sbomdir" ] || [ ! -f "$sbomdir/$file" ]; then
    bad "no SBOM for linux/$arch: none attested, and no $file"
    continue
  fi
  # The file's bytes against its one line in SHA256SUMS.
  hash=$(awk -v name="$file" '
    length($1) == 64 && $1 ~ /^[0-9a-f]+$/ && ($2 == name || $2 == "*" name) { hash = $1; n++ }
    END { if (n == 1) print hash; else exit 1 }
  ' "$sums") || { bad "SHA256SUMS does not list $file exactly once"; continue; }
  [ "$(sha256sum "$sbomdir/$file" | cut -d' ' -f1)" = "$hash" ] || { bad "$file does not match SHA256SUMS"; continue; }
  jq -e '.spdxVersion == "SPDX-2.3" and (.packages | type == "array" and length > 0)' "$sbomdir/$file" > /dev/null \
    || bad "$file is not an SPDX 2.3 document listing packages"
done

[ "$fail" = 0 ] && echo "check-attestations: $image has provenance and an SBOM for linux/amd64 and linux/arm64"
exit "$fail"
