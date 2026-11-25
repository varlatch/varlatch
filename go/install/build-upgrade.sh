#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# What go/install/test-upgrade.sh runs, built from this checkout:
#
#   go/install/build-upgrade.sh <new directory> [<published prerelease>]
#
#   bin/       fakegithub, enrollpasskey, setupterminal
#   from/      the published prerelease's own varlatch, from its tag (release.json's
#              previous, by default): its engine is the one that upgrades from it
#   releases/  four releases, each a directory of its published files: the
#              candidate, then the next one (declared rollback-safe for the
#              candidate), one that is not declared so, and one whose
#              varlatchd never serves
#   versions   their versions, as shell variables
#
# Each varlatch is built with -tags selfupdatetest, so it can be pointed at
# fakegithub: none of it is a release. It needs Go, jq, the prerelease's tag in
# this clone, and no root.
set -eu
out=${1:-}
[ -n "$out" ] && [ ! -e "$out" ] || { echo "usage: build-upgrade.sh <new directory> [<published prerelease>]" >&2; exit 64; }
go=$(cd "$(dirname "$0")/.." && pwd)
from=${2:-$(jq -r .previous.version "$go/release/release.json")}
git -C "$go" rev-parse -q --verify "refs/tags/v$from^{commit}" >/dev/null || { echo "build-upgrade.sh: no tag v$from here: git fetch origin tag v$from" >&2; exit 1; }
mkdir -p "$out/bin" "$out/releases" "$out/from"
out=$(cd "$out" && pwd)
arch=$(cd "$go" && go env GOARCH)

# Synthetic stable releases newer than the published 0.50.0 upgrade source.
CANDIDATE=0.50.9000 NEXT=0.50.9001 UNSAFE=0.50.9002 BROKEN=0.50.9003
schema=$(jq -r .schemaVersion "$go/release/release.json")

# manifest <version> <previous>: its release.json, as the release makes it.
manifest() {
  jq -S --arg v "$1" --arg p "$2" --argjson s "$schema" \
    '{manifestVersion: 2, version: $v} + . + {previous: {version: $p, schemaVersion: $s}}' "$go/release/release.json" >"$out/releases/$1/release.json"
}
build() { # <version> <package> <file> [<tags>]
  (cd "$go" && CGO_ENABLED=0 go build -trimpath -tags "${4:-}" -ldflags "-X github.com/varlatch/varlatch/go/lib/buildinfo.Version=$1" -o "$out/releases/$1/$3" "$2")
}
for v in "$CANDIDATE" "$NEXT" "$UNSAFE" "$BROKEN"; do
  mkdir "$out/releases/$v"
  build "$v" ./cmd/varlatch "varlatch-$v-linux-$arch" selfupdatetest
done
for v in "$CANDIDATE" "$NEXT" "$UNSAFE"; do
  build "$v" ./cmd/varlatchd "varlatchd-$v-linux-$arch"
done
mkdir "$out/from/source"
git -C "$go/.." archive "v$from" go | tar -x -C "$out/from/source"
(cd "$out/from/source/go" && CGO_ENABLED=0 go build -trimpath -tags selfupdatetest -ldflags "-X github.com/varlatch/varlatch/go/lib/buildinfo.Version=$from" -o "$out/from/varlatch" ./cmd/varlatch)
rm -r "$out/from/source"
manifest "$CANDIDATE" "$from"
manifest "$NEXT" "$CANDIDATE"
manifest "$UNSAFE" "$from" # declares nothing about the candidate
manifest "$BROKEN" "$CANDIDATE"
# It does all but serve: what it is asked beside the running server is the
# candidate's, kept by the upgrade, under its own version.
cat >"$out/releases/$BROKEN/varlatchd-$BROKEN-linux-$arch" <<END
#!/bin/sh
case "\${1:-}" in
  --version) echo "varlatchd $BROKEN" ;;
  serve) echo "broken on purpose" >&2; exit 1 ;;
  *) exec /usr/local/lib/varlatch/releases/$CANDIDATE/varlatchd "\$@" ;;
esac
END
for tool in cmd/varlatch/internal/selfupdate/fakerelease/fakegithub server/auth/authtest/enrollpasskey install/setupterminal; do
  (cd "$go" && CGO_ENABLED=0 go build -trimpath -o "$out/bin/${tool##*/}" "./$tool")
done
printf 'FROM=%s\nCANDIDATE=%s\nNEXT=%s\nUNSAFE=%s\nBROKEN=%s\n' "$from" "$CANDIDATE" "$NEXT" "$UNSAFE" "$BROKEN" >"$out/versions"
echo "built in $out"
