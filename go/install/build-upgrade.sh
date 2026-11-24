#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# What go/install/test-upgrade.sh runs, built from this checkout:
#
#   go/install/build-upgrade.sh <new directory>
#
#   bin/       fakegithub, enrollpasskey, setupterminal
#   releases/  four releases, each a directory of its published files: the
#              candidate, then the next one (declared rollback-safe for the
#              candidate), one that is not declared so, and one whose
#              varlatchd never serves
#   versions   their versions, as shell variables
#
# Their varlatch is built with -tags selfupdatetest, so it can be pointed at
# fakegithub: none of it is a release. It needs Go and jq, and no root.
set -eu
out=${1:-}
[ -n "$out" ] && [ ! -e "$out" ] || { echo "usage: build-upgrade.sh <new directory>" >&2; exit 64; }
go=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out/bin" "$out/releases"
out=$(cd "$out" && pwd)
arch=$(cd "$go" && go env GOARCH)

# Above every prerelease there will be of 0.50.0, and before 0.50.0.
CANDIDATE=0.50.0-rc.9000 NEXT=0.50.0-rc.9001 UNSAFE=0.50.0-rc.9002 BROKEN=0.50.0-rc.9003
schema=$(jq -r .schemaVersion "$go/release/release.json")
from=$(jq -r .previous.version "$go/release/release.json")

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
printf 'CANDIDATE=%s\nNEXT=%s\nUNSAFE=%s\nBROKEN=%s\n' "$CANDIDATE" "$NEXT" "$UNSAFE" "$BROKEN" >"$out/versions"
echo "built in $out"
