#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# G5 for a release, against the last TypeScript release as it was published
# (internal docs/design/go-step7.md, "G5 per release"): the rehearsal's
# restored case on its published images, by digest, with this checkout's
# varlatch and varlatchd.
#
#   published.sh whole|forward <work-dir>
#
#   whole    a migration, a day of changes on Go, --rollback, --finish, and the
#            migration again, each with its parity checks (a release that
#            keeps the rollback window)
#   forward  a migration killed in the address transfer, aborted on one copy
#            and resumed to open on another (a release that ends the window)
#
# The data is synthetic, made here (VL_RH_ONLY=bundle). The release's files are
# downloaded from its GitHub release and must have the hashes below, which are
# those of its signed SHA256SUMS; its images are named by digest, varlatchd's
# the one varlatch migrate itself is pinned to (sides.go). The reports, which
# hold no secret, are <work-dir>/runs/<run>/report. It needs Docker with
# Compose, curl, jq, Node.js and the checkout's packages/backup installed
# (pnpm install --filter @varlatch/backup): the harness's S3 client. One run at
# a time on a host.
set -euo pipefail
fail() { echo "published.sh: $*" >&2; exit 1; }
[ $# = 2 ] || { echo "usage: published.sh whole|forward <work-dir>" >&2; exit 64; }
case "$1" in whole | forward) what=$1 ;; *) echo "usage: published.sh whole|forward <work-dir>" >&2; exit 64 ;; esac
here=$(cd "$(dirname "$0")" && pwd) top=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$2" && work=$(cd "$2" && pwd)

# The release, and its files' hashes.
VERSION=0.23.1
HASHES='3063d7cdcb2370b435547af9f317b1bb1bccf294f9b7df6ffc4ccaeed8225225  varlatch-release.json
c6b99d7e0254ed40fdf53c9b2f1764c6e8e7b2bd482aedbeedde3f4d80a85250  varlatch-compose-0.23.1.tar.gz
fe3526d5fe1d92681ae04b63641bffc789c04a484e46043bf606939b5fb9b3c8  varlatch-cli-0.23.1.cjs
b524da83b50a4cbb042be7679ed64201b774b76821df2257ed9798699270777d  coolify-image-digests.env'
last=$(sed -n 's/^const LastTypeScriptRelease = "\(.*\)"$/\1/p' "$top/go/lib/release/manifest.go")
[ "$last" = "$VERSION" ] || fail "the last TypeScript release is ${last:-not named} and this script has $VERSION's hashes: bring it up to date"
pinned=$(sed -n 's/^\tLastTypeScriptDigest *= "\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$top/go/cmd/varlatch/internal/migrate/sides.go")
[ -n "$pinned" ] || fail "sides.go names no LastTypeScriptDigest"

release=$work/release
mkdir -p "$release"
while read -r _ file; do
  [ -f "$release/$file" ] || curl -fsSL --retry 5 --retry-all-errors --max-time 300 -o "$release/$file" "https://github.com/varlatch/varlatch/releases/download/v$VERSION/$file"
done <<< "$HASHES"
(cd "$release" && sha256sum --check --strict --quiet - <<< "$HASHES") || fail "a file of the release is not the published one"
# The harness's images.json: name -> repository:tag@digest.
jq -e --arg v "$VERSION" --arg d "$pinned" '
  select(.version == $v and (.images.varlatchd.digest | endswith("@" + $d))) |
  {registry: 0, images: ([("varlatchd", "varlatch-web", "convex-deploy") as $k | .images[$k] |
    {key: $k, value: (.tag + "@" + (.digest | split("@")[1]))}] | from_entries)}' \
  "$release/varlatch-release.json" > "$release/images.json" || fail "varlatch-release.json does not name the pinned varlatchd, $pinned"

# Every image the run starts, by digest, before it starts.
minio=$(sed -n 's/^const minioImage = "\(.*\)"$/\1/p' "$here/s3_test.go")
compose=$(tar -xzOf "$release/varlatch-compose-$VERSION.tar.gz" --wildcards '*/docker-compose.yml' | sed -n 's/^ *image: *//p')
mapfile -t images < <({ printf '%s\n%s\n' "$compose" "$minio"; jq -r '.images[]' "$release/images.json"; sed -n 's/^FROM \([^ ]*\).*/\1/p' "$here/runner.Dockerfile"; } | sort -u)
for image in "${images[@]}"; do
  [[ $image =~ @sha256:[0-9a-f]{64}$ ]] || fail "$image is not named by digest"
done
"$top/scripts/ci-pull-image.sh" "${images[@]}" > /dev/null

export VL_RH_ROOT=$work/runs
run=published-$$
operator=$work/operator-$$
mkdir "$operator"
VL_RH_ONLY=bundle VL_RH_BUNDLE_OUT=$operator "$here/run.sh" "$top" "$run-bundle" "$release"
# The runner wrote as root: handed back.
docker run --rm -v "$operator:/operator" "$(sed -n 's/^FROM \([^ ]*\) AS docker$/\1/p' "$here/runner.Dockerfile")" chown -R "$(id -u):$(id -g)" /operator
export VL_RH_SOURCE=restore:$operator/archive.vltbak VL_RH_RESTORE_BEK=$operator/backup-key VL_RH_RESTORE_KEK=$operator/root-kek
if [ "$what" = whole ]; then
  "$here/run.sh" "$top" "$run" "$release"
else
  VL_RH_ONLY=kill VL_RH_KILL=transfer "$here/run.sh" "$top" "$run" "$release"
fi
sed -n '/^## Checks/p' "$VL_RH_ROOT/$run/report/report.md"
