#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The rehearsal's TypeScript images (step 7.8b): the last TypeScript
# release's three images built from a checkout (a branch, while 0.23.0 is
# not published), labelled with the release, pushed to a registry of this
# run's own (loopback only) so each has a registry digest, as a published
# image has. Then the release's own files, from those references.
#
#   images.sh <typescript-checkout> <run> <out-dir>
#
# Writes <out-dir>/images.json ({"registry": <port>, "images": {name: ref}})
# and the release's files (build-release-artifacts.mjs). The registry runs
# as the container vl-rh-<run>-registry; remove it with
# `docker rm -fv vl-rh-<run>-registry`.
set -euo pipefail
ts=$(cd "$1" && pwd) run=$2 out=$3
[[ $run =~ ^[a-z0-9-]+$ ]] || { echo "run is lowercase letters, digits and dashes" >&2; exit 64; }
mkdir -p "$out" && out=$(cd "$out" && pwd)
registry=vl-rh-$run-registry
version=$(node -p "require('$ts/packages/backup/src/release.json').version")
# registry:2, by digest.
docker run -d --name "$registry" -p 127.0.0.1::5000 \
  registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373 >/dev/null
port=$(docker port "$registry" 5000/tcp | head -1 | sed 's/.*://')
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break; sleep 0.2; done
refs=()
for pair in varlatchd=services/varlatchd/Dockerfile varlatch-web=apps/web/Dockerfile convex-deploy=infra/compose/convex-deploy.Dockerfile; do
  name=${pair%%=*} file=${pair#*=}
  repo=127.0.0.1:$port/vl-rh/$name
  [ "$name" != convex-deploy ] || repo=127.0.0.1:$port/vl-rh/varlatch-convex-deploy
  docker build -q --label "org.opencontainers.image.version=$version" -f "$ts/$file" -t "$repo:$version" "$ts" >/dev/null
  docker push -q "$repo:$version" >/dev/null
  digest=$(docker image inspect "$repo:$version" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep -m1 "^$repo@" | cut -d@ -f2)
  [ -n "$digest" ] || { echo "no registry digest for $repo" >&2; exit 1; }
  refs+=("$name=$repo:$version@$digest")
  echo "built $name $digest" >&2
done
(cd "$out" && node "$ts/infra/release/build-release-artifacts.mjs" "$version" --out "$out" \
  --image "${refs[0]}" --image "${refs[1]}" --image "${refs[2]}" >&2)
node -e '
  const [port, out, ...refs] = process.argv.slice(1);
  const images = Object.fromEntries(refs.map(r => [r.slice(0, r.indexOf("=")), r.slice(r.indexOf("=") + 1)]));
  require("fs").writeFileSync(out + "/images.json", JSON.stringify({ registry: Number(port), images }, null, 2) + "\n");
' "$port" "$out" "${refs[@]}"
