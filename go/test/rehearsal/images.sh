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
# Writes <out-dir>/images.json ({"registry": <port>, "images": {name: ref}}),
# the release's files (build-release-artifacts.mjs) and
# coolify-image-digests.env (the Coolify variables, as the release job
# publishes them; written here when the checkout's builder predates it). The registry runs
# as the container vl-rh-<run>-registry; run.sh removes that container and
# its three images by exact name/tag on teardown (and this script cleans
# them up on error). If run standalone, remove vl-rh-<run>-registry and
# the three image refs listed in <out-dir>/images.json by exact name.
set -euo pipefail
[ $# -ge 3 ] || { echo "usage: images.sh <typescript-checkout> <run> <out-dir>" >&2; exit 64; }
ts=$(cd "$1" && pwd) run=$2 out=$3
[[ $run =~ ^[a-z0-9-]+$ ]] || { echo "run is lowercase letters, digits and dashes" >&2; exit 64; }
mkdir -p "$out" && out=$(cd "$out" && pwd)
registry=vl-rh-$run-registry
built_tags=()
built_digests=()
cleanup_on_err() {
  docker rm -fv "$registry" >/dev/null 2>&1 || true
  local ref
  for ref in "${built_tags[@]}" "${built_digests[@]}"; do
    docker image rm "$ref" >/dev/null 2>&1 || true
  done
}
trap cleanup_on_err ERR
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
  built_tags+=("$repo:$version")
  docker push -q "$repo:$version" >/dev/null
  digest=$(docker image inspect "$repo:$version" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep -m1 "^$repo@" | cut -d@ -f2)
  [ -n "$digest" ] || { echo "no registry digest for $repo" >&2; exit 1; }
  built_digests+=("$repo@$digest")
  refs+=("$name=$repo:$version@$digest")
  echo "built $name $digest" >&2
done
(cd "$out" && node "$ts/infra/release/build-release-artifacts.mjs" "$version" --out "$out" \
  --image "${refs[0]}" --image "${refs[1]}" --image "${refs[2]}" >&2)
node -e '
  const fs = require("fs");
  const [port, out, ...refs] = process.argv.slice(1);
  const images = Object.fromEntries(refs.map(r => [r.slice(0, r.indexOf("=")), r.slice(r.indexOf("=") + 1)]));
  fs.writeFileSync(out + "/images.json", JSON.stringify({ registry: Number(port), images }, null, 2) + "\n");
  // coolify-image-digests.env, in the release job'"'"'s format (#373,
  // infra/release/coolify-digests.mjs): the registry, then each image'"'"'s
  // digest. A 0.23.0 candidate'"'"'s builder writes it; an older checkout'"'"'s
  // does not, so it is written here; one the builder wrote must agree.
  const vars = { varlatchd: "VARLATCH_VARLATCHD_DIGEST", "varlatch-web": "VARLATCH_WEB_DIGEST", "convex-deploy": "VARLATCH_CONVEX_DEPLOY_DIGEST" };
  const lines = [];
  let registry;
  for (const [name, variable] of Object.entries(vars)) {
    const m = /^(.+)\/[^/:@]+(?::[^@]+)?@(sha256:[0-9a-f]{64})$/.exec(images[name] || "");
    if (!m) throw new Error("no digest-pinned reference for " + name);
    registry = m[1];
    lines.push(variable + "=" + m[2]);
  }
  const text = "VARLATCH_IMAGE_REGISTRY=" + registry + "\n" + lines.join("\n") + "\n";
  const file = out + "/coolify-image-digests.env";
  if (fs.existsSync(file) && fs.readFileSync(file, "utf8") !== text) throw new Error(file + " (the release builder'"'"'s) names other images than images.json");
  fs.writeFileSync(file, text);
' "$port" "$out" "${refs[@]}"
