// SPDX-License-Identifier: Apache-2.0
/**
 * Target `go-container:<image>`: the Go `varlatchd` in the single-container
 * image (go/image/Dockerfile; ADR-0059 Decision 8, internal
 * docs/design/go-step6.md slice 6.10a), <image> in the local Docker, built
 * with the conformance binaries (go build -tags conformance).
 *
 * It is go-binary (go-binary.mjs) with varlatchd in the container: every
 * operation, capability and expectation is go-binary's
 * (expect/go-binary.json; targets/index.mjs runs it as go-binary), and
 * `binary` is a wrapper script, written for the run, that runs the image's
 * varlatchd in place of the file:
 *
 *   <wrapper> serve --config <conf>
 *             `docker run` in the foreground, the container named
 *             vl-conformance-<installation directory's name>: host network,
 *             read-only root filesystem (no tmpfs), the installation
 *             directory mounted at its own path (its data directory, Root
 *             KEK file and configuration), as this user, with only
 *             SSL_CERT_FILE, VARLATCH_CONFORMANCE_OUTBOUND_HOSTS and
 *             VARLATCH_CONFORMANCE_CLI_RELEASE from the environment. The
 *             supervisor's SIGTERM reaches varlatchd
 *             through docker's signal proxy
 *   <wrapper> admin ... --config <conf>
 *             `docker exec` in that container while it runs; otherwise a
 *             read-only container of its own, removed when it ends
 *   <wrapper> admin conformance-probe ...   (up's check, no installation)
 *             a read-only container of its own, removed when it ends
 *   <wrapper> admin conformance-sign-release <dir> <version>
 *             (serve-cli's release, go-binary's prepareCliRelease) a
 *             read-only container of its own with <dir> alone mounted at its own path
 *             (not the installation's Root KEK, data or configuration): it
 *             reads and signs the files in <dir> and writes the signature
 *             and the trusted root into it
 *
 * `serve` and every admin container also take VARLATCH_CONFORMANCE_CLI_RELEASE
 * from the environment: go-binary hands serve-cli's release to varlatchd
 * through it, a directory inside the installation's, so mounted with it.
 *
 * `down` is go-binary's, then the installation's container removed by its
 * name, and the wrapper. The fingerprint is the image's ID.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import * as goBinary from "./go-binary.mjs";

export * from "./go-binary.mjs";

export const name = "go-container";

const VARLATCHD = "/opt/varlatch/varlatchd";
/** The container of an installation, by its directory. */
export const containerName = (dir) => `vl-conformance-${basename(dir).toLowerCase().replace(/[^a-z0-9_.-]/g, "")}`;

const quote = (s) => `'${String(s).replaceAll("'", "'\\''")}'`;

/** The wrapper script that runs the image's varlatchd as go-binary runs the file. */
export function wrapper(image) {
  return `#!/bin/sh
# Written by scripts/conformance/targets/go-container.mjs for one run:
# varlatchd in the image ${image.replace(/[^\w.:/@-]/g, "")}.
set -eu
image=${quote(image)}
conf=''
prev=''
for a in "$@"; do
  [ "$prev" != --config ] || conf=$a
  prev=$a
done
user="$(id -u):$(id -g)"
if [ -n "$conf" ]; then
  dir=$(dirname "$conf")
  name="vl-conformance-$(basename "$dir" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_.-')"
  mount="-v $dir:$dir"
elif [ "\${1:-}" = admin ] && [ "\${2:-}" = conformance-sign-release ] && [ -n "\${3:-}" ]; then
  # The release's directory alone, mounted at its own path so the path
  # the harness passes means the same inside: signing reads and writes
  # only there, so nothing else of the installation is exposed. Named by
  # the installation (its parent) for a name unique to the run.
  dir=$(dirname "$3")
  name="vl-conformance-$(basename "$dir" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_.-')-sign"
  mount="-v $3:$3"
else
  name="vl-conformance-probe-$$"
  mount=''
fi
env="-e SSL_CERT_FILE -e VARLATCH_CONFORMANCE_OUTBOUND_HOSTS -e VARLATCH_CONFORMANCE_CLI_RELEASE"
if [ "\${1:-}" = serve ]; then
  # This installation's container, by its exact name: one that ended and
  # is not yet removed would hold the name.
  docker rm -fv "$name" >/dev/null 2>&1 || true
  exec docker run --rm --read-only --name "$name" --network host --user "$user" $mount \\
    $env --entrypoint ${VARLATCHD} "$image" "$@"
fi
if [ -n "$conf" ] && [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ]; then
  exec docker exec "$name" ${VARLATCHD} "$@"
fi
exec docker run --rm --read-only --name "$name-admin-$$" --network host --user "$user" $mount \\
  $env --entrypoint ${VARLATCHD} "$image" "$@"
`;
}

function imageId(image) {
  const r = spawnSync("docker", ["image", "inspect", "--format", "{{.Id}}", image], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

/** Starts a fresh installation in the image; hands its state to onState before creating anything. */
export async function up({ argument, onState = () => {} }) {
  const id = imageId(argument);
  if (!id) throw new Error(`go-container: ${argument} is not an image in the local Docker (go/image/build.sh --load)`);
  const wrapperDir = mkdtempSync(join(tmpdir(), "conformance-go-container-"));
  const file = join(wrapperDir, "varlatchd");
  writeFileSync(file, wrapper(argument), { mode: 0o755 });
  let state;
  try {
    state = await goBinary.up({
      argument: file,
      onState: (s) => {
        Object.assign(s, { target: `go-container:${argument}`, image: argument, imageId: id, wrapperDir });
        onState(s);
      },
    });
  } catch (err) {
    if (err.state) Object.assign(err.state, { wrapperDir });
    else rmSync(wrapperDir, { recursive: true, force: true });
    throw err;
  }
  return state;
}

/** Stops the server and removes the installation, its container and the wrapper. */
export async function down(state) {
  await goBinary.down(state);
  if (state?.dir) spawnSync("docker", ["rm", "-fv", containerName(state.dir)], { stdio: "ignore" });
  if (state?.wrapperDir && state.wrapperDir.startsWith(join(tmpdir(), "conformance-go-container-"))) rmSync(state.wrapperDir, { recursive: true, force: true });
}

export function describe(state) {
  return { image: state.image, imageId: state.imageId, origin: state.origin, directory: state.dir };
}

/** The implementation fingerprint: the image's ID, whatever it is tagged. */
export const fingerprint = (state) => (state?.imageId ? { target: name, imageId: state.imageId } : null);

/** Expectations are go-binary's: the same server. */
export const expectKey = () => "go-binary";
