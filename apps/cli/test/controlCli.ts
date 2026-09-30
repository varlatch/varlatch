// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build, type Plugin } from "esbuild";

/**
 * The 0.13 CLI, the negative control for credential isolation (ADR-0043
 * Decision 11): the same probes against a CLI without Decision 5 must leak.
 *
 * It is the release commit of v0.13.0, pinned by hash so a moved tag cannot
 * change it, bundled from that commit's own source (`git archive`, fetched
 * from origin when a shallow checkout lacks it) with this checkout's
 * third-party dependencies. VARLATCH_CONTROL_CLI may name a prebuilt
 * `varlatch-cli-0.13.0.cjs` instead. A control that cannot be obtained
 * fails the test: it is never skipped.
 */
export const CONTROL_VERSION = "0.13.0";
export const CONTROL_COMMIT = "8d68ba4ab697a5d96d18a5f247c6dd02faf299f6";

const cliDir = fileURLToPath(new URL("..", import.meta.url));
const root = join(cliDir, "..", "..");

function git(args: string[]): Buffer {
  return execFileSync("git", args, { cwd: root, stdio: ["pipe", "pipe", "pipe"], maxBuffer: 256 * 1024 * 1024 });
}

function haveCommit(): boolean {
  try {
    git(["cat-file", "-e", `${CONTROL_COMMIT}^{commit}`]);
    return true;
  } catch {
    return false;
  }
}

export async function controlCli(workDir: string): Promise<string> {
  const prebuilt = process.env.VARLATCH_CONTROL_CLI;
  if (prebuilt) {
    if (!existsSync(prebuilt)) throw new Error(`VARLATCH_CONTROL_CLI names ${prebuilt}, which does not exist`);
    return prebuilt;
  }
  if (!haveCommit()) {
    try {
      git(["fetch", "--quiet", "--depth=1", "origin", CONTROL_COMMIT]);
    } catch {
      /* reported below */
    }
  }
  if (!haveCommit()) {
    throw new Error(
      `the ${CONTROL_VERSION} control CLI needs commit ${CONTROL_COMMIT} (git fetch origin ${CONTROL_COMMIT}), ` +
        `or VARLATCH_CONTROL_CLI=<path to varlatch-cli-${CONTROL_VERSION}.cjs>`,
    );
  }
  const source = join(workDir, `control-${CONTROL_VERSION}`);
  mkdirSync(source, { recursive: true });
  const archive = git(["archive", "--format=tar", CONTROL_COMMIT, "apps/cli/src", "packages"]);
  execFileSync("tar", ["-x", "-C", source], { input: archive });

  const require = createRequire(join(cliDir, "package.json"));
  // Workspace packages resolve to the control's own sources; anything the
  // control does not have as source (generated modules) and every
  // third-party package come from this checkout.
  const workspace: Plugin = {
    name: "control-workspace",
    setup(b) {
      b.onResolve({ filter: /^@varlatch\// }, (args) => {
        const [, pkg, sub] = /^@varlatch\/([^/]+)(?:\/(.+))?$/.exec(args.path) ?? [];
        const candidate = join(source, "packages", pkg ?? "", "src", `${sub ?? "index"}.ts`);
        return { path: existsSync(candidate) ? candidate : require.resolve(args.path) };
      });
    },
  };
  const nodePaths = [
    join(root, "node_modules"),
    join(cliDir, "node_modules"),
    ...readdirSync(join(root, "packages")).map((p) => join(root, "packages", p, "node_modules")),
  ].filter(existsSync);
  const outfile = join(workDir, `varlatch-cli-${CONTROL_VERSION}.cjs`);
  await build({
    entryPoints: [join(source, "apps", "cli", "src", "main.ts")],
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    outfile,
    nodePaths,
    plugins: [workspace],
    logLevel: "silent",
  });
  return outfile;
}
