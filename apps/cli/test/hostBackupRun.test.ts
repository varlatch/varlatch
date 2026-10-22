// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * The reference host timer (infra/host-backup/run.sh) runs the release
 * check (ADR-0049) as its own advisory step after the backup: a failed check
 * never fails a successful backup, and a failed backup still fails the run.
 * Runs the real script against a stub CLI.
 */

const RUN_SH = resolve(__dirname, "../../../infra/host-backup/run.sh");

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "varlatch-host-backup-"));
  mkdirSync(join(root, "conf"));
  mkdirSync(join(root, "compose", "backups"), { recursive: true });
  // The stub CLI: logs each command, and fails where the test asks it to.
  writeFileSync(
    join(root, "cli.mjs"),
    `import { appendFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const command = args.slice(0, args[0] === "admin" ? 3 : 1).join(" ");
appendFileSync(process.env.CALLS, (command === "upgrade" ? args.join(" ") : command) + "\\n");
if (command === "--version") console.log("0.0.0-test");
if (command === "admin backup create") {
  writeFileSync(process.env.COMPOSE_DIR_FOR_STUB + "/backups/a.vltbak", "");
  console.log("Archive created: " + process.env.COMPOSE_DIR_FOR_STUB + "/backups/a.vltbak (00000000-0000-0000-0000-000000000000)");
}
if (command === "admin backup verify" && process.env.VERIFY_FAILS) process.exit(1);
if (command === "admin backup status") console.log("{}");
if (command === "upgrade") process.exit(Number(process.env.CHECK_EXIT ?? 0));
`,
  );
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function run(config: string, env: Record<string, string> = {}) {
  writeFileSync(
    join(root, "conf", "config.env"),
    `COMPOSE_DIR=${join(root, "compose")}\nCLI=${join(root, "cli.mjs")}\nSTATUS_FILE=${join(root, "state", "status.json")}\n${config}`,
  );
  const result = spawnSync("bash", [RUN_SH], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      VARLATCH_BACKUP_CONF: join(root, "conf"),
      VARLATCH_BACKUP_STATE: join(root, "state"),
      VARLATCH_BACKUP_FROM_IMAGE: "1",
      CALLS: join(root, "calls"),
      COMPOSE_DIR_FOR_STUB: join(root, "compose"),
      ...env,
    },
  });
  const calls = existsSync(join(root, "calls")) ? readFileSync(join(root, "calls"), "utf8").trim().split("\n") : [];
  return { status: result.status, out: result.stdout + result.stderr, calls };
}

describe("host backup timer: the release check", () => {
  it("runs last, after a successful backup", () => {
    const r = run("");
    expect(r.status).toBe(0);
    expect(r.calls).toEqual(["--version", "admin backup create", "admin backup verify", "admin backup status", `upgrade --check --dir ${join(root, "compose")}`]);
  });

  it("leaves a successful backup's exit status 0 when the check fails, and says so", () => {
    const r = run("", { CHECK_EXIT: "1" });
    expect(r.status).toBe(0);
    expect(r.out).toContain("backup run complete");
    expect(r.out).toContain("release check failed (advisory; the backup succeeded): exit 1");
  });

  it("still fails the run when the backup fails, and checks nothing", () => {
    const r = run("", { VERIFY_FAILS: "1" });
    expect(r.status).not.toBe(0);
    expect(r.calls.some((c) => c.startsWith("upgrade"))).toBe(false);
  });

  it("can be turned off", () => {
    const r = run("RELEASE_CHECK=off\n");
    expect(r.status).toBe(0);
    expect(r.calls.some((c) => c.startsWith("upgrade"))).toBe(false);
  });
});
