#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * The part of the CLI's compatibility core that no other suite checks as
 * its own result: signing in with a token, `varlatch whoami`, and
 * `varlatch env list`, with the CLI under test against the target. The core
 * is never version-gated: every pinned CLI must pass it.
 *
 *   cli-core.mjs <origin> <api token> <seeded secret>   (run by scripts/conformance/run.mjs)
 *
 * The runner seeded organization acme, project api with the environments
 * development and production, and a Secret in development.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cliPath, reporter } from "../suite-kit.mjs";

const [origin, token, seeded] = process.argv.slice(2);
if (!origin || !token || !seeded) {
  console.error("Usage: cli-core.mjs <origin> <api token> <seeded secret>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });
const repo = mkdtempSync(join(tmpdir(), "cli-core-repo-"));
const config = mkdtempSync(join(tmpdir(), "cli-core-cfg-"));

/** The CLI under test, in a checkout of acme/api, with no Varlatch setting from the host. */
function cli(args) {
  const env = { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0" };
  const r = spawnSync(process.execPath, [cliPath(), ...args], { cwd: repo, env, encoding: "utf8", timeout: 90_000 });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}
const holdsNoSecret = (text) => !text.includes(token) && !text.includes(seeded);

try {
  const init = cli(["init", "--org", "acme", "--project", "api", "--server", origin]);
  if (init.code !== 0) throw new Error(`init exited ${init.code}: ${init.out.trim().slice(-400)}`);

  const login = cli(["login", "--server", origin, "--token", token]);
  check(
    "cli-core.login-token-stores-credential",
    "login --token signs in and says so, without printing the credential",
    login.code === 0 && /Logged in/.test(login.stdout) && holdsNoSecret(login.out),
    `exit ${login.code}: ${login.out.trim().slice(-300)}`,
  );

  const me = await fetch(`${origin}/v1/me`, { headers: { Authorization: `Bearer ${token}` } }).then((r) => r.json());
  const who = cli(["whoami", "--json"]);
  let parsed = null;
  try {
    parsed = JSON.parse(who.stdout);
  } catch {
    // Judged below.
  }
  check(
    "cli-core.whoami-names-signed-in-identity",
    "whoami --json names the identity and credential the server sees for the stored credential",
    who.code === 0 &&
      parsed?.server === origin &&
      parsed?.identity?.id === me?.identity?.id &&
      parsed?.credential?.id === me?.credential?.id &&
      holdsNoSecret(who.out),
    `exit ${who.code}: ${who.out.trim().slice(-300)}`,
  );
  const human = cli(["whoami"]);
  check(
    "cli-core.whoami-human-format",
    "whoami prints the identity and the server, one labeled line each",
    human.code === 0 && human.stdout.includes(me?.identity?.id ?? "<none>") && new RegExp(`^Server +${origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} `, "m").test(human.stdout),
    `exit ${human.code}: ${human.out.trim().slice(-300)}`,
  );

  // The human format of env list is frozen: scripts parse it.
  const listed = cli(["env", "list", "-e", "development"]);
  const lines = listed.stdout.trim().split("\n");
  check(
    "cli-core.env-list-frozen-format",
    "env list prints each environment as `<name>  (<tier>, <kind>[, selected])`",
    listed.code === 0 &&
      lines.includes("development  (development, shared, selected)") &&
      lines.includes("production  (production, shared)") &&
      holdsNoSecret(listed.out),
    `exit ${listed.code}: ${listed.out.trim().slice(-300)}`,
  );
  const json = cli(["env", "list", "--json"]);
  let environments = null;
  try {
    environments = JSON.parse(json.stdout).environments;
  } catch {
    // Judged below.
  }
  check(
    "cli-core.env-list-json",
    "env list --json lists the same environments with tier and kind",
    json.code === 0 &&
      Array.isArray(environments) &&
      ["development", "production"].every((name) => environments.some((e) => e.name === name && e.tier === name && e.kind === "shared")),
    `exit ${json.code}: ${json.out.trim().slice(-300)}`,
  );
} catch (err) {
  error(`cli-core: ${err.message}`);
} finally {
  rmSync(repo, { recursive: true, force: true });
  rmSync(config, { recursive: true, force: true });
}
finish("CLI core check(s)");
