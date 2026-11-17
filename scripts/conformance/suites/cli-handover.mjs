#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * The hand-over between the Go CLI and the TypeScript CLI (internal
 * docs/design/go-cli.md, decision 11): until the TypeScript CLI is gone,
 * people have both, so each must use what the other stored. This suite
 * runs with the Go CLI under test (`--cli go:<path>`) and the TypeScript
 * CLI the runner pairs it with (`--handover-cli`, 0.22.0 by default); with
 * a TypeScript CLI under test its checks are not applicable (kind
 * go-client).
 *
 *   cli-handover.mjs <origin> <credential A> <credential B>   (run by scripts/conformance/run.mjs)
 *
 * The credentials are two fresh CLI credentials of the admin identity, one
 * per direction. The runner seeded organization acme, project api with the
 * environments development and production.
 *
 * Token sign-in both ways (slice 5.1e): signed in by one CLI, the other
 * finds the credential and the default server; both write the store alike;
 * a logout by one is seen by the other.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cliCommand, handoverCliCommand, reporter } from "../suite-kit.mjs";

const [origin, tokenA, tokenB] = process.argv.slice(2);
if (!origin || !tokenA || !tokenB) {
  console.error("Usage: cli-handover.mjs <origin> <credential A> <credential B>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });
const scratch = mkdtempSync(join(tmpdir(), "cli-handover-"));

/** The two CLIs, by the name the checks use. */
const CLIS = { go: cliCommand, ts: handoverCliCommand };

/**
 * Runs `which` CLI with `args`, with `config` as its configuration
 * directory and home, from `cwd` (a checkout of acme/api, or a directory
 * outside any repository), with nothing from the host's Varlatch settings.
 */
function run(which, args, { config, cwd, input = "" }) {
  const env = { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0", VARLATCH_NODE_CHECK: "off" };
  const r = spawnSync(...CLIS[which](args), { cwd, env, input, encoding: "utf8", timeout: 90_000 });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}
const tail = (r) => `exit ${r.code}: ${r.out.trim().slice(-300)}`;
const holdsNoCredential = (text) => !text.includes(tokenA) && !text.includes(tokenB);

/** A store's file as text and its permission bits; null when missing. */
function file(config, name) {
  try {
    const path = join(config, name);
    return { text: readFileSync(path, "utf8"), mode: statSync(path).mode & 0o777 };
  } catch {
    return null;
  }
}

/** credentials.json with the token and the time of the sign-in taken out: what must be the same whichever CLI wrote it. */
function shape(text, token) {
  return text.replace(JSON.stringify(token), '"<token>"').replace(/"issuedAt": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z"/, '"issuedAt": "<time>"');
}

/** The identity and credential the server sees for `token`. */
async function me(token) {
  return fetch(`${origin}/v1/me`, { headers: { Authorization: `Bearer ${token}` } }).then((r) => r.json());
}

/**
 * Signs in with `signer` and uses the credential with `reader`: whoami
 * outside any repository (the default server the sign-in remembered), and
 * env list inside the checkout (the frozen format).
 */
async function signInThenRead(signer, reader, token) {
  const config = mkdtempSync(join(scratch, `${signer}-signs-in-`));
  const outside = mkdtempSync(join(scratch, "outside-"));
  const repo = mkdtempSync(join(scratch, "repo-"));
  const init = run(reader, ["init", "--org", "acme", "--project", "api", "--server", origin, "--no-agent-files"], { config, cwd: repo });
  if (init.code !== 0) throw new Error(`${reader} init exited ${init.code}: ${init.out.trim().slice(-300)}`);
  const login = run(signer, ["login", "--server", origin, "--token-stdin"], { config, cwd: outside, input: `${token}\n` });
  const who = run(reader, ["whoami", "--json"], { config, cwd: outside });
  const listed = run(reader, ["env", "list", "-e", "development"], { config, cwd: repo });
  let parsed = null;
  try {
    parsed = JSON.parse(who.stdout);
  } catch {
    // Judged below.
  }
  const expected = await me(token);
  const lines = listed.stdout.trim().split("\n");
  const ok =
    login.code === 0 &&
    /^Logged in to /.test(login.stdout) &&
    who.code === 0 &&
    parsed?.server === origin &&
    parsed?.identity?.id === expected?.identity?.id &&
    parsed?.credential?.id === expected?.credential?.id &&
    listed.code === 0 &&
    lines.includes("development  (development, shared, selected)") &&
    lines.includes("production  (production, shared)") &&
    holdsNoCredential(login.out + who.out + listed.out);
  return { config, ok, detail: `login ${tail(login)}; whoami ${tail(who)}; env list ${tail(listed)}` };
}

try {
  const fromTs = await signInThenRead("ts", "go", tokenA);
  check(
    "cli-handover.ts-login-go-reads",
    "signed in with the TypeScript CLI (--token-stdin), the Go CLI finds the default server and the credential: whoami and env list",
    fromTs.ok,
    fromTs.detail,
  );
  const fromGo = await signInThenRead("go", "ts", tokenB);
  check(
    "cli-handover.go-login-ts-reads",
    "signed in with the Go CLI (--token-stdin), the TypeScript CLI finds the default server and the credential: whoami and env list",
    fromGo.ok,
    fromGo.detail,
  );

  // The same store from either CLI: credentials.json and settings.json,
  // their text (but the token and the time) and their modes.
  const stores = ["credentials.json", "settings.json"].map((name) => [name, file(fromTs.config, name), file(fromGo.config, name)]);
  const differences = stores.flatMap(([name, ts, go]) => {
    if (!ts || !go) return [`${name}: ${ts ? "" : "TypeScript wrote none "}${go ? "" : "Go wrote none"}`];
    const out = [];
    const tsText = name === "credentials.json" ? shape(ts.text, tokenA) : ts.text;
    const goText = name === "credentials.json" ? shape(go.text, tokenB) : go.text;
    if (tsText !== goText) out.push(`${name}: TypeScript wrote ${JSON.stringify(tsText)}, Go ${JSON.stringify(goText)}`);
    if (process.platform !== "win32" && (ts.mode !== 0o600 || go.mode !== 0o600)) out.push(`${name}: modes ${ts.mode.toString(8)} and ${go.mode.toString(8)}, not 600`);
    return out;
  });
  check(
    "cli-handover.store-written-alike",
    "both CLIs write credentials.json and settings.json alike: the same text but the token and the time, mode 0600",
    differences.length === 0,
    differences.join("; "),
  );

  // A logout by one is seen by the other.
  const outside = mkdtempSync(join(scratch, "outside-"));
  const logouts = [
    ["go", "ts", fromTs.config],
    ["ts", "go", fromGo.config],
  ].map(([leaver, reader, config]) => {
    const out = run(leaver, ["logout"], { config, cwd: outside });
    const who = run(reader, ["whoami", "--server", origin], { config, cwd: outside });
    const stored = file(config, "credentials.json");
    const ok =
      out.code === 0 &&
      out.stdout.startsWith(`${origin}: `) &&
      who.code === 77 &&
      /^Not authenticated to /.test(who.stderr) &&
      stored?.text === `${JSON.stringify({ servers: {} }, null, 2)}\n` &&
      file(config, "settings.json")?.text === "{}\n" &&
      holdsNoCredential(out.out + who.out);
    return { ok, detail: `${leaver} logout ${tail(out)}; ${reader} whoami ${tail(who)}` };
  });
  check(
    "cli-handover.logout-seen-by-other",
    "a logout with either CLI empties the store and forgets the default server for the other: whoami is refused (77)",
    logouts.every((l) => l.ok),
    logouts.map((l) => l.detail).join(" | "),
  );
} catch (err) {
  error(`cli-handover: ${err.message}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
finish("CLI hand-over check(s)");
