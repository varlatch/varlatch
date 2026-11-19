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
 *   cli-handover.mjs <origin> <credential A> <credential B> <enrollment URL>   (run by scripts/conformance/run.mjs)
 *
 * The credentials are two fresh CLI credentials of the admin identity, one
 * per direction; the enrollment URL is a recovery grant for the admin, whose
 * passkey (a virtual authenticator) approves and denies device sign-ins. The
 * runner seeded organization acme, project api with the environments
 * development and production.
 *
 * Token sign-in both ways (slice 5.1e): signed in by one CLI, the other
 * finds the credential and the default server; both write the store alike;
 * a logout by one is seen by the other.
 *
 * Device sign-in both ways (slice 5.2): a `login --start` by one CLI is
 * waited for by the other, which reaches its deadline (75) with the entry
 * kept; the first continues it with the interval kept (no poll before it is
 * due); approved in the browser, the other collects and stores it and the
 * entry goes; a denial seen by the other removes the entry; the file's and
 * its directory's modes after each step; and both refuse to start one
 * inside an agent-safe run.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cliCommand, handoverCliCommand, reporter } from "../suite-kit.mjs";

const [origin, tokenA, tokenB, enrollUrl] = process.argv.slice(2);
if (!origin || !tokenA || !tokenB || !enrollUrl?.includes("#")) {
  console.error("Usage: cli-handover.mjs <origin> <credential A> <credential B> <enrollment URL>");
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
function run(which, args, { config, cwd, input = "", env: extra = {} }) {
  const env = { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0", VARLATCH_NODE_CHECK: "off", ...extra };
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
  await deviceHandover();
} catch (err) {
  error(`cli-handover: ${err.message}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
finish("CLI hand-over check(s)");

/** pending-sign-ins.json in `config`: its entry for the origin, and the file's and the directory's modes; null when there is no file. */
function pending(config) {
  const path = join(config, "pending-sign-ins.json");
  if (!existsSync(path)) return null;
  const entry = Object.values(JSON.parse(readFileSync(path, "utf8")).servers ?? {})[0] ?? null;
  return { entry, mode: statSync(path).mode & 0o777, dirMode: statSync(config).mode & 0o777 };
}
/** Whether a pending-sign-ins.json state is private: the file 0600 in a 0700 directory. */
function privateModes(p) {
  return process.platform === "win32" || (p?.mode === 0o600 && p?.dirMode === 0o700);
}
/** The credential `config` stores for the origin, or null. */
function stored(config) {
  const f = file(config, "credentials.json");
  return f ? ((JSON.parse(f.text).servers ?? {})[origin] ?? null) : null;
}

/** The device sign-in hand-over, with a browser whose passkey approves and denies (the device suite's flow). */
async function deviceHandover() {
  const { chromium } = createRequire(new URL("../../../apps/web/package.json", import.meta.url))("playwright");
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });
    await page.goto(enrollUrl);
    await page.click("#enroll");
    await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 20000 });
    if (!/API credential/.test(await page.textContent("#status"))) throw new Error("the passkey was not enrolled");
    const decide = async (userCode, decision) => {
      await page.goto(`${origin}/device`);
      await page.waitForSelector('[data-testid="device-code-input"]', { timeout: 20000 });
      await page.fill('[data-testid="device-code-input"]', userCode);
      await page.click('[data-testid="device-continue"]');
      await page.waitForSelector('[data-testid="device-confirm"]', { timeout: 10000 });
      await page.click(`[data-testid="device-${decision}"]`);
      await page.waitForSelector('[data-testid="device-result"]', { timeout: 20000 });
      return page.getAttribute('[data-testid="device-result"]', "data-decision");
    };
    const outside = mkdtempSync(join(scratch, "outside-"));

    // The check IDs, spelled out (the inventory test reads them from this file).
    const IDS = {
      ts: { waits: "cli-handover.device-ts-start-go-waits", collects: "cli-handover.device-ts-start-go-collects", denied: "cli-handover.device-ts-start-go-denied" },
      go: { waits: "cli-handover.device-go-start-ts-waits", collects: "cli-handover.device-go-start-ts-collects", denied: "cli-handover.device-go-start-ts-denied" },
    };
    for (const [starter, waiter] of [["ts", "go"], ["go", "ts"]]) {
      // Started by one; the other waits to its deadline, the entry kept; the first continues within the interval.
      const config = mkdtempSync(join(scratch, `${starter}-starts-device-`));
      const started = run(starter, ["login", "--server", origin, "--start", "--json"], { config, cwd: outside });
      let doc = {};
      try {
        doc = JSON.parse(started.stdout);
      } catch {
        // judged below
      }
      const afterStart = pending(config);
      const early = run(waiter, ["login", "--server", origin, "--wait", "--timeout", "3"], { config, cwd: outside });
      const afterEarly = pending(config);
      const begun = Date.now();
      const kept = run(starter, ["login", "--server", origin, "--wait", "--timeout", "1"], { config, cwd: outside });
      const afterKept = pending(config);
      check(
        IDS[starter].waits,
        `a device sign-in started with the ${starter === "ts" ? "TypeScript" : "Go"} CLI: the other's --wait reaches its deadline (75) with the entry kept, and the first continues it with the interval kept (no early poll); the file 0600 in a 0700 directory after each step`,
        started.code === 0 &&
          /^[A-Z]{4}-[A-Z]{4}$/.test(doc.userCode ?? "") &&
          afterStart?.entry?.userCode === doc.userCode &&
          early.code === 75 &&
          typeof afterEarly?.entry?.lastPolledAt === "string" &&
          afterEarly.entry.deviceCode === afterStart.entry.deviceCode &&
          kept.code === 75 &&
          Date.now() - begun < 5000 &&
          afterKept?.entry?.lastPolledAt === afterEarly.entry.lastPolledAt &&
          afterKept?.entry?.interval === afterEarly.entry.interval &&
          [afterStart, afterEarly, afterKept].every(privateModes) &&
          holdsNoCredential(started.out + early.out + kept.out) &&
          !(started.out + early.out + kept.out).includes(afterStart?.entry?.deviceCode ?? "no device code"),
        `start ${tail(started)}; ${waiter} wait ${tail(early)}; ${starter} wait ${tail(kept)}; entries ${JSON.stringify([afterStart, afterEarly, afterKept].map((p) => p && { mode: p.mode.toString(8), dirMode: p.dirMode.toString(8), lastPolledAt: p.entry?.lastPolledAt, interval: p.entry?.interval }))}`,
      );

      // Approved in the browser: the other collects and stores it, and the entry goes.
      const decision = await decide(doc.userCode ?? "", "approve");
      const done = run(waiter, ["login", "--server", origin, "--wait"], { config, cwd: outside });
      const credential = stored(config);
      check(
        IDS[starter].collects,
        `approved in the browser, a device sign-in started with the ${starter === "ts" ? "TypeScript" : "Go"} CLI is collected and stored by the other, and the entry removed`,
        decision === "approved" &&
          done.code === 0 &&
          /^Logged in to /.test(done.stdout) &&
          typeof credential?.token === "string" &&
          !done.out.includes(credential.token) &&
          pending(config) === null &&
          (process.platform === "win32" || file(config, "credentials.json")?.mode === 0o600),
        `decision ${decision}; ${waiter} wait ${tail(done)}`,
      );

      // A denial seen by the other: 77, the entry removed, the stored credential kept.
      const second = run(starter, ["login", "--server", origin, "--start", "--json"], { config, cwd: outside });
      let code = "";
      try {
        code = JSON.parse(second.stdout).userCode ?? "";
      } catch {
        // judged below
      }
      const denial = await decide(code, "deny");
      const denied = run(waiter, ["login", "--server", origin, "--wait"], { config, cwd: outside });
      check(
        IDS[starter].denied,
        `denied in the browser, a device sign-in started with the ${starter === "ts" ? "TypeScript" : "Go"} CLI ends for the other with 77, the entry removed and the stored credential kept`,
        second.code === 0 && denial === "denied" && denied.code === 77 && /denied/.test(denied.stderr) && pending(config) === null && stored(config)?.token === credential?.token,
        `start ${tail(second)}; decision ${denial}; ${waiter} wait ${tail(denied)}`,
      );
    }

    // Both refuse to start one inside an agent-safe run, before any request or file.
    const refusals = ["ts", "go"].map((which) => {
      const config = mkdtempSync(join(scratch, `${which}-agent-run-`));
      const r = run(which, ["login", "--server", origin, "--start"], { config, cwd: outside, env: { VARLATCH_AGENT_RUN: "run_handover" } });
      return { ok: r.code === 64 && /agent-safe run run_handover/.test(r.stderr) && pending(config) === null, detail: `${which} ${tail(r)}` };
    });
    check(
      "cli-handover.device-refused-in-agent-run",
      "inside an agent-safe run, both CLIs refuse to start a device sign-in (64) and write no pending sign-in",
      refusals.every((r) => r.ok),
      refusals.map((r) => r.detail).join(" | "),
    );
  } finally {
    await browser.close();
  }
}
