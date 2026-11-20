#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * The security commands with the CLI under test, one check per command
 * (internal docs/design/go-cli.md, slice 5.7b): security controls, set,
 * status and report each exit 0, and each --json document parses. The
 * transcripts and process tests hold the output byte for byte; this suite
 * shows the commands work against a real installation, started as every
 * suite's.
 *
 * `security set` also reads its change back (security controls --json), and
 * a loosening in assisted mode must stop for the person's approval (75),
 * print no credential, and change nothing; its approval is then cancelled.
 * The other checks are smoke checks.
 *
 *   security-cli.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 *
 * It works in an Organization of its own, created here, with --org and
 * --server outside any repository; nothing the seed made is touched.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cliCommand, reporter } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: security-cli.mjs <origin> <api token>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });
const cwd = mkdtempSync(join(tmpdir(), "security-cli-cwd-"));
const config = mkdtempSync(join(tmpdir(), "security-cli-cfg-"));
const org = `e2e-sec-${randomBytes(4).toString("hex")}`;
const scope = ["--org", org, "--server", origin];

/** The CLI under test, outside any repository, with no Varlatch setting from the host. */
function cli(args) {
  const env = { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0" };
  const r = spawnSync(...cliCommand(args), { cwd, env, encoding: "utf8", timeout: 90_000 });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

/** The parsed --json document, or null. */
function json(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** One check: the command exits 0, its --json document parses, and ok (given the document, or the run) holds. */
async function smoke(id, name, args, ok = () => true) {
  const r = cli(args);
  const isJson = args.includes("--json");
  const parsed = isJson ? json(r.stdout) : undefined;
  const passed = r.code === 0 && (isJson ? parsed !== null && Boolean(await ok(parsed, r)) : Boolean(await ok(r, r)));
  check(id, name, passed, `exit ${r.code}: ${r.out.trim().slice(-400)}`);
  return { ...r, parsed };
}

async function api(method, path, body) {
  const res = await fetch(`${origin}/v1${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

/** The control's mode, as security controls --json reads it. */
function modeOf(control) {
  return json(cli(["security", "controls", ...scope, "--json"]).stdout)?.items?.find((c) => c.control === control)?.mode;
}

try {
  const login = cli(["login", "--server", origin, "--token", token]);
  if (login.code !== 0) throw new Error(`login exited ${login.code}: ${login.out.trim().slice(-400)}`);
  await api("POST", "/organizations", { slug: org, name: "E2E security" });

  // controls
  await smoke("security-cli.controls", "security controls lists the organization's controls", ["security", "controls", ...scope], (r) => r.stdout.startsWith(`Security controls for ${org}:`));
  await smoke("security-cli.controls-json", "security controls --json lists them", ["security", "controls", ...scope, "--json"], (d) => d.organization === org && Array.isArray(d.items) && d.items.length >= 4);

  // set: tightening applies at once (from off, as a new Organization has it, so the check cannot pass unchanged)
  const before = modeOf("passkey-verification");
  await smoke("security-cli.set", "security set turns a control up at once (security controls agrees)", ["security", "set", "passkey-verification", "report", ...scope], () => before === "off" && modeOf("passkey-verification") === "report");
  await smoke("security-cli.set-json", "security set --json prints the change", ["security", "set", "requirement-protection", "report", ...scope, "--json"], (d) => d.organization === org && d.control?.control === "requirement-protection" && d.changed === true);

  // set: loosening in assisted mode stops for the approval, changes nothing, prints no credential
  const loosen = cli(["--assisted", "security", "set", "requirement-protection", "off", ...scope]);
  const approvalId = /--approval (apr_[A-Za-z0-9_-]+)/.exec(loosen.stderr)?.[1];
  check(
    "security-cli.set-loosen-waits",
    "a loosening in assisted mode stops for the approval (75), unchanged and with no credential printed",
    loosen.code === 75 && approvalId !== undefined && !/vlt_[a-z]+_/.test(loosen.out) && !loosen.out.includes(token) && modeOf("requirement-protection") === "report",
    `exit ${loosen.code}: ${loosen.out.trim().slice(-400)}`,
  );
  if (approvalId) await api("POST", `/me/approvals/${approvalId}/cancel`);

  // status and report
  await smoke("security-cli.status", "security status shows the organization's security", ["security", "status", ...scope], (r) => r.stdout.startsWith(`Security for ${org}`));
  await smoke("security-cli.status-json", "security status --json shows it", ["security", "status", ...scope, "--json"], (d) => d.organization === org && Array.isArray(d.controls?.items) && Array.isArray(d.unavailable));
  await smoke("security-cli.report", "security report shows the credential review", ["security", "report", ...scope], (r) => r.stdout.startsWith(`Credential review for ${org}`));
  await smoke("security-cli.report-json", "security report --json shows it", ["security", "report", ...scope, "--json"], (d) => d.organization === org && typeof d.credentialReview?.summary === "object");
} catch (err) {
  error(err instanceof Error ? err.message : String(err));
} finally {
  rmSync(cwd, { recursive: true, force: true });
  rmSync(config, { recursive: true, force: true });
}
finish("security-cli check(s)");
