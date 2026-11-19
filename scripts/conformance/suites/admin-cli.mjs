#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Organization administration with the CLI under test, one smoke check per
 * command (internal docs/design/go-cli.md, slice 5.7a): each exits 0, and
 * its --json document (NDJSON for member exposure) parses. The transcripts
 * and process tests hold the output byte for byte; this suite shows the
 * commands work against a real installation, started as every suite's.
 *
 *   admin-cli.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 *
 * It works in an Organization of its own, created here, with a Project,
 * an Environment, a machine identity and a Tailnet Requirement of its own;
 * nothing the seed made is touched.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cliCommand, reporter } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: admin-cli.mjs <origin> <api token>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });
const repo = mkdtempSync(join(tmpdir(), "admin-cli-repo-"));
const config = mkdtempSync(join(tmpdir(), "admin-cli-cfg-"));
const org = `e2e-admin-${randomBytes(4).toString("hex")}`;
const project = "smoke";

/** The CLI under test, in this suite's repository, with no Varlatch setting from the host. */
function cli(args) {
  const env = { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0" };
  const r = spawnSync(...cliCommand(args), { cwd: repo, env, encoding: "utf8", timeout: 90_000 });
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

/** One smoke check: the command exits 0, and its --json document parses (and satisfies ok). */
function smoke(id, name, args, ok = () => true) {
  const r = cli(args);
  const isJson = args.includes("--json");
  const parsed = isJson ? json(r.stdout) : undefined;
  const passed = r.code === 0 && (isJson ? parsed !== null && Boolean(ok(parsed)) : Boolean(ok(r)));
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

try {
  const login = cli(["login", "--server", origin, "--token", token]);
  if (login.code !== 0) throw new Error(`login exited ${login.code}: ${login.out.trim().slice(-400)}`);

  // org: create and list. There is no repository yet, so they name the
  // server (CLI 0.21.0 does not fall back to the only credential's).
  smoke("admin-cli.org-create", "org create makes an organization the caller administers", ["org", "create", org, "E2E admin", "--server", origin], (r) => r.stdout.includes(org));
  smoke("admin-cli.org-list-json", "org list --json lists it", ["org", "list", "--server", origin, "--json"], (d) => d.organizations?.some((o) => o.slug === org));

  // project: create, then a repository for it, list and rename.
  smoke("admin-cli.project-create", "project create --org makes a project", ["project", "create", project, "--org", org, "--server", origin]);
  const init = cli(["init", "--org", org, "--project", project, "--server", origin, "--no-agent-files"]);
  if (init.code !== 0) throw new Error(`init exited ${init.code}: ${init.out.trim().slice(-400)}`);
  smoke("admin-cli.project-list-json", "project list --json lists it", ["project", "list", "--json"], (d) => d.projects?.some((p) => p.slug === project));
  smoke("admin-cli.project-rename", "project rename renames it", ["project", "rename", project, "Smoke test"]);

  // env-create and env-delete.
  smoke("admin-cli.env-create", "env-create makes a root environment", ["env-create", "qa", "--tier", "development"]);
  smoke("admin-cli.env-delete", "env-delete deletes it", ["env-delete", "qa"]);

  // invite and member.
  smoke("admin-cli.invite", "invite prints a one-time enrollment link", ["invite", "Someone", "--role", "member"], (r) => r.stdout.includes("/enroll#"));
  smoke("admin-cli.member-list-json", "member list --json lists the caller", ["member", "list", "--json"], (d) => Array.isArray(d.members) && d.members.length >= 1);
  const me = (await api("GET", "/me"))?.identity?.id;
  smoke("admin-cli.member-role", "member role to the role the caller has changes nothing", ["member", "role", me ?? "me", "admin"]);
  const exposure = cli(["member", "exposure", "me", "--json"]);
  const records = exposure.stdout.trim().split("\n").map(json);
  check(
    "admin-cli.member-exposure-json",
    "member exposure --json is NDJSON, the member first",
    exposure.code === 0 && records.length >= 2 && records.every((r) => r !== null) && records[0].kind === "member" && records.at(-1).kind === "indirect",
    `exit ${exposure.code}: ${exposure.out.trim().slice(-400)}`,
  );

  // identity and credential, on a machine identity of the suite's own.
  const machine = await api("POST", `/organizations/${org}/identities`, { name: "smoke-machine", kind: "service" });
  smoke("admin-cli.identity-list-json", "identity list --json lists the machine", ["identity", "list", "--json"], (d) => d.identities?.some((i) => i.id === machine.id));
  smoke("admin-cli.identity-rename", "identity rename renames it", ["identity", "rename", machine.id, "smoke-machine-2"]);
  smoke("admin-cli.identity-reach-json", "identity reach --json shows its reach", ["identity", "reach", "smoke-machine-2", "--json"], (d) => d.identity?.id === machine.id);
  const out = join(repo, "machine.token");
  const issued = smoke("admin-cli.credential-issue-json", "credential issue --json writes the token to a new 0600 file only", ["credential", "issue", machine.id, "--name", "smoke", "--out", out, "--json"], (d) => {
    const mode = existsSync(out) ? statSync(out).mode & 0o777 : null;
    return typeof d.credential?.id === "string" && (process.platform === "win32" || mode === 0o600);
  });
  smoke("admin-cli.credential-list-json", "credential list --json lists it", ["credential", "list", machine.id, "--json"], (d) => d.credentials?.some((c) => c.id === issued.parsed?.credential?.id));
  smoke("admin-cli.credential-revoke", "credential revoke revokes it", ["credential", "revoke", machine.id, issued.parsed?.credential?.id ?? "crd_missing"]);
  smoke("admin-cli.identity-retire", "identity retire --confirm retires it", ["identity", "retire", machine.id, "--confirm", "smoke-machine-2"]);
  smoke("admin-cli.identity-reactivate", "identity reactivate reactivates it", ["identity", "reactivate", machine.id]);

  // tailnet: a development-tier Requirement of the suite's organization.
  const required = smoke("admin-cli.tailnet-require", "tailnet require makes a Tailnet Requirement", ["tailnet", "require", "--tier", "development", "--tailnet", "example.ts.net", "--tags", "tag:e2e"], (r) => /^Tailnet Requirement \S+:/.test(r.stdout));
  const requirement = /^Tailnet Requirement (\S+):/.exec(required.stdout)?.[1] ?? "req_missing";
  smoke("admin-cli.tailnet-requirements-json", "tailnet requirements --json lists it", ["tailnet", "requirements", "--json"], (d) => d.requirements?.some((x) => x.id === requirement));
  smoke("admin-cli.tailnet-remove", "tailnet remove removes it", ["tailnet", "remove", requirement]);

  // audit list.
  smoke("admin-cli.audit-list-json", "audit list --json lists the organization's events", ["audit", "list", "--json"], (d) => Array.isArray(d.events) && d.events.length > 0);
} catch (err) {
  error(err instanceof Error ? err.message : String(err));
} finally {
  rmSync(repo, { recursive: true, force: true });
  rmSync(config, { recursive: true, force: true });
}
finish("admin-cli check(s)");
