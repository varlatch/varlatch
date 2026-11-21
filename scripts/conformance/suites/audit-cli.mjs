#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * The audit export, deletion and freezes with the CLI under test (internal
 * docs/design/go-cli.md, slice 5.7c): audit-export show, check, create,
 * change and remove against a local S3 server with Object Lock; audit
 * export (NDJSON) and --deleted-org; project delete; org delete, deletion
 * and its cancel; org freeze and unfreeze. Each exits as it should and
 * each --json document parses.
 *
 * Every destructive command is also run without its confirmation, and must
 * refuse (64) with nothing changed, read back over the API. A step that
 * needs the person's passkey approval (unfreezing, removing the export)
 * runs in assisted mode: it must stop for the approval (75) with nothing
 * changed, and its approval is then cancelled. The secret access key goes
 * in on standard input and must appear in no output.
 *
 *   audit-cli.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 *
 * It works in Organizations of its own, created here; nothing the seed
 * made is touched.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { s3Request } from "../lib/s3.mjs";
import { cliCommand, reporter, targetOp } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: audit-cli.mjs <origin> <api token>");
  process.exit(64);
}
const { check, error, finish, supports } = reporter({ detailOnFailure: true });
const repo = mkdtempSync(join(tmpdir(), "audit-cli-repo-"));
const config = mkdtempSync(join(tmpdir(), "audit-cli-cfg-"));
const suffix = randomBytes(4).toString("hex");
const org = `e2e-audit-${suffix}`; // the audit export and the log
const doomed = `e2e-del-${suffix}`; // deletion scheduled, then cancelled
const frozen = `e2e-frz-${suffix}`; // frozen, left frozen
const server = ["--server", origin];

/** The CLI under test, with no Varlatch setting from the host. */
function cli(args, { cwd = repo, input = "" } = {}) {
  const env = { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0" };
  const r = spawnSync(...cliCommand(args), { cwd, env, input, encoding: "utf8", timeout: 120_000 });
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

/** One check on a run: its exit status, and ok (given the run and its --json document). */
async function expect(id, name, args, status, ok = () => true, options = {}) {
  const r = cli(args, options);
  const parsed = args.includes("--json") ? json(r.stdout) : undefined;
  const passed = r.code === status && (parsed !== null) && Boolean(await ok(r, parsed));
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

/** Cancel the approval an assisted run stopped for, named in its --approval command. */
async function cancelApproval(r) {
  const id = /--approval (apr_[A-Za-z0-9_-]+)/.exec(r.stderr)?.[1];
  if (id) await api("POST", `/me/approvals/${id}/cancel`);
  return id !== undefined;
}

try {
  const login = cli(["login", ...server, "--token", token]);
  if (login.code !== 0) throw new Error(`login exited ${login.code}: ${login.out.trim().slice(-400)}`);
  for (const slug of [org, doomed, frozen]) await api("POST", "/organizations", { slug, name: `E2E ${slug}` });
  await api("POST", `/organizations/${org}/projects`, { slug: "kept", name: "Kept", contractAuthority: "git" });
  await api("POST", `/organizations/${org}/projects`, { slug: "gone", name: "Gone", contractAuthority: "git" });
  const init = cli(["init", "--org", org, "--project", "kept", ...server, "--no-agent-files"]);
  if (init.code !== 0) throw new Error(`init exited ${init.code}: ${init.out.trim().slice(-400)}`);
  const projects = async () => (await api("GET", `/organizations/${org}/projects`)).items.map((p) => p.slug);

  // project delete
  await expect("audit-cli.project-delete-unconfirmed", "project delete without --confirm refuses (64) and deletes nothing", ["project", "delete", "gone"], 64, async () => (await projects()).includes("gone"));
  await expect("audit-cli.project-delete", "project delete --confirm deletes the Project", ["project", "delete", "gone", "--confirm", "gone"], 0, async (r) => r.stdout.startsWith("Project gone deleted") && !(await projects()).includes("gone"));

  // audit export (NDJSON) and --deleted-org
  await expect("audit-cli.audit-export-ndjson", "audit export prints the log as NDJSON", ["audit", "export"], 0, (r) => {
    const lines = r.stdout.trim().split("\n");
    return lines.length > 0 && lines.every((l) => json(l) !== null);
  });
  await expect("audit-cli.audit-export-deleted-unknown", "audit export --deleted-org of an unknown id fails with the server's 404 (1)", ["audit", "export", "--deleted-org", `org_${"a".repeat(26)}`, ...server], 1, (r) => r.stderr.includes("RESOURCE_NOT_FOUND"));

  // org delete, org deletion, cancel (in an Organization of its own)
  const deletion = async () => (await api("GET", `/organizations/${doomed}/deletion`)).deletion;
  await expect("audit-cli.org-delete-unconfirmed", "org delete without --confirm refuses (64) and schedules nothing", ["org", "delete", doomed, ...server], 64, async () => (await deletion()) === null);
  await expect("audit-cli.org-delete-schedule", "org delete --confirm schedules the deletion", ["org", "delete", doomed, "--confirm", doomed, ...server], 0, async (r) => r.stdout.startsWith(`Deletion of ${doomed} scheduled.`) && (await deletion()) !== null);
  const listed = await expect("audit-cli.org-deletion-json", "org deletion --json shows it", ["org", "deletion", doomed, ...server, "--json"], 0, (_, d) => d.organization === doomed && typeof d.deletion?.id === "string");
  await expect("audit-cli.org-delete-cancel", "org delete --cancel cancels it", ["org", "delete", doomed, "--cancel", listed.parsed?.deletion?.id ?? "del_missing", ...server], 0, async () => (await deletion()) === null);

  // org freeze and unfreeze (in an Organization of its own, left frozen); CLI 0.22.0 and later
  if (supports("incident-freeze")) {
    const freeze = async () => (await api("GET", `/organizations/${frozen}/incident-freeze`)).freeze;
    await expect("audit-cli.org-freeze-unconfirmed", "org freeze without --confirm refuses (64) and freezes nothing", ["org", "freeze", frozen, "--reason", "e2e", ...server], 64, async () => (await freeze()) === null);
    await expect("audit-cli.org-freeze", "org freeze --confirm freezes it", ["org", "freeze", frozen, "--reason", "e2e", "--confirm", frozen, ...server], 0, async () => (await freeze()) !== null);
    const lift = cli(["--assisted", "org", "unfreeze", frozen, ...server]);
    check(
      "audit-cli.org-unfreeze-waits",
      "org unfreeze in assisted mode stops for the passkey approval (75), still frozen",
      lift.code === 75 && (await cancelApproval(lift)) && (await freeze()) !== null,
      `exit ${lift.code}: ${lift.out.trim().slice(-400)}`,
    );
  }

  // audit-export; CLI 0.22.0 and later, against a local S3 server with Object Lock
  if (supports("audit-export")) {
    const store = JSON.parse(targetOp("object-store", ["start"]));
    const s3 = { endpoint: store.hostEndpoint, region: store.region, accessKeyId: store.accessKeyId, secretAccessKey: store.secretAccessKey };
    const bucket = `audit-cli-${suffix}`;
    const deadline = Date.now() + 30_000;
    const lockHeaders = { "x-amz-bucket-object-lock-enabled": "true" };
    let made = await s3Request(s3, "PUT", `/${bucket}`, { headers: lockHeaders });
    while (made.status === 503 && made.text.includes("XMinioServerNotInitialized") && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      made = await s3Request(s3, "PUT", `/${bucket}`, { headers: lockHeaders, timeoutMs: Math.max(1, deadline - Date.now()) });
  }
  if (made.status !== 200) throw new Error(`creating the bucket: ${made.status} ${made.text.slice(0, 300)}`);
  const destination = ["--endpoint", store.endpoint, "--region", store.region, "--bucket", bucket, "--prefix", "varlatch", "--path-style"];
  const key = ["--access-key-id", store.accessKeyId, "--secret-stdin"];
  const secret = { input: `${store.secretAccessKey}\n` };
  const shown = (r) => !r.out.includes(store.secretAccessKey);
  const exportState = async () => (await api("GET", `/organizations/${org}/audit-export`)).export?.state ?? null;

  await expect("audit-cli.audit-export-show-json", "audit-export show --json shows no export yet", ["audit-export", "show", "--json"], 0, (_, d) => d.organization === org && d.export === null);
  await expect("audit-cli.audit-export-check", "audit-export check passes a destination, saves nothing, never shows the key", ["audit-export", "check", ...destination, ...key, "--retention", "governance:1"], 0, async (r) => r.stdout.startsWith("The destination passed the check") && shown(r) && (await exportState()) === null, secret);
  await expect("audit-cli.audit-export-create", "audit-export create --json makes the export, never showing the key", ["audit-export", "create", ...destination, ...key, "--retention", "governance:1", "--json"], 0, (r, d) => d.export?.state === "active" && shown(r), secret);
  await expect("audit-cli.audit-export-change", "audit-export change --retention longer applies at once", ["audit-export", "change", "--retention", "governance:2"], 0, (r) => r.stdout.startsWith(`The audit export of ${org} was changed`));
  await expect("audit-cli.audit-export-show", "audit-export show shows it active", ["audit-export", "show"], 0, (r) => r.stdout.startsWith(`Audit export of ${org}: active`));
  await expect("audit-cli.audit-export-remove-unconfirmed", "audit-export remove without --confirm refuses (64), the export kept", ["audit-export", "remove"], 64, async () => (await exportState()) === "active");
  const removal = cli(["--assisted", "audit-export", "remove", "--confirm", org]);
  check(
    "audit-cli.audit-export-remove-waits",
    "audit-export remove in assisted mode stops for the passkey approval (75), the export kept",
    removal.code === 75 && (await cancelApproval(removal)) && (await exportState()) === "active",
    `exit ${removal.code}: ${removal.out.trim().slice(-400)}`,
  );
  }
} catch (err) {
  error(err instanceof Error ? err.message : String(err));
} finally {
  rmSync(repo, { recursive: true, force: true });
  rmSync(config, { recursive: true, force: true });
}
finish("audit-cli check(s)");
