// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Approval, AuditExport } from "@varlatch/sdk";
import {
  AuditExportUsageError,
  changeInput,
  changeRequest,
  checkInput,
  checkLines,
  createInput,
  parseRetention,
  statusLines,
} from "../src/auditExport.js";
import { EXIT } from "../src/exitCodes.js";
import { commandHelp } from "../src/usage.js";

/**
 * `varlatch audit-export` (ADR-0056): the secret access key never on the
 * command line, approvals through the shared step-up handling, removal
 * named again with --confirm (assisted mode leaves it to the person), and
 * what each subcommand sends.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-audit-export-"));
const bundle = join(dir, "varlatch.cjs");
const ORG = "/v1/organizations/acme";
const SECRET = "the-secret-access-key-0001";

let server: http.Server;
let origin = "";
let capabilities: string[] = [];
let requests: { method: string; url: string; body: unknown; approval: string | null }[] = [];
let current: AuditExport | null = null;

function exportOf(over: Partial<AuditExport> = {}): AuditExport {
  return {
    id: "aex_1",
    organizationId: "org_1",
    destination: { endpoint: "https://s3.eu-central-1.amazonaws.com", region: "eu-central-1", bucket: "acme-audit", prefix: "", pathStyle: false },
    retention: { mode: "compliance", days: 400 },
    state: "active",
    streamId: "aes_1",
    cursor: "42",
    version: 3,
    lastAttemptAt: "2026-11-13T10:00:00.000Z",
    lastSuccessAt: "2026-11-13T10:00:00.000Z",
    lastHeartbeatAt: "2026-11-13T10:00:00.000Z",
    lastError: null,
    failingSince: null,
    keyCanRead: false,
    retentionReadable: false,
    stoppedReason: null,
    conditionalCheckedAt: "2026-11-13T09:00:00.000Z",
    lockVerified: true,
    drainDeadline: null,
    createdBy: "idn_ada",
    createdAt: "2026-11-13T09:00:00.000Z",
    removedAt: null,
    lag: { pending: 0, oldestPendingAt: null },
    objectLock: "verified",
    unsupportedPlanFormat: null,
    ...over,
  };
}

function approval(state: Approval["state"], operation: Approval["operation"]): Approval {
  const created = Date.now();
  return {
    id: "apr_1",
    operation,
    organization: { id: "org_1", slug: "acme", name: "Acme" },
    summary: { title: "Change the audit export of Acme", changes: [{ field: "retention", from: "compliance, 400 days", to: "none", loosens: true }] },
    state,
    closeReason: null,
    requestedBy: { credentialKind: "cli", client: "varlatch CLI on Linux" },
    url: "https://varlatch.example/approve/apr_1",
    interval: 1,
    createdAt: new Date(created).toISOString(),
    expiresAt: new Date(created + 600_000).toISOString(),
    approvedAt: state === "approved" ? new Date(created).toISOString() : null,
    consumedAt: null,
    closedAt: null,
  };
}

function answer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    const header = req.headers["varlatch-approval"];
    const body = raw ? JSON.parse(raw) : undefined;
    if (url !== "/") requests.push({ method: req.method ?? "", url, body, approval: typeof header === "string" ? header : null });
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    const stepUp = (operation: Approval["operation"]) =>
      json(403, { error: { code: "STEP_UP_REQUIRED", message: "This needs your approval with a trusted passkey", requestId: "req_1", details: { approval: approval("pending", operation) } } });
    if (url === "/v1/meta") return json(200, { apiMajor: 1, serverVersion: "0.22.0", capabilities });
    if (url === "/v1/me/approvals/apr_1") return json(200, approval("approved", "audit_export.change"));
    if (url === `${ORG}/audit-export` && req.method === "GET") return json(200, { enabled: true, export: current });
    if (url === `${ORG}/audit-export` && req.method === "POST") return json(201, exportOf({ version: 1 }));
    if (url === `${ORG}/audit-export/check` && req.method === "POST") {
      return json(200, { ok: true, message: null, conditionalCreation: true, objectLock: "verified", keyCanRead: false, retentionReadable: false });
    }
    if (url === `${ORG}/audit-export` && req.method === "PATCH") {
      if (!header) return stepUp("audit_export.change");
      return json(200, { export: exportOf({ version: 4, retention: null, objectLock: "not-set" }), changed: true, loosened: true });
    }
    if (url === `${ORG}/audit-export/credential` && req.method === "PUT") {
      if (!header) return stepUp("audit_export.change");
      return json(200, exportOf({ version: 4 }));
    }
    if (url.startsWith(`${ORG}/audit-export?`) && req.method === "DELETE") {
      if (!header) return stepUp("audit_export.remove");
      return json(200, exportOf({ version: 4, state: "removed", lag: null }));
    }
    json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "Not found", requestId: "req_1" } });
  });
}

beforeAll(async () => {
  await build({
    entryPoints: [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    outfile: bundle,
    logLevel: "silent",
  });
  server = http.createServer(answer);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  requests = [];
  capabilities = ["audit.storage-export"];
  current = exportOf();
});

function cli(args: string[], options: { env?: Record<string, string>; stdin?: string } = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bundle, ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_TOKEN: "vlt_test", VARLATCH_ASSISTED: "0", ...options.env },
      stdio: [options.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    if (options.stdin !== undefined) child.stdin!.end(options.stdin);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

const scope = () => ["--org", "acme", "--server", origin];
const changes = () => requests.filter((r) => r.method !== "GET");
const CREATE = ["--endpoint", "https://s3.eu-central-1.amazonaws.com", "--region", "eu-central-1", "--bucket", "acme-audit", "--access-key-id", "AKIA0001"];

describe("varlatch audit-export", () => {
  it("show: the status in words, or JSON", async () => {
    const r = await cli(["audit-export", "show", ...scope()]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Audit export of acme: active");
    expect(r.stdout).toContain("s3.eu-central-1.amazonaws.com, bucket acme-audit");
    expect(r.stdout).toContain("compliance, 400 days; Object Lock verified");
    const j = await cli(["audit-export", "show", "--json", ...scope()]);
    expect(JSON.parse(j.stdout)).toMatchObject({ organization: "acme", enabled: true, export: { id: "aex_1" } });
    current = null;
    expect((await cli(["audit-export", "show", ...scope()])).stdout).toContain("acme has no audit export.");
  });

  it("create: the secret from standard input or a file, never the command line; never a prompt without a terminal", async () => {
    const piped = await cli(["audit-export", "create", ...CREATE, "--secret-stdin", "--retention", "compliance:400", "--from", "now", ...scope()], { stdin: `${SECRET}\n` });
    expect(piped.code, piped.stderr).toBe(0);
    expect(changes()).toEqual([{
      method: "POST",
      url: `${ORG}/audit-export`,
      body: {
        destination: { endpoint: "https://s3.eu-central-1.amazonaws.com", region: "eu-central-1", bucket: "acme-audit" },
        credential: { accessKeyId: "AKIA0001", secretAccessKey: SECRET },
        retention: { mode: "compliance", days: 400 },
        from: "now",
      },
      approval: null,
    }]);
    expect(piped.stdout + piped.stderr).not.toContain(SECRET);
    requests = [];
    const file = join(dir, "secret.txt");
    writeFileSync(file, `${SECRET}\n`);
    const fromFile = await cli(["audit-export", "create", ...CREATE, "--secret-file", file, ...scope()]);
    expect(fromFile.code, fromFile.stderr).toBe(0);
    expect((changes()[0]!.body as { credential: unknown }).credential).toEqual({ accessKeyId: "AKIA0001", secretAccessKey: SECRET });
    requests = [];
    // No terminal and no source: refused before any request, in either mode.
    for (const env of [{}, { VARLATCH_ASSISTED: "1" }]) {
      const none = await cli(["audit-export", "create", ...CREATE, ...scope()], { env });
      expect(none.code).toBe(EXIT.usage);
      expect(none.stderr).toContain("--secret-stdin or --secret-file");
    }
    // There is no option that takes the secret itself.
    const inline = await cli(["audit-export", "create", ...CREATE, "--secret-access-key", SECRET, ...scope()]);
    expect(inline.code).toBe(EXIT.usage);
    expect(requests).toEqual([]);
  });

  it("change: loosening asks for the approval, waits, and repeats with it; a new key on its own", async () => {
    const r = await cli(["audit-export", "change", "--no-retention", ...scope()]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain("https://varlatch.example/approve/apr_1");
    expect(changes().map((c) => [c.method, c.approval, c.body])).toEqual([
      ["PATCH", null, { expectedVersion: 3, retention: null }],
      ["PATCH", "apr_1", { expectedVersion: 3, retention: null }],
    ]);
    expect(r.stdout).toContain("your approval was used");
    requests = [];
    const key = await cli(["audit-export", "change", "--access-key-id", "AKIA0002", "--secret-stdin", ...scope()], { stdin: SECRET });
    expect(key.code, key.stderr).toBe(0);
    expect(changes().map((c) => [c.method, c.url, c.approval])).toEqual([
      ["PUT", `${ORG}/audit-export/credential`, null],
      ["PUT", `${ORG}/audit-export/credential`, "apr_1"],
    ]);
    expect(changes()[1]!.body).toEqual({ expectedVersion: 3, credential: { accessKeyId: "AKIA0002", secretAccessKey: SECRET } });
    requests = [];
    const both = await cli(["audit-export", "change", "--bucket", "other", "--access-key-id", "AKIA0002", "--secret-stdin", ...scope()], { stdin: SECRET });
    expect(both.code).toBe(EXIT.usage);
    expect(both.stderr).toContain("change the key on its own");
    expect(requests).toEqual([]);
  });

  it("change in assisted mode: prints the address and exits 75 instead of waiting", async () => {
    const r = await cli(["audit-export", "change", "--no-retention", ...scope()], { env: { VARLATCH_ASSISTED: "1" } });
    expect(r.code).toBe(75);
    expect(r.stderr).toContain("https://varlatch.example/approve/apr_1");
    expect(changes().map((c) => c.approval)).toEqual([null]);
  });

  it("remove: named again with --confirm; assisted mode leaves it to the person; then the approval", async () => {
    const plain = await cli(["audit-export", "remove", ...scope()]);
    expect(plain.code).toBe(EXIT.usage);
    expect(plain.stderr).toContain(`varlatch audit-export remove --confirm acme --org acme --server ${origin}`);
    const assisted = await cli(["audit-export", "remove", ...scope()], { env: { VARLATCH_ASSISTED: "1" } });
    expect(assisted.code).toBe(EXIT.config);
    expect(assisted.stderr).toContain("That is the human's decision. With their approval, add --confirm acme.");
    const other = await cli(["audit-export", "remove", "--confirm", "beta", ...scope()]);
    expect(other.code).toBe(EXIT.usage);
    expect(requests).toEqual([]);
    const r = await cli(["audit-export", "remove", "--confirm", "acme", ...scope()]);
    expect(r.code, r.stderr).toBe(0);
    expect(changes().map((c) => [c.method, c.url, c.approval])).toEqual([
      ["DELETE", `${ORG}/audit-export?expectedVersion=3`, null],
      ["DELETE", `${ORG}/audit-export?expectedVersion=3`, "apr_1"],
    ]);
    expect(r.stdout).toContain("What it delivered stays in the bucket.");
  });

  it("check: the export's own destination and stored key by default; exit 1 when it fails", async () => {
    const r = await cli(["audit-export", "check", ...scope()]);
    expect(r.code, r.stderr).toBe(0);
    expect(changes()).toEqual([{
      method: "POST",
      url: `${ORG}/audit-export/check`,
      body: { destination: exportOf().destination, retention: { mode: "compliance", days: 400 } },
      approval: null,
    }]);
    expect(r.stdout).toContain("The destination passed the check");
  });

  it("refuses on a server without audit export, sending nothing else", async () => {
    capabilities = [];
    const r = await cli(["audit-export", "show", ...scope()]);
    expect(r.code).toBe(EXIT.failure);
    expect(r.stderr).toContain("has no audit export to object storage");
    expect(requests.map((x) => x.url)).toEqual(["/v1/meta"]);
  });

  it("has help entries", () => {
    const help = commandHelp("audit-export") ?? "";
    for (const sub of ["show", "create", "change", "remove", "check"]) expect(help).toContain(`varlatch audit-export ${sub}`);
    expect(help).toContain("never the command line");
  });
});

describe("the command line, before any request", () => {
  const values = (pairs: Record<string, string>) => new Map(Object.entries(pairs));
  const flags = (...names: string[]) => new Set(names);

  it("parses retention", () => {
    expect(parseRetention("governance:1")).toEqual({ mode: "governance", days: 1 });
    for (const bad of ["compliance", "compliance:0", "compliance:3651", "legal:10", "compliance:-1"]) {
      expect(() => parseRetention(bad), bad).toThrow(AuditExportUsageError);
    }
  });

  it("create needs the destination and a key id, and takes no --no-retention", () => {
    expect(() => createInput(values({ "--region": "r", "--bucket": "b", "--access-key-id": "k" }), flags())).toThrow(/--endpoint/);
    expect(() => createInput(values({ "--endpoint": "https://x", "--region": "r", "--bucket": "b" }), flags())).toThrow(/--access-key-id/);
    expect(() => createInput(values({ "--endpoint": "https://x", "--region": "r", "--bucket": "b", "--access-key-id": "k" }), flags("--no-retention"))).toThrow(AuditExportUsageError);
    expect(createInput(values({ "--endpoint": "https://x", "--region": "r", "--bucket": "b", "--access-key-id": "k" }), flags("--path-style"))).toEqual({
      destination: { endpoint: "https://x", region: "r", bucket: "b", pathStyle: true },
      retention: null,
      from: "beginning",
    });
  });

  it("change names what changes, sends only that, at the current version", () => {
    expect(() => changeRequest(values({}), flags())).toThrow(/name what changes/);
    expect(() => changeRequest(values({ "--retention": "compliance:1" }), flags("--no-retention"))).toThrow(AuditExportUsageError);
    expect(() => changeRequest(values({}), flags("--path-style", "--no-path-style"))).toThrow(AuditExportUsageError);
    expect(() => changeRequest(values({}), flags("--secret-stdin"))).toThrow(/--access-key-id/);
    const request = changeRequest(values({ "--prefix": "audit/" }), flags("--no-path-style"));
    expect(request.kind === "settings" && changeInput(request, exportOf())).toEqual({ expectedVersion: 3, destination: { prefix: "audit/", pathStyle: false } });
    expect(changeRequest(values({ "--access-key-id": "k" }), flags("--secret-stdin"))).toEqual({ kind: "key" });
  });

  it("check takes the export's destination unless one is named", () => {
    expect(checkInput(values({ "--bucket": "other" }), flags(), exportOf()).destination.bucket).toBe("other");
    expect(() => checkInput(values({}), flags(), null)).toThrow(/no export to check/);
  });

  it("says nothing about reading retention when none is configured", () => {
    const key = (over: Partial<AuditExport>) => statusLines("acme", { enabled: true, export: exportOf(over) }).find((l) => l.startsWith("  key "));
    expect(key({ retention: null, objectLock: "not-set", keyCanRead: true, retentionReadable: null })).toBe("  key           can read objects");
    expect(key({ keyCanRead: null, retentionReadable: null })).toBe("  key           object read not determined, retention read not determined");
    expect(key({ keyCanRead: false, retentionReadable: false })).toBe("  key           write-only, cannot read retention");
  });

  it("words the status and the check without the key", () => {
    const stopped = statusLines("acme", { enabled: false, export: exportOf({ stoppedReason: "object_conflict", lastError: "An object with this name exists with other content; nothing was overwritten", unsupportedPlanFormat: 2 }) });
    expect(stopped[0]).toContain("stopped by the host operator");
    expect(stopped.join("\n")).toContain("STOPPED       an object with the planned name exists with other content");
    expect(stopped.join("\n")).toContain("planned in format 2");
    expect(checkLines({ ok: false, message: "This destination overwrote an existing object; audit export needs conditional writes (If-None-Match)", conditionalCreation: false, objectLock: null, keyCanRead: null, retentionReadable: null }))
      .toEqual(["The destination check failed: This destination overwrote an existing object; audit export needs conditional writes (If-None-Match)", "Nothing was saved."]);
  });
});
