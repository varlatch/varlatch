// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalTargets } from "@varlatch/protocol";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SKILL_FILES } from "../src/agents/skillFiles.generated.js";

/**
 * `varlatch request` end to end (ADR-0043 Decision 6): a real
 * `varlatch run --agent-safe` (Broker, Capability, exercise against a fake
 * Varlatch server) whose Agent sends requests with `varlatch request` to an
 * HTTPS destination with its own certificate. It proves that the request
 * reaches the destination over TLS, that the Secret is substituted exactly
 * at its targets, and that the response is scrubbed before the Agent sees
 * it. Negative controls, each on the same destination:
 *
 * - a client that tunnels HTTPS with CONNECT (curl, fetch, SDKs) gets the
 *   Broker's 502 and reaches nothing;
 * - a Placeholder outside every target is never substituted: in a header
 *   that is not a target the Broker refuses the request (403), and in a
 *   surface with no targets (the query here) it is forwarded unchanged and
 *   reported; nothing is exercised for either;
 * - a response to a request that carried no Secret is relayed unscrubbed
 *   (the stated scope: scrubbing covers the request that used the value);
 * - the destination's own records show the plaintext it received and sent,
 *   which is what substitution and scrubbing changed.
 */

const CANARY = "sk_live_request_canary_7f3e21";

const dir = mkdtempSync(join(tmpdir(), "varlatch-request-e2e-"));
const bundle = join(dir, "varlatch.cjs");
const repo = join(dir, "repo");
let api: http.Server;
let origin = "";
let upstream: https.Server;
let upstreamPort = 0;
const exercises: { item: string; target: string }[][] = [];

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
  sent: string;
}
const seen: Seen[] = [];

const ENV_PATH = "/v1/organizations/acme/projects/web/environments/development";

function answerApi(req: http.IncomingMessage, res: http.ServerResponse): void {
  let raw = "";
  req.on("data", (d: Buffer) => (raw += d.toString()));
  req.on("end", () => {
    const url = (req.url ?? "").replace(/^https?:\/\/[^/]+/, "");
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    const json = (status: number, payload?: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(payload === undefined ? "" : JSON.stringify(payload));
    };
    if (url === "/v1/meta") return json(200, { serverVersion: "0.14.0", capabilities: ["capabilities.targets"] });
    if (url.startsWith(`${ENV_PATH}/effective-configuration`)) {
      return json(200, {
        environmentId: "env_1",
        items: [{ name: "STRIPE_KEY", sensitive: true, source: "self", value: null }],
        manifest: { manifestVersion: 1, projectId: "prj_1", environment: { id: "env_1", rootId: "env_1", parentId: null, tier: "development", expiresAt: null }, contract: null, items: [] },
      });
    }
    if (url === "/v1/organizations/acme/identities") return json(200, { items: [{ id: "idn_agent", kind: "agent", name: "coder" }] });
    const targets = { STRIPE_KEY: ["header:authorization", "json:/key"] };
    if (url === `${ENV_PATH}/capabilities` && req.method === "POST") {
      const items = body.items as string[];
      return json(201, {
        id: "cap_1",
        secret: "capsecret",
        agentIdentityId: "idn_agent",
        environmentId: "env_1",
        items,
        destinations: body.destinations,
        targets: canonicalTargets(items, body.targets as Record<string, string[]>),
        runId: body.runId,
        expiresAt: "2026-10-01T00:00:00.000Z",
        preflight: "ok",
      });
    }
    if (url === `${ENV_PATH}/capabilities/cap_1/exercises` && req.method === "POST") {
      exercises.push(body.placements as { item: string; target: string }[]);
      return json(200, {
        items: [{ name: "STRIPE_KEY", versionId: "ver_1", value: CANARY }],
        withheld: [],
        targets: canonicalTargets(["STRIPE_KEY"], targets),
      });
    }
    if (req.method === "DELETE") return json(204);
    json(404, { error: { code: "NOT_FOUND", message: url, requestId: "r" } });
  });
}

/** The destination: records what it received and what it sent back, and echoes what carries a value. */
function answerUpstream(req: http.IncomingMessage, res: http.ServerResponse): void {
  let body = "";
  req.on("data", (d: Buffer) => (body += d.toString()));
  req.on("end", () => {
    const url = req.url ?? "";
    let sent: string;
    if (url.startsWith("/leak")) sent = JSON.stringify({ leaked: CANARY });
    else if (url.startsWith("/stray")) sent = JSON.stringify({ url, xOther: req.headers["x-other"] ?? null });
    else sent = JSON.stringify({ auth: req.headers.authorization ?? null, echo: body });
    seen.push({ method: req.method ?? "", url, headers: req.headers, body, sent });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(sent);
  });
}

/**
 * The Agent. It records its Placeholder, then runs each probe and writes
 * everything it saw to OUT; only what the Agent receives is recorded.
 */
const AGENT = `
const { spawnSync } = require("child_process");
const fs = require("fs");
const net = require("net");
const e = process.env;
const ph = e.STRIPE_KEY;
const dest = "127.0.0.1:" + e.UPSTREAM_PORT;
const record = { placeholder: ph, probes: {} };
function request(name, args, env = e) {
  const r = spawnSync(process.execPath, [e.CLI_BUNDLE, "request", ...args], { env, encoding: "utf8", timeout: 20000 });
  record.probes[name] = { code: r.status, stdout: r.stdout, stderr: r.stderr };
}
request("json", ["-X", "POST", "-H", "Authorization: Bearer " + ph, "--json", JSON.stringify({ key: ph, note: "keep" }), "-i", "https://" + dest + "/charges"]);
fs.writeFileSync(e.BODY_FILE, JSON.stringify({ key: ph }));
request("output", ["-X", "PUT", "-H", "Content-Type: application/json", "--data", "@" + e.BODY_FILE, "-o", e.OUTPUT_FILE, "https://" + dest + "/put"]);
record.outputFile = fs.existsSync(e.OUTPUT_FILE) ? fs.readFileSync(e.OUTPUT_FILE, "utf8") : null;
request("strayHeader", ["-H", "X-Other: " + ph, "https://" + dest + "/stray-header"]);
request("strayQuery", ["https://" + dest + "/stray-query?note=" + ph]);
request("leak", ["https://" + dest + "/leak"]);
request("plainHttp", ["-H", "Authorization: Bearer " + ph, "http://" + dest + "/plain"]);
const outside = { ...e };
delete outside.VARLATCH_AGENT_RUN;
request("outside", ["https://" + dest + "/outside"], outside);
// The documented request example, through a shell: double quotes expand $STRIPE_KEY to the Placeholder;
// the same command in single quotes (the negative control) sends the literal text.
for (const [name, command] of [["docDouble", e.DOC_DOUBLE], ["docSingle", e.DOC_SINGLE]]) {
  const r = spawnSync("sh", ["-c", command], { env: e, encoding: "utf8", timeout: 20000 });
  record.probes[name] = { code: r.status, stdout: r.stdout, stderr: r.stderr };
}
// A CONNECT tunnel, as curl, fetch, and most SDKs open for HTTPS through a proxy.
const proxy = new URL(e.HTTPS_PROXY);
const auth = Buffer.from(decodeURIComponent(proxy.username) + ":" + decodeURIComponent(proxy.password)).toString("base64");
const socket = net.connect(Number(proxy.port), proxy.hostname, () => {
  socket.write("CONNECT " + dest + " HTTP/1.1\\r\\nHost: " + dest + "\\r\\nProxy-Authorization: Basic " + auth + "\\r\\n\\r\\n");
});
let connectReply = "";
socket.on("data", (d) => (connectReply += d));
socket.on("close", () => {
  record.connect = connectReply;
  fs.writeFileSync(e.OUT, JSON.stringify(record));
});
`;

interface Probe {
  code: number | null;
  stdout: string;
  stderr: string;
}
interface Record {
  placeholder: string;
  probes: { [name: string]: Probe };
  outputFile: string | null;
  connect: string;
}

let outer: { code: number | null; output: string };
let record: Record;

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
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
    { stdio: "ignore" },
  );
  upstream = https.createServer({ key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) }, answerUpstream);
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  upstreamPort = (upstream.address() as AddressInfo).port;
  api = http.createServer(answerApi);
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "web"\nserver = "${origin}"\ndefault_environment = "development"\n`);
  writeFileSync(join(dir, "agent.cjs"), AGENT);
  // `varlatch` on PATH, so the documented command runs as written.
  mkdirSync(join(dir, "bin"));
  writeFileSync(join(dir, "bin", "varlatch"), `#!/bin/sh\nexec "${process.execPath}" "${bundle}" "$@"\n`, { mode: 0o755 });
  const documented = /^(varlatch --assisted request -X POST -H "Authorization: Bearer \$STRIPE_KEY" .*) https:\/\/api\.stripe\.com\/v1\/charges$/m.exec(SKILL_FILES["references/agent-run.md"] as string)?.[1];
  if (!documented) throw new Error("the documented request example is not in references/agent-run.md");

  const out = join(dir, "record.json");
  const args = [
    bundle, "run", "--agent-safe", "--agent", "coder",
    "--allow-host", `127.0.0.1:${upstreamPort}`,
    "--target", "STRIPE_KEY=header:authorization", "--target", "STRIPE_KEY=json:/key",
    "--", process.execPath, join(dir, "agent.cjs"),
  ];
  const env = {
    PATH: `${join(dir, "bin")}:${process.env.PATH}`,
    DOC_DOUBLE: `${documented} https://127.0.0.1:${upstreamPort}/doc-double`,
    DOC_SINGLE: `${documented.replace('"Authorization: Bearer $STRIPE_KEY"', "'Authorization: Bearer $STRIPE_KEY'")} https://127.0.0.1:${upstreamPort}/doc-single`,
    HOME: dir,
    VARLATCH_CONFIG_DIR: join(dir, "config"),
    VARLATCH_TOKEN: "vlt_operator",
    VARLATCH_BROKER_CREDENTIAL: "vlt_brk_test",
    VARLATCH_ASSISTED: "0",
    // The Broker originates TLS and must trust the destination's certificate.
    NODE_EXTRA_CA_CERTS: join(dir, "cert.pem"),
    CLI_BUNDLE: bundle,
    UPSTREAM_PORT: String(upstreamPort),
    OUT: out,
    BODY_FILE: join(dir, "body.json"),
    OUTPUT_FILE: join(dir, "response.json"),
  };
  outer = await new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: repo, env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (d: Buffer) => (output += d.toString()));
    child.stderr.on("data", (d: Buffer) => (output += d.toString()));
    child.on("close", (code) => resolve({ code, output }));
  });
  record = existsSync(out) ? (JSON.parse(readFileSync(out, "utf8")) as Record) : ({ probes: {} } as Record);
}, 120_000);

afterAll(async () => {
  await new Promise((resolve) => upstream?.close(resolve));
  await new Promise((resolve) => api?.close(resolve));
  rmSync(dir, { recursive: true, force: true });
});

const at = (path: string) => seen.filter((s) => s.url.startsWith(path));

describe("varlatch request through the Broker of an agent-safe run", () => {
  it("the run completes, and the Agent holds only a Placeholder", () => {
    expect(outer.code, outer.output).toBe(0);
    expect(record.placeholder).toMatch(/^vlch_ph_v1_[0-9a-f]+$/);
  });

  it("reaches the HTTPS destination with the Secret substituted exactly at its targets", () => {
    const probe = record.probes.json!;
    expect(probe.code, probe.stderr).toBe(0);
    const [got] = at("/charges");
    expect(got).toBeDefined();
    expect(got!.method).toBe("POST");
    expect(got!.headers.authorization).toBe(`Bearer ${CANARY}`);
    expect(got!.body).toBe(JSON.stringify({ key: CANARY, note: "keep" }));
    expect(got!.headers["content-type"]).toBe("application/json");
    expect(got!.headers.host).toBe(`127.0.0.1:${upstreamPort}`);
    expect(got!.headers["proxy-authorization"]).toBeUndefined();
    expect(exercises[0]).toEqual([
      { item: "STRIPE_KEY", target: "header:authorization" },
      { item: "STRIPE_KEY", target: "json:/key" },
    ]);
  });

  it("scrubs the response: the destination sent the plaintext, the Agent sees its Placeholder", () => {
    const [got] = at("/charges");
    // The control: what the destination actually sent carries the Secret, raw and JSON-escaped.
    expect(got!.sent).toContain(CANARY);
    const probe = record.probes.json!;
    expect(probe.stdout).toMatch(/^HTTP\/1\.1 200 OK\r\n/);
    expect(probe.stdout).not.toContain(CANARY);
    const body = JSON.parse(probe.stdout.slice(probe.stdout.indexOf("\r\n\r\n") + 4)) as { auth: string; echo: string };
    expect(body.auth).toBe(`Bearer ${record.placeholder}`);
    expect(JSON.parse(body.echo)).toEqual({ key: record.placeholder, note: "keep" });
  });

  it("--data @file and -o: substituted in the body, the response written scrubbed to the file", () => {
    expect(record.probes.output!.code, record.probes.output!.stderr).toBe(0);
    expect(record.probes.output!.stdout).toBe("");
    const [got] = at("/put");
    expect(got!.method).toBe("PUT");
    expect(got!.body).toBe(JSON.stringify({ key: CANARY }));
    expect(got!.sent).toContain(CANARY);
    expect(record.outputFile).not.toBeNull();
    expect(record.outputFile).not.toContain(CANARY);
    expect(JSON.parse(JSON.parse(record.outputFile!).echo)).toEqual({ key: record.placeholder });
  });

  it("negative control: a Placeholder in a header that is not a target is refused (403), reaching nothing", () => {
    const probe = record.probes.strayHeader!;
    expect(probe.code).toBe(1);
    expect(probe.stderr).toMatch(/varlatch-broker: STRIPE_KEY: placeholder at header "x-other", which is not a target/);
    expect(probe.stderr).toMatch(/the Broker refused the request \(403\)/);
    expect(at("/stray-header")).toEqual([]);
  });

  it("negative control: a Placeholder in a surface without targets is forwarded unchanged and reported; nothing is exercised", () => {
    expect(record.probes.strayQuery!.code).toBe(0);
    const [got] = at("/stray-query");
    expect(got!.url).toBe(`/stray-query?note=${record.placeholder}`);
    expect(outer.output).toMatch(/STRIPE_KEY placeholder forwarded unchanged in the query/);
    // Three exercises: the JSON request, the --data @file request, and the documented example; none for any stray.
    expect(exercises).toHaveLength(3);
  });

  it("negative control (stated scope): a response to a request that carried no Secret is relayed unscrubbed", () => {
    expect(at("/leak")[0]!.sent).toContain(CANARY);
    expect(record.probes.leak!.code).toBe(0);
    expect(record.probes.leak!.stdout).toContain(CANARY);
  });

  it("negative control: a CONNECT tunnel, as curl and fetch open, gets the Broker's 502 naming varlatch request, and reaches nothing", () => {
    expect(record.connect).toMatch(/^HTTP\/1\.1 502 /);
    expect(record.connect).toMatch(/Send the request with varlatch request/);
    expect(seen.filter((s) => s.method === "CONNECT")).toEqual([]);
  });

  it("a request the Broker refuses (substitution over plain HTTP) exits 1 with its reason on stderr, and reaches nothing", () => {
    const probe = record.probes.plainHttp!;
    expect(probe.code).toBe(1);
    expect(probe.stdout).toBe("");
    expect(probe.stderr).toMatch(/varlatch-broker: secret substitution requires an HTTPS destination with verified TLS/);
    expect(probe.stderr).toMatch(/the Broker refused the request \(502\)/);
    expect(at("/plain")).toEqual([]);
  });

  it("the documented request example, run in a shell as written, reaches the API with the real key", () => {
    const probe = record.probes.docDouble!;
    expect(probe.code, probe.stderr).toBe(0);
    const [got] = at("/doc-double");
    expect(got?.headers.authorization).toBe(`Bearer ${CANARY}`);
    expect(probe.stdout).not.toContain(CANARY);
  });

  it("negative control: the same command in single quotes sends the literal $STRIPE_KEY, and nothing is substituted", () => {
    const probe = record.probes.docSingle!;
    const [got] = at("/doc-single");
    expect(got?.headers.authorization).toBe("Bearer $STRIPE_KEY");
    expect(JSON.stringify(got)).not.toContain(CANARY);
    // Exit 0: the destination answered. Whether the call was authenticated is the API's answer, not the CLI's status.
    expect(probe.code).toBe(0);
  });

  it("refuses outside an agent-safe run (64), sending nothing", () => {
    const probe = record.probes.outside!;
    expect(probe.code).toBe(64);
    expect(probe.stderr).toMatch(/VARLATCH_AGENT_RUN is not set/);
    expect(at("/outside")).toEqual([]);
  });

  it("the Secret appears nowhere the Agent or the run printed, except the unscrubbed-scope control", () => {
    for (const [name, probe] of Object.entries(record.probes)) {
      if (name === "leak") continue;
      expect(probe.stdout + probe.stderr, name).not.toContain(CANARY);
    }
    expect(record.connect).not.toContain(CANARY);
    expect(outer.output).not.toContain(CANARY);
  });
});
