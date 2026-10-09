#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Spikes S1-S8 for browser reads through the tailnet listener (ADR-0046).
// They test the Tailscale and browser behavior that design rests on, which
// was read in source but never run. README.md in this directory lists what
// each spike needs from the test tailnet; nothing here changes access rules.
//
//   node scripts/spike-tailnet-browser/run.mjs preflight      checks only, joins nothing
//   node scripts/spike-tailnet-browser/run.mjs plan           writes and validates the Compose project, joins nothing
//   node scripts/spike-tailnet-browser/run.mjs selftest       the probe against a fake LocalAPI, no tailnet
//   node scripts/spike-tailnet-browser/run.mjs all            S1-S8
//   node scripts/spike-tailnet-browser/run.mjs s1 s2 s6       a selection
//
// The auth key comes from SPIKE_TS_AUTHKEY_FILE (a file holding it) or
// SPIKE_TS_AUTHKEY; it is never printed or logged. Every result is a line:
// PASS / FAIL (an acceptance check), OBSERVED (a measurement, never a
// verdict), INCONCLUSIVE (the check could not decide), NOT RUN (a
// prerequisite is missing). Only PASS is passing. Results also go to a
// JSONL file. Both spike nodes log out and every container and volume is
// removed at the end, unless SPIKE_KEEP=1.
import { execFile, execFileSync } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import https from "node:https";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { pageHtml } from "./page.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const TS_IMAGE = "tailscale/tailscale:v1.102.3"; // the overlay's pin (infra/compose/docker-compose.tailscale.yml)
const NODE_IMAGE = "node:26-slim"; // varlatchd's base image
const CURL_IMAGE = "curlimages/curl:8.11.1";
const SPIKES = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"];
// varlatchd's user (`useradd -r` in services/varlatchd/Dockerfile); check
// with: docker run --rm --entrypoint id ghcr.io/varlatch/varlatchd:<v> -u
const PROBE_UID = process.env.SPIKE_PROBE_UID ?? "999";
const MACHINE = process.env.SPIKE_HOSTNAME ?? "varlatch-browser-spike";
const PUBLIC_ORIGIN = "https://spike-dashboard.example";

// The key, if it came by environment: taken out of the environment before
// any child process starts, so none inherits it.
const AUTHKEY_FROM_ENV = process.env.SPIKE_TS_AUTHKEY;
delete process.env.SPIKE_TS_AUTHKEY;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const resultsFile = join(tmpdir(), `varlatch-browser-spike-${stamp}.jsonl`);
const results = [];

function emit(kind, spike, name, detail) {
  const rec = { at: new Date().toISOString(), kind, spike, name, ...(detail === undefined ? {} : { detail }) };
  results.push(rec);
  appendFileSync(resultsFile, JSON.stringify(rec) + "\n");
  const text = detail === undefined ? "" : typeof detail === "string" ? detail : JSON.stringify(detail);
  console.log(`${kind.padEnd(8)} [${spike.toUpperCase()}] ${name}${text ? ` :: ${text.slice(0, 400)}` : ""}`);
}
const expect = (spike, name, ok, detail) => emit(ok ? "PASS" : "FAIL", spike, name, detail);
const observe = (spike, name, detail) => emit("OBSERVED", spike, name, detail);
const notRun = (spike, why) => emit("NOT RUN", spike, why);
const judge = (spike, name, verdict) => emit(verdict.kind, spike, name, verdict.detail);
const verdict = (kind, detail) => ({ kind, ...(detail === undefined ? {} : { detail }) });

/**
 * S5 acceptance for one browser and one page. A reachable endpoint passes
 * only when the browser read a JSON answer naming this machine AND the
 * probe's own record of that request (the entry the answer names) shows the
 * same WhoIs; an unreachable one only when every fetch failed. A page that
 * did not complete is inconclusive, and so is a headless run where every
 * fetch failed, since a permission prompt nobody could answer may explain
 * it. `serverEntries` are the probe's entries for this page's run ID.
 */
function judgeS5(expected, outcome, { headed, localId, serverEntries = [], permissionGranted = false }) {
  if (!outcome.completed) return verdict("INCONCLUSIVE", `the test page did not complete: ${outcome.error ?? "no result"}`);
  const results = outcome.results ?? [];
  if (results.length === 0) return verdict("INCONCLUSIVE", "the page recorded no fetch");
  if (expected === "unreachable") {
    return results.every((r) => !r.ok) ? verdict("PASS", results.map((r) => ({ ms: r.ms, error: r.error }))) : verdict("FAIL", { answered: results.filter((r) => r.ok) });
  }
  const read = results.find((r) => r.ok && r.status === 200 && r.json === true);
  if (read) {
    if (!(read.whois?.ok && read.whois.nodeId === localId)) return verdict("FAIL", { problem: "the browser read an answer that does not name this machine", whois: read.whois });
    const entry = serverEntries.find((e) => e.id === read.id && e.listener === "tailnet-https");
    if (!entry) return verdict("INCONCLUSIVE", { problem: "the browser read an answer the probe has no record of", id: read.id });
    if (entry.whois?.nodeId !== localId) return verdict("FAIL", { problem: "the probe's own WhoIs for that request names another node", whois: entry.whois });
    return verdict("PASS", { pna: read.pna, ms: read.ms, id: entry.id });
  }
  const reached = serverEntries.filter((e) => e.listener === "tailnet-https");
  if (reached.length > 0) {
    return verdict("FAIL", { problem: "the request reached the probe, but the browser did not read the answer", browser: results, server: reached.map((e) => ({ id: e.id, whois: e.whois })) });
  }
  // Headed, or with the local-network permission already granted, no
  // unanswered prompt can explain the failure.
  return headed || permissionGranted
    ? verdict("FAIL", { problem: headed ? "every fetch failed in a headed browser" : "every fetch failed with the local-network permission granted", results })
    : verdict("INCONCLUSIVE", { problem: "every fetch failed headless; a permission prompt may explain it: rerun with SPIKE_HEADED=1", results });
}

/**
 * S5 by hand in Safari. Two independent records must agree: the page's own
 * report of what the browser read (posted to its origin after the fetches,
 * from the Mac), and the probe's record of the request that answer names.
 * A request that arrived without a report is inconclusive: arriving is not
 * completing. `entries` and `reports` are the probe's, `node` is the Mac's
 * MagicDNS short name or node ID, `run` the unique ID of this attempt.
 */
const SAFARI_UA = (ua) => /Version\/[\d.]+.*Safari\//.test(ua ?? "") && !/(Chrome|Chromium|CriOS|FxiOS|EdgiOS|Edg\/|OPR\/|Firefox)/.test(ua ?? "");

function judgeSafari({ entries, reports, node, run, browser = null }) {
  const names = (w) => !!w?.ok && (w.nodeId === node || w.name?.split(".")[0] === node);
  const mine = entries.filter((e) => new URL(e.url ?? "/", "https://x.invalid").searchParams.get("run") === run);
  const answered = mine.filter((e) => e.listener === "tailnet-https");
  const report = reports.find((r) => r.run === run);
  if (!report) {
    return mine.length === 0
      ? verdict("NOT RUN", "nothing arrived from the browser for this run")
      : verdict("INCONCLUSIVE", { problem: "requests arrived, but the browser never reported completing them", arrived: mine.map((e) => ({ listener: e.listener, url: e.url })) });
  }
  if (!names(report.reporter?.whois)) return verdict("INCONCLUSIVE", { problem: "the report did not come from the Mac", reporter: report.reporter?.whois });
  // The step is about Safari: the same page opened in another browser on the Mac proves nothing about it.
  if (browser === "safari" && !SAFARI_UA(report.userAgent)) return verdict("INCONCLUSIVE", { problem: "the report came from a browser other than Safari", userAgent: report.userAgent });
  const read = (report.results ?? []).filter((r) => r.ok && r.status === 200 && r.json === true);
  if (read.length === 0) {
    const browser = (report.results ?? []).map((r) => ({ pna: r.pna, status: r.status, error: r.error }));
    if (answered.length > 0) {
      return verdict("FAIL", { problem: "the request reached the probe, but the browser rejected the response", browser, server: answered.map((e) => ({ id: e.id, whois: e.whois })) });
    }
    if (mine.some((e) => e.listener === "tailnet-https-refused-origin")) return verdict("FAIL", { problem: "the endpoint refused the page's origin", browser });
    if (mine.some((e) => e.listener === "tailnet-https-preflight")) return verdict("FAIL", { problem: "only the preflight arrived; the browser never sent the request", browser });
    return verdict("FAIL", { problem: "the browser reported every fetch failed, and nothing reached the endpoint", browser });
  }
  for (const r of read) {
    const entry = answered.find((e) => e.id === r.id);
    if (entry && names(r.whois) && names(entry.whois) && r.whois.nodeId === entry.whois.nodeId) {
      return verdict("PASS", { id: entry.id, nodeId: entry.whois.nodeId, pna: r.pna, ms: r.ms, userAgent: report.userAgent });
    }
  }
  if (read.every((r) => !answered.some((e) => e.id === r.id))) return verdict("INCONCLUSIVE", { problem: "the browser reported an answer the probe has no record of", read });
  return verdict("FAIL", { problem: "the browser read an answer, but WhoIs did not name the Mac", browser: read.map((r) => r.whois), server: answered.map((e) => e.whois) });
}

/**
 * S8 acceptance. The denied device's failure means something only when the
 * allowed device got an HTTPS answer on the same port (there is a listener
 * and the rule lets someone through) and the denied device still reaches
 * the node on another port (the failure is the rule's, not a broken node).
 */
function judgeS8({ control, denied, deniedPlain, allowedId }) {
  if (!control.ok || control.status !== 200) {
    return verdict("INCONCLUSIVE", { problem: "the allowed device's HTTPS request failed, so the denied device's failure proves nothing", control });
  }
  if (control.whois?.nodeId !== allowedId) return verdict("INCONCLUSIVE", { problem: "the control was answered without naming the allowed device", whois: control.whois });
  if (!deniedPlain.ok) return verdict("INCONCLUSIVE", { problem: "the denied device does not reach the node on tcp:8687 either, so the failure is not shown to be the rule's", deniedPlain });
  if (denied.ok) return verdict("FAIL", { problem: "the denied device was answered on tcp:8688", denied });
  return verdict("PASS", { deniedFailedAfterMs: denied.ms, error: denied.error });
}

async function until(what, test, ms = 180_000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    try {
      const v = await test();
      if (v) return v;
    } catch (err) {
      last = err;
    }
    await sleep(2000);
  }
  throw new Error(`timed out waiting for ${what}${last ? `: ${String(last).slice(0, 200)}` : ""}`);
}

/** One request on its own connection (agent: false), so every request is a new socket peer. */
function request(url, { timeoutMs = 15000, headers = {}, method = "GET" } = {}) {
  const u = new URL(url);
  const mod = u.protocol === "https:" ? https : http;
  return new Promise((done) => {
    const t0 = Date.now();
    const req = mod.request(u, { method, agent: false, headers, timeout: timeoutMs }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => {
        let json = null;
        try {
          json = JSON.parse(body);
        } catch {}
        done({ ok: true, status: res.statusCode, json, ms: Date.now() - t0 });
      });
    });
    req.on("timeout", () => req.destroy(new Error(`timeout after ${timeoutMs} ms`)));
    req.on("error", (err) => done({ ok: false, error: String(err.code ?? err.message ?? err), ms: Date.now() - t0 }));
    req.end();
  });
}

// ---- The auth key: from a file or the environment, never printed. Read once,
// then removed from this process's environment so no child inherits it.
function authKeyPath(scratch) {
  const fromFile = process.env.SPIKE_TS_AUTHKEY_FILE?.replace(/^~/, homedir());
  const fromEnv = AUTHKEY_FROM_ENV;
  if (fromFile) {
    if (!existsSync(fromFile)) throw new Error("SPIKE_TS_AUTHKEY_FILE names a file that does not exist");
    if (statSync(fromFile).mode & 0o077) console.log("warning: the auth key file is readable by group or others; chmod 600 it");
    return { path: fromFile, temporary: false };
  }
  if (fromEnv?.trim()) {
    const path = join(scratch, "authkey");
    writeFileSync(path, `${fromEnv.trim()}\n`, { mode: 0o600 });
    return { path, temporary: true };
  }
  throw new Error("set SPIKE_TS_AUTHKEY_FILE (a file holding the auth key) or SPIKE_TS_AUTHKEY; the key is never printed");
}

// ---- The Compose project: a spike node with the probe in its namespace, a
// second client node with curl behind its SOCKS5 proxy, and a peer on the
// project's own network. JSON is valid Compose YAML; `$$` escapes interpolation.
const BOOT =
  'load() { [ -z "$$(printenv "$$1")" ] && [ -s "$$2" ] && export "$$1=$$(cat "$$2")"; return 0; }; ' +
  "load TS_AUTHKEY /run/secrets/tailscale-authkey; exec /usr/local/bin/containerboot";

function composeProject(scratch) {
  const project = `vlt-browser-spike-${randomBytes(3).toString("hex")}`;
  mkdirSync(join(scratch, "serve"));
  // S6: Serve's TCP forwarding to the tailnet listener's shape, TLS-terminated and plain.
  writeFileSync(
    join(scratch, "serve/serve.json"),
    JSON.stringify({
      TCP: {
        8689: { TCPForward: "127.0.0.1:8687", TerminateTLS: "${TS_CERT_DOMAIN}" },
        8692: { TCPForward: "127.0.0.1:8687" },
      },
    }),
  );
  const tsNode = (hostname, extra) => ({
    image: TS_IMAGE,
    hostname,
    entrypoint: ["sh", "-c", BOOT],
    secrets: ["tailscale-authkey"],
    networks: ["spike"],
    ...extra,
  });
  const compose = {
    name: project,
    services: {
      "server-ts": tsNode(MACHINE, {
        environment: {
          TS_AUTHKEY: "",
          TS_STATE_DIR: "/var/lib/tailscale",
          TS_USERSPACE: "true",
          TS_SOCKET: "/var/run/tailscale/tailscaled.sock",
          TS_SERVE_CONFIG: "/serve/serve.json",
          TS_PERMIT_CERT_UID: "${SPIKE_PERMIT_CERT_UID:-}",
        },
        volumes: ["server-state:/var/lib/tailscale", "server-socket:/var/run/tailscale", "./serve:/serve:ro"],
      }),
      probe: {
        image: NODE_IMAGE,
        network_mode: "service:server-ts",
        user: `${PROBE_UID}:${PROBE_UID}`,
        command: ["node", "/spike/probe.mjs"],
        environment: { SPIKE_ALLOWED_ORIGINS: "${SPIKE_ALLOWED_ORIGINS:-}" },
        volumes: ["server-socket:/var/run/tailscale:ro", `${here}:/spike:ro`],
        depends_on: ["server-ts"],
      },
      "client-ts": tsNode(`${MACHINE}-client`, {
        environment: {
          TS_AUTHKEY: "",
          TS_STATE_DIR: "/var/lib/tailscale",
          TS_USERSPACE: "true",
          TS_SOCKET: "/var/run/tailscale/tailscaled.sock",
          TS_SOCKS5_SERVER: "localhost:1055",
        },
        volumes: ["client-state:/var/lib/tailscale"],
      }),
      "client-curl": {
        image: CURL_IMAGE,
        network_mode: "service:client-ts",
        entrypoint: ["sleep", "infinity"],
        depends_on: ["client-ts"],
      },
      peer: { image: NODE_IMAGE, entrypoint: ["sleep", "infinity"], networks: ["spike"] },
    },
    networks: { spike: {} },
    secrets: { "tailscale-authkey": { file: "${SPIKE_AUTHKEY_PATH:-/dev/null}" } },
    volumes: { "server-state": {}, "server-socket": {}, "client-state": {} },
  };
  writeFileSync(join(scratch, "docker-compose.yml"), JSON.stringify(compose, null, 2));
  return project;
}

const composeEnv = { SPIKE_AUTHKEY_PATH: "/dev/null", SPIKE_PERMIT_CERT_UID: "", SPIKE_ALLOWED_ORIGINS: "" };
let scratchDir;
const dc = (args, opts = {}) =>
  execFileSync("docker", ["compose", ...args], {
    cwd: scratchDir,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, ...composeEnv },
    ...opts,
  }).trim();
const tsStatus = (svc) => JSON.parse(dc(["exec", "-T", svc, "tailscale", "status", "--json"]));
const ctl = (method, path) => JSON.parse(dc(["exec", "-T", "probe", "node", "/spike/probe.mjs", "ctl", method, path]));
// The same without blocking this process, for a swap while requests are in flight.
const ctlAsync = (method, path) =>
  new Promise((done, fail) =>
    execFile(
      "docker",
      ["compose", "exec", "-T", "probe", "node", "/spike/probe.mjs", "ctl", method, path],
      { cwd: scratchDir, env: { ...process.env, ...composeEnv } },
      (err, out) => (err ? fail(err) : done(JSON.parse(out))),
    ),
  );
/** Requests from the client node: the answers that came, and curl's errors for the rest (a partial result, not an exception). */
function curlRun(args) {
  let out = "";
  let error = null;
  try {
    out = dc(["exec", "-T", "client-curl", "curl", "-sS", "--socks5-hostname", "localhost:1055", "-m", "30", "-H", "Connection: close", "-w", "\\n", ...args]);
  } catch (err) {
    out = String(err.stdout ?? "");
    error = String(err.stderr ?? err).trim().split("\n").slice(0, 5).join(" | ");
  }
  const lines = out
    .split("\n")
    .filter((l) => l.startsWith("{"))
    .map((l) => JSON.parse(l));
  return { lines, error };
}

/** One request from the client node, with its outcome and timing; a failure is a result, not an exception. */
function curlOnce(url, timeoutSec) {
  const t0 = Date.now();
  try {
    const out = dc(["exec", "-T", "client-curl", "curl", "-sS", "--socks5-hostname", "localhost:1055", "-m", String(timeoutSec), "-H", "Connection: close", "-w", "\n%{http_code}", url]);
    const lines = out.split("\n");
    const status = Number(lines.at(-1));
    const body = lines.find((l) => l.startsWith("{"));
    return { ok: status > 0, status, json: body ? JSON.parse(body) : null, ms: Date.now() - t0 };
  } catch (err) {
    return { ok: false, error: String(err.stderr ?? err).trim().slice(0, 200), ms: Date.now() - t0 };
  }
}

// ---- Preflight: what this machine and the auth key source allow, joining nothing.
function preflight() {
  const facts = {};
  try {
    facts.docker = execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8" }).trim();
  } catch {
    facts.docker = null;
  }
  try {
    const s = JSON.parse(execFileSync("tailscale", ["status", "--json"], { encoding: "utf8" }));
    facts.tailnet = s.MagicDNSSuffix ?? s.CurrentTailnet?.MagicDNSSuffix ?? null;
    facts.magicDNS = s.CurrentTailnet?.MagicDNSEnabled ?? null;
    facts.httpsCertificates = Array.isArray(s.CertDomains) && s.CertDomains.length > 0;
    facts.thisNode = s.Self?.ID ?? null;
    facts.thisNodeName = s.Self?.DNSName?.replace(/\.$/, "") ?? null;
    facts.peerIPs = Object.values(s.Peer ?? {}).flatMap((p) => p.TailscaleIPs ?? []);
    facts.selfIPs = s.Self?.TailscaleIPs ?? [];
  } catch {
    facts.tailnet = null;
  }
  facts.authKeySource = process.env.SPIKE_TS_AUTHKEY_FILE ? "file" : AUTHKEY_FROM_ENV?.trim() ? "environment" : null;
  try {
    const pw = createRequire(join(root, "apps/web/package.json"))("playwright");
    facts.browsers = Object.fromEntries(
      ["chromium", "firefox", "webkit"].map((b) => {
        try {
          return [b, existsSync(pw[b].executablePath())];
        } catch {
          return [b, false];
        }
      }),
    );
  } catch {
    facts.browsers = null;
  }
  return facts;
}

/** Whether each Playwright browser actually starts here; an executable on disk is not enough. */
async function launchableBrowsers() {
  let pw;
  try {
    pw = createRequire(join(root, "apps/web/package.json"))("playwright");
  } catch {
    return null;
  }
  const out = {};
  for (const b of ["chromium", "firefox", "webkit"]) {
    if (!existsSync(pw[b].executablePath())) {
      out[b] = "not installed";
      continue;
    }
    try {
      const browser = await pw[b].launch();
      await browser.close();
      out[b] = "launches";
    } catch (err) {
      out[b] = /missing dependencies/i.test(String(err)) ? "installed, missing system libraries" : "installed, does not launch";
    }
  }
  return out;
}

function printPreflight(f) {
  const line = (ok, text) => console.log(`${ok ? "ok  " : "MISSING"}  ${text}`);
  line(!!f.docker, `Docker ${f.docker ?? "not reachable"}`);
  line(!!f.tailnet, `this machine on a tailnet: ${f.tailnet ?? "no (tailscale status failed)"}${f.thisNodeName ? ` as ${f.thisNodeName}` : ""}`);
  line(f.magicDNS !== false, `MagicDNS ${f.magicDNS === null ? "unknown" : f.magicDNS ? "on" : "off"}`);
  line(f.httpsCertificates, `HTTPS certificates for the tailnet ${f.httpsCertificates ? "on" : "off or unknown"} (S3-S6, S8)`);
  line(!!f.authKeySource, `auth key from ${f.authKeySource ?? "nowhere: set SPIKE_TS_AUTHKEY_FILE or SPIKE_TS_AUTHKEY"} (not read here)`);
  line(!!f.browsers && Object.values(f.browsers).every((v) => v === true || v === "launches"), `browsers for S5: ${f.browsers ? Object.entries(f.browsers).map(([b, v]) => `${b} ${v === true ? "installed" : v === false ? "missing" : v}`).join(", ") : "Playwright not found"}`);
  line(process.env.SPIKE_S7_WAIT_SECONDS > 0, "S7 needs the spike node shared with a user of another tailnet (SPIKE_S7_WAIT_SECONDS)");
  line(process.env.SPIKE_S8_RULE_APPLIED === "1", "S8 needs the approved rule from README.md applied (SPIKE_S8_RULE_APPLIED=1)");
  line(!!process.env.SPIKE_SAFARI_NODE, "S5 in Safari needs a person at a Mac on the tailnet (SPIKE_SAFARI_NODE, SPIKE_SAFARI_WAIT_SECONDS)");
  if (f.selfIPs?.length) console.log(`         this machine's Tailscale addresses, for the S8 rule: ${f.selfIPs.join(", ")}`);
}

// ---- Setup: both nodes join, the key copy goes, the probe starts.
async function setup(local, { permitCert }) {
  scratchDir = mkdtempSync(join(tmpdir(), "varlatch-browser-spike-"));
  const key = authKeyPath(scratchDir);
  const project = composeProject(scratchDir);
  console.log(`project ${project}; results ${resultsFile}`);
  composeEnv.SPIKE_AUTHKEY_PATH = key.path;
  composeEnv.SPIKE_PERMIT_CERT_UID = permitCert ? PROBE_UID : "";
  dc(["up", "-d", "server-ts", "client-ts"]);
  const server = await until("the spike node to join", () => {
    const s = tsStatus("server-ts");
    return s.BackendState === "Running" && s.Self?.DNSName ? s : null;
  });
  const client = await until("the client node to join", () => {
    const s = tsStatus("client-ts");
    return s.BackendState === "Running" && s.Self?.ID ? s : null;
  });
  // Enrolled nodes keep their state; the key is not needed again.
  composeEnv.SPIKE_AUTHKEY_PATH = "/dev/null";
  if (key.temporary) rmSync(key.path, { force: true });
  const name = server.Self.DNSName.replace(/\.$/, "");
  const ctx = {
    name,
    tailnet: server.MagicDNSSuffix,
    serverId: server.Self.ID,
    serverIPs: server.Self.TailscaleIPs ?? [],
    clientId: client.Self.ID,
    localId: local.thisNode,
    permitCert,
  };
  composeEnv.SPIKE_ALLOWED_ORIGINS = `${PUBLIC_ORIGIN},https://${name}:8690`;
  dc(["up", "-d", "probe", "client-curl", "peer"]);
  await until("the probe", () => ctl("GET", "/status").status?.ok);
  if (ctx.tailnet !== local.tailnet) throw new Error(`the spike node joined ${ctx.tailnet}, this machine is on ${local.tailnet}`);
  console.log(`spike node ${name} (${ctx.serverId}); client node ${ctx.clientId}; this machine ${ctx.localId}`);
  await until(
    `this machine to reach ${name}:8687 (if this never succeeds, the tailnet's access rules or DNS block it; this script does not change them)`,
    async () => (await request(`http://${name}:8687/probe?setup=1`)).json?.whois,
    120_000,
  );
  return ctx;
}

async function recreateServer(ctx, permitCert) {
  composeEnv.SPIKE_PERMIT_CERT_UID = permitCert ? PROBE_UID : "";
  dc(["up", "-d", "--force-recreate", "server-ts", "probe"]);
  await until("the spike node after recreation", () => tsStatus("server-ts").BackendState === "Running");
  await until("the probe after recreation", () => ctl("GET", "/status").status?.ok);
  await until("this machine to reach the recreated node", async () => (await request(`http://${ctx.name}:8687/probe?setup=2`)).json?.whois, 120_000);
  ctx.permitCert = permitCert;
}

// ---- S1: the socket peer and WhoIs, from two nodes, under concurrency.
async function s1(ctx) {
  const a = await request(`http://${ctx.name}:8687/probe?s1=a`);
  const b = curlRun([`http://${ctx.name}:8687/probe?s1=b`]).lines[0];
  if (!a.json || !b) return expect("s1", "both nodes reach the tailnet listener shape", false, { a: a.error, b: !!b });
  observe("s1", "socket peer seen for this machine", `${a.json.remoteAddress}:${a.json.remotePort}`);
  observe("s1", "socket peer seen for the client node", `${b.remoteAddress}:${b.remotePort}`);
  expect("s1", "WhoIs with the port resolves this machine", a.json.whois.ok && a.json.whois.nodeId === ctx.localId, a.json.whois);
  expect("s1", "WhoIs with the port resolves the client node", b.whois.ok && b.whois.nodeId === ctx.clientId, b.whois);
  expect("s1", "WhoIs with port 0 fails (this machine)", !a.json.whoisPort0.ok, a.json.whoisPort0);
  expect("s1", "WhoIs with port 0 fails (client node)", !b.whoisPort0.ok, b.whoisPort0);
  await sleep(1500);
  const log = ctl("GET", "/log");
  const after = (id) => log.find((e) => e.id === id)?.whoisAfterClose;
  expect("s1", "WhoIs fails after the connection closed (this machine)", after(a.json.id)?.ok === false, after(a.json.id));
  expect("s1", "WhoIs fails after the connection closed (client node)", after(b.id)?.ok === false, after(b.id));
  const N = 50;
  const fromA = await Promise.all(Array.from({ length: N }, (_, i) => request(`http://${ctx.name}:8687/probe?s1=pa${i}`)));
  const fromB = curlRun(["--parallel", "--parallel-max", String(N), `http://${ctx.name}:8687/probe?s1=pb[1-${N}]`]);
  // An unanswered request is not a misattributed one: count them apart.
  const answeredA = fromA.filter((r) => r.json?.whois);
  const answeredB = fromB.lines.filter((r) => r.whois);
  const wrongA = answeredA.filter((r) => r.json.whois.nodeId !== ctx.localId).length;
  const wrongB = answeredB.filter((r) => r.whois.nodeId !== ctx.clientId).length;
  const counts = { answeredA: answeredA.length, answeredB: answeredB.length, wrongA, wrongB, errorsA: [...new Set(fromA.filter((r) => !r.json).map((r) => r.error))], errorB: fromB.error };
  observe("s1", `${N} parallel connections from each node`, counts);
  judge(
    "s1",
    `${N} parallel connections from each node each resolve to their own node`,
    wrongA > 0 || wrongB > 0
      ? verdict("FAIL", counts)
      : answeredA.length === N && answeredB.length === N
        ? verdict("PASS", counts)
        : verdict("INCONCLUSIVE", { problem: "not every parallel request was answered; none was misattributed", ...counts }),
  );
}

// ---- S2: a 127.0.0.1 bind still gets tailnet traffic and keeps Compose peers out.
async function s2(ctx) {
  const lo = await request(`http://${ctx.name}:8691/probe?s2=lo`);
  expect("s2", "a tailnet client reaches the 127.0.0.1-bound listener, identified", lo.json?.whois?.nodeId === ctx.localId, lo.json?.whois ?? lo.error);
  const container = dc(["ps", "-q", "server-ts"]);
  const ip = execFileSync("docker", ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container], { encoding: "utf8" }).trim().split(" ")[0];
  const peerGet = (port) =>
    JSON.parse(
      dc([
        "exec",
        "-T",
        "peer",
        "node",
        "-e",
        `require("http").get({host:${JSON.stringify(ip)},port:${port},path:"/probe?s2=peer",timeout:5000},r=>{let b="";r.on("data",d=>b+=d);r.on("end",()=>console.log(JSON.stringify({ok:true,body:JSON.parse(b)})))}).on("error",e=>console.log(JSON.stringify({ok:false,error:String(e.code||e)}))).on("timeout",function(){this.destroy(new Error("timeout"))})`,
      ]),
    );
  const p8691 = peerGet(8691);
  expect("s2", "a Compose-network peer cannot reach the 127.0.0.1-bound listener", !p8691.ok, p8691.ok ? p8691.body : p8691.error);
  const p8687 = peerGet(8687);
  observe("s2", "a Compose-network peer reaching the 0.0.0.0 listener is seen as", p8687.ok ? `${p8687.body.remoteAddress}:${p8687.body.remotePort}` : p8687.error);
  expect("s2", "that peer gets no tailnet identity", p8687.ok && p8687.body.whois.ok === false, p8687.ok ? p8687.body.whois : p8687.error);
}

// ---- S3: certificate access for varlatchd's uid: none by default, cert-only when permitted.
async function s3(ctx) {
  if (ctx.permitCert) await recreateServer(ctx, false);
  const before = ctl("GET", "/status");
  observe("s3", "probe uid", before.uid);
  expect("s3", "without TS_PERMIT_CERT_UID, varlatchd's uid gets no certificate", !before.cert.ok, before.cert);
  const writeBefore = ctl("GET", "/write-check");
  expect("s3", "varlatchd's uid has no LocalAPI write access", writeBefore.status !== 200, writeBefore);
  await recreateServer(ctx, true);
  const after = ctl("GET", "/status");
  expect("s3", "with TS_PERMIT_CERT_UID, it gets the node's certificate pair", after.cert.ok, after.cert);
  if (after.cert.ok) {
    observe("s3", "certificate", { domain: after.cert.domain, notBefore: after.cert.notBefore, notAfter: after.cert.notAfter, issuer: after.cert.issuer, fetchMs: after.cert.ms });
    const again = ctl("GET", "/cert");
    observe("s3", "a second fetch returns the same certificate (cached)", { same: again.serial === after.cert.serial, fetchMs: again.ms });
  }
  const writeAfter = ctl("GET", "/write-check");
  expect("s3", "cert permission grants no write access", writeAfter.status !== 200, writeAfter);
}

// ---- S4: renewal through min_validity, and a TLS context swap under load.
async function s4(ctx) {
  if (!ctx.permitCert) await recreateServer(ctx, true);
  const cur = ctl("GET", "/cert");
  if (!cur.ok) return expect("s4", "a certificate to renew", false, cur);
  if (process.env.SPIKE_S4_FORCE_RENEW === "1") {
    const hours = Math.ceil((Date.parse(cur.notAfter) - Date.now()) / 3_600_000) + 24;
    // While the renewal runs, keep asking: does WhoIs stay available? varlatchd
    // gives WhoIs 3 s before it fails closed.
    let renewing = true;
    const during = [];
    const watcher = (async () => {
      while (renewing) {
        const r = await request(`http://${ctx.name}:8687/probe?s4=renewal`, { timeoutMs: 20000 });
        during.push({ ok: r.ok && r.json?.whois?.ok === true, whoisMs: r.json?.whoisMs ?? null, ms: r.ms, error: r.error });
        await sleep(500);
      }
    })();
    const renewed = await ctlAsync("GET", `/cert?min_validity=${hours}h`).catch((err) => ({ ok: false, error: String(err).slice(0, 200) }));
    renewing = false;
    await watcher;
    expect("s4", "min_validity beyond the remaining lifetime renews the certificate", renewed.ok && renewed.serial !== cur.serial, {
      before: cur.notAfter,
      after: renewed.notAfter,
      fetchMs: renewed.ms,
      error: renewed.error,
    });
    const slow = during.filter((d) => !d.ok || d.whoisMs === null || d.whoisMs > 3000);
    observe("s4", "WhoIs while the renewal ran", {
      samples: during.length,
      renewalMs: renewed.ms,
      maxWhoisMs: Math.max(0, ...during.map((d) => d.whoisMs ?? 0)),
      failed: during.filter((d) => !d.ok).length,
    });
    judge(
      "s4",
      "WhoIs keeps answering within 3 s while a renewal runs",
      during.length === 0 ? verdict("INCONCLUSIVE", "no sample was taken during the renewal") : slow.length === 0 ? verdict("PASS", { samples: during.length }) : verdict("FAIL", { samples: during.length, slow: slow.slice(0, 5) }),
    );
  } else {
    notRun("s4", "forced renewal: set SPIKE_S4_FORCE_RENEW=1 (one Let's Encrypt issuance for the spike node's name)");
  }
  // 20 workers keep requests in flight. The same load runs twice: first
  // without a swap, as a control, then with the swap landing in the middle.
  // Failures in the control mean the load itself fails, and the swap cannot
  // be judged.
  const load = async (swapMidway) => {
    const total = 400;
    let issued = 0;
    const failures = [];
    const whoisMs = [];
    const worker = async () => {
      while (issued < total) {
        const n = ++issued;
        // lean=1: one WhoIs per request, as varlatchd makes, not the probe's three.
        const r = await request(`https://${ctx.name}:8688/probe?lean=1&s4=${swapMidway ? "swap" : "control"}-${n}`);
        if (!r.ok || r.status !== 200) failures.push({ n, error: r.error ?? `HTTP ${r.status}`, ms: r.ms });
        else if (typeof r.json?.whoisMs === "number") whoisMs.push(r.json.whoisMs);
      }
    };
    const running = Promise.all(Array.from({ length: 20 }, worker));
    let swapped = null;
    let issuedAtSwap = null;
    if (swapMidway) {
      await sleep(500);
      issuedAtSwap = issued;
      swapped = await ctlAsync("POST", "/reload-tls").catch((err) => ({ swapped: false, error: String(err).slice(0, 300) }));
    }
    await running;
    const errors = {};
    for (const f of failures) errors[f.error] = (errors[f.error] ?? 0) + 1;
    whoisMs.sort((a, b) => a - b);
    const pct = (q) => (whoisMs.length ? whoisMs[Math.min(whoisMs.length - 1, Math.floor(q * whoisMs.length))] : null);
    return {
      total,
      failures: failures.length,
      errors,
      whoisMs: { p50: pct(0.5), p95: pct(0.95), max: whoisMs.at(-1) ?? null, over3s: whoisMs.filter((m) => m > 3000).length },
      issuedAtSwap,
      swapped: swapped?.swapped ?? null,
      swapError: swapped?.error ?? swapped?.cert?.error ?? null,
    };
  };
  const control = await load(false);
  observe("s4", "load without a swap (control)", control);
  const withSwap = await load(true);
  observe("s4", "load with a swap midway", withSwap);
  judge(
    "s4",
    "swapping the TLS context under load fails no request",
    control.failures > 0
      ? verdict("INCONCLUSIVE", { problem: "the load fails without a swap too, so the swap cannot be judged", control })
      : withSwap.swapped !== true
        ? verdict("INCONCLUSIVE", { problem: "the swap did not happen", swapError: withSwap.swapError })
        : withSwap.failures === 0 && withSwap.issuedAtSwap < withSwap.total
          ? verdict("PASS", { total: withSwap.total, issuedAtSwap: withSwap.issuedAtSwap })
          : verdict("FAIL", withSwap),
  );
}

// ---- S5: browsers calling the endpoint cross-origin, from a public and a ts.net origin.
async function s5(ctx, local) {
  if (!ctx.permitCert) await recreateServer(ctx, true);
  let pw;
  try {
    pw = createRequire(join(root, "apps/web/package.json"))("playwright");
  } catch {
    return notRun("s5", "Playwright is not installed (pnpm install)");
  }
  const headed = process.env.SPIKE_HEADED === "1";
  // Headed, a person may have to answer a permission prompt: give them time.
  const abortMs = headed ? 60000 : 4000;
  const endpoint = `https://${ctx.name}:8688`;
  const taken = new Set([...local.peerIPs, ...local.selfIPs]);
  const blackhole = ["100.88.77.66", "100.99.88.77", "100.77.66.55"].find((ip) => !taken.has(ip));
  // Every page gets its own run ID, carried by its fetches: the probe's
  // entries for it are the server side of the judgement.
  const runId = () => `s5-${randomBytes(6).toString("hex")}`;
  const cases = [
    { origin: "public", expected: "reachable", url: `${PUBLIC_ORIGIN}/`, page: (run) => pageHtml(endpoint, abortMs, { run }) },
    { origin: "ts.net", expected: "reachable", url: `https://${ctx.name}:8690/page`, query: (run) => `?run=${run}&abort_ms=${abortMs}` },
    { origin: "public, name does not resolve", expected: "unreachable", url: `${PUBLIC_ORIGIN}/nxdomain`, page: (run) => pageHtml(`https://no-such-spike-node.${ctx.tailnet}:8688`, 30000, { run }) },
    { origin: "public, address not on the tailnet", expected: "unreachable", url: `${PUBLIC_ORIGIN}/blackhole`, page: (run) => pageHtml(`https://${blackhole}:8688`, 30000, { run }) },
  ];
  for (const type of ["chromium", "firefox", "webkit"]) {
    if (!existsSync(pw[type].executablePath())) {
      notRun("s5", `${type} is not installed (npx playwright install ${type})`);
      continue;
    }
    let browser;
    try {
      browser = await pw[type].launch({ headless: !headed });
    } catch (err) {
      notRun("s5", `${type} does not launch on this machine: ${String(err).split("\n").find((l) => /missing|error/i.test(l))?.trim() ?? String(err).slice(0, 120)}`);
      continue;
    }
    // Chromium asks before a page reaches the local network: once without
    // the permission (a measurement: does it block?), once with it granted,
    // as after a person clicks Allow (judged). Other browsers have no such
    // permission to grant.
    const passes = type === "chromium" ? [{ grant: false }, { grant: true }] : [{ grant: null }];
    try {
      for (const { grant } of passes) {
        for (const c of cases) {
          const run = runId();
          const context = await browser.newContext();
          if (grant) await context.grantPermissions(["local-network-access"]);
          const label = `${type}${grant === true ? " (local-network permission granted)" : grant === false ? " (no local-network permission)" : ""}, ${c.origin} origin`;
          const notes = [];
          if (c.page) await context.route(`${c.url}*`, (route) => route.fulfill({ status: 200, contentType: "text/html", body: c.page(run) }));
          const page = await context.newPage();
          page.on("console", (m) => /private|local network|cors|blocked/i.test(m.text()) && notes.push(m.text().slice(0, 200)));
          let outcome;
          try {
            await page.goto(c.query ? `${c.url}${c.query(run)}` : c.url, { timeout: 30000 });
            await page.waitForFunction(() => window.__spikeDone === true, null, { timeout: abortMs * 2 + 70000 });
            outcome = { completed: true, results: await page.evaluate(() => window.__spike) };
          } catch (err) {
            outcome = { completed: false, error: String(err).slice(0, 200) };
          }
          observe("s5", `${label}: what happened`, { ...outcome, console: notes });
          const serverEntries = ctl("GET", `/log?run=${run}`);
          if (grant === false) {
            // Without the permission only what happened is recorded.
            observe("s5", `${label}: read the endpoint`, (outcome.results ?? []).some((r) => r.ok && r.json === true));
          } else {
            judge(
              "s5",
              `${label}: ${c.expected === "reachable" ? "read an answer naming this machine, matching the probe's record" : "fails"}`,
              judgeS5(c.expected, outcome, { headed, localId: ctx.localId, serverEntries, permissionGranted: grant === true }),
            );
          }
          await context.close();
        }
      }
    } finally {
      await browser.close();
    }
  }
  // Safari, by hand on a Mac on the tailnet (README): Playwright's WebKit is
  // not Safari, and may not launch here at all. The probe judges what arrives.
  const safariNode = process.env.SPIKE_SAFARI_NODE;
  const safariWait = Number(process.env.SPIKE_SAFARI_WAIT_SECONDS ?? 0);
  if (!safariNode || !(safariWait > 0)) {
    notRun("s5", "Safari: by hand on a Mac on the tailnet, see README.md (SPIKE_SAFARI_NODE, SPIKE_SAFARI_WAIT_SECONDS)");
  } else {
    // A fresh run ID: only this attempt's requests and report count.
    const run = runId();
    console.log(`S5 Safari: on ${safariNode}, open https://${ctx.name}:8690/page?run=${run} in Safari within ${safariWait} s and leave it until it shows "reported: true".`);
    const end = Date.now() + safariWait * 1000;
    const state = () => ({ entries: ctl("GET", `/log?run=${run}`), reports: ctl("GET", "/reports"), node: safariNode, run });
    // The browser's report settles it; without one, the deadline does.
    while (Date.now() < end && !ctl("GET", "/reports").some((r) => r.run === run)) await sleep(3000);
    judge("s5", "Safari (by hand), ts.net origin: the browser read an answer naming the Mac, matching the probe's record", judgeSafari({ ...state(), browser: "safari" }));
    notRun("s5", "Safari, public origin: needs the test page on a public HTTPS origin, which needs the owner's approval");
  }
  const preflights = ctl("GET", "/log").filter((e) => e.listener === "tailnet-https-preflight");
  observe("s5", "preflights the probe saw", preflights.map((e) => ({ url: e.url, origin: e.origin, requestPrivateNetwork: e.requestPrivateNetwork })));
}

// ---- S6: Serve's TCP forwarding loses the device.
async function s6(ctx) {
  const tlsTcp = await request(`https://${ctx.name}:8689/probe?s6=tls`);
  expect("s6", "Serve TLS-terminated TCP forwarding carries no tailnet identity", tlsTcp.json?.whois?.ok === false, tlsTcp.json ? { peer: `${tlsTcp.json.remoteAddress}:${tlsTcp.json.remotePort}`, whois: tlsTcp.json.whois } : tlsTcp.error);
  const tcp = await request(`http://${ctx.name}:8692/probe?s6=tcp`);
  expect("s6", "Serve plain TCP forwarding carries no tailnet identity", tcp.json?.whois?.ok === false, tcp.json ? { peer: `${tcp.json.remoteAddress}:${tcp.json.remotePort}`, whois: tcp.json.whois } : tcp.error);
}

// ---- S7: a device of another tailnet, which the spike node is shared with.
async function s7(ctx) {
  const wait = Number(process.env.SPIKE_S7_WAIT_SECONDS ?? 0);
  if (!(wait > 0)) return notRun("s7", "needs the spike node shared with a user of another tailnet; set SPIKE_S7_WAIT_SECONDS and request the printed URL from their device");
  console.log(`S7: from the other tailnet's device, request http://${ctx.serverIPs[0]}:8687/probe?s7=1 within ${wait} s`);
  const end = Date.now() + wait * 1000;
  while (Date.now() < end) {
    const hit = ctl("GET", "/log").find((e) => e.url?.includes("s7=1"));
    if (hit) {
      observe("s7", "WhoIs for the other tailnet's device", hit.whois);
      const suffix = hit.whois.ok ? hit.whois.name.replace(/\.$/, "").split(".").slice(1).join(".") : null;
      return expect("s7", "the tailnet pin refuses it", !hit.whois.ok || suffix !== ctx.tailnet, { suffix, pinned: ctx.tailnet });
    }
    await sleep(2000);
  }
  notRun("s7", "no request from the other tailnet's device arrived");
}

// ---- S8: a device the access rules deny tcp:8688. The rule (README.md)
// lets only this machine use 8688, so the client node is the denied device
// and this machine the allowed control.
async function s8(ctx) {
  if (process.env.SPIKE_S8_RULE_APPLIED !== "1") {
    return notRun("s8", "needs the rule from README.md applied to the test tailnet with the owner's approval; this script never changes access rules");
  }
  if (!ctx.permitCert) await recreateServer(ctx, true);
  const listener = ctl("GET", "/status").listeners?.find((l) => l.port === 8688);
  if (!listener?.ok) return emit("INCONCLUSIVE", "s8", "the spike node has no HTTPS listener on 8688, so nothing can be judged", ctl("GET", "/status").cert);
  const control = await request(`https://${ctx.name}:8688/probe?s8=control`, { timeoutMs: 15000 });
  const controlOutcome = { ok: control.ok, status: control.status, whois: control.json?.whois, error: control.error, ms: control.ms };
  observe("s8", "this machine (allowed) on tcp:8688", controlOutcome);
  const denied = curlOnce(`https://${ctx.name}:8688/probe?s8=denied`, 30);
  observe("s8", "the client node (denied) on tcp:8688", { ok: denied.ok, status: denied.status, error: denied.error, ms: denied.ms });
  const deniedPlain = curlOnce(`http://${ctx.name}:8687/probe?s8=plain`, 15);
  observe("s8", "the client node on tcp:8687", { ok: deniedPlain.ok, status: deniedPlain.status, error: deniedPlain.error, ms: deniedPlain.ms });
  judge("s8", "only the allowed device is answered on tcp:8688", judgeS8({ control: controlOutcome, denied, deniedPlain, allowedId: ctx.localId }));
}

// ---- Selftest: the probe's plumbing against a fake LocalAPI, in a throwaway
// container. It proves the harness, not Tailscale: no tailnet, no key.
const FAKE_LOCALAPI = `
const http = require("http");
const fs = require("fs");
const sock = "/scratch/ts.sock";
try { fs.unlinkSync(sock); } catch {}
http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const json = (status, body) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
  if (url.pathname === "/localapi/v0/whois") {
    const port = Number(url.searchParams.get("addr").split(":").pop());
    return port === 0 ? json(404, { error: "no match" }) : json(200, { Node: { StableID: "nFAKEPEER", Name: "peer.example.ts.net.", Tags: ["tag:test"] }, UserProfile: { LoginName: "tagged-devices" } });
  }
  if (url.pathname === "/localapi/v0/status") return json(200, { BackendState: "Running", Self: { ID: "nFAKESELF", DNSName: "spike.example.ts.net.", TailscaleIPs: ["100.64.0.1"] }, MagicDNSSuffix: "example.ts.net", CertDomains: ["spike.example.ts.net"] });
  if (url.pathname.startsWith("/localapi/v0/cert/")) {
    // Phase two of the selftest: a self-signed pair, key first as Tailscale sends it.
    if (!fs.existsSync("/scratch/pair.pem")) return json(403, { error: "cert access denied" });
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end(fs.readFileSync("/scratch/pair.pem"));
  }
  if (url.pathname === "/localapi/v0/prefs" && req.method === "PATCH") return json(403, { error: "write access denied" });
  json(404, { error: "unknown" });
}).listen(sock, () => fs.chmodSync(sock, 0o666));
`;

/** The acceptance rules on made-up outcomes: what may and may not count as a pass. */
function selftestJudges() {
  const me = { headed: false, localId: "nME" };
  const read = (whois, id = 7) => ({ pna: "0", ok: true, status: 200, json: true, id, ms: 40, whois });
  const failed = { pna: "0", ok: false, json: false, error: "TypeError: Failed to fetch", ms: 30 };
  const server = (id, nodeId) => ({ id, listener: "tailnet-https", url: "/probe?pna=0&run=r", whois: { ok: true, nodeId } });
  const cases = [
    ["S5: a page that did not complete is inconclusive", judgeS5("reachable", { completed: false, error: "net::ERR_NAME_NOT_RESOLVED" }, me), "INCONCLUSIVE"],
    ["S5: a page with no fetch result is inconclusive", judgeS5("reachable", { completed: true, results: [] }, me), "INCONCLUSIVE"],
    ["S5: a JSON read naming this machine, matching the probe's record, passes", judgeS5("reachable", { completed: true, results: [failed, read({ ok: true, nodeId: "nME" })] }, { ...me, serverEntries: [server(7, "nME")] }), "PASS"],
    ["S5: a JSON read the probe has no record of is inconclusive", judgeS5("reachable", { completed: true, results: [read({ ok: true, nodeId: "nME" })] }, me), "INCONCLUSIVE"],
    ["S5: a JSON read whose probe record names another node fails", judgeS5("reachable", { completed: true, results: [read({ ok: true, nodeId: "nME" })] }, { ...me, serverEntries: [server(7, "nOTHER")] }), "FAIL"],
    ["S5: a JSON read naming another node fails", judgeS5("reachable", { completed: true, results: [read({ ok: true, nodeId: "nOTHER" })] }, { ...me, serverEntries: [server(7, "nOTHER")] }), "FAIL"],
    ["S5: a request that reached the probe without the browser reading the answer fails", judgeS5("reachable", { completed: true, results: [failed, failed] }, { ...me, serverEntries: [server(7, "nME")] }), "FAIL"],
    ["S5: every fetch failing headless, nothing reaching the probe, is inconclusive", judgeS5("reachable", { completed: true, results: [failed, failed] }, me), "INCONCLUSIVE"],
    ["S5: every fetch failing headed fails", judgeS5("reachable", { completed: true, results: [failed, failed] }, { ...me, headed: true }), "FAIL"],
    ["S5: every fetch failing with the local-network permission granted fails", judgeS5("reachable", { completed: true, results: [failed, failed] }, { ...me, permissionGranted: true }), "FAIL"],
    ["S5: an unreachable endpoint failing passes", judgeS5("unreachable", { completed: true, results: [failed, failed] }, me), "PASS"],
    ["S5: an unreachable endpoint answering fails", judgeS5("unreachable", { completed: true, results: [read({ ok: true, nodeId: "nME" })] }, me), "FAIL"],
    ["S5: an unreachable case that did not complete is inconclusive", judgeS5("unreachable", { completed: false, error: "timeout" }, me), "INCONCLUSIVE"],
  ];
  const control = { ok: true, status: 200, whois: { ok: true, nodeId: "nME" } };
  const refused = { ok: false, error: "curl: (28) Connection timed out", ms: 30000 };
  const plainOk = { ok: true, status: 200 };
  cases.push(
    ["S8: no answer for the allowed device (no listener, or a rule shutting out everyone) is inconclusive", judgeS8({ control: { ok: false, error: "ECONNREFUSED" }, denied: refused, deniedPlain: plainOk, allowedId: "nME" }), "INCONCLUSIVE"],
    ["S8: an allowed answer without the allowed device's identity is inconclusive", judgeS8({ control: { ...control, whois: { ok: false } }, denied: refused, deniedPlain: plainOk, allowedId: "nME" }), "INCONCLUSIVE"],
    ["S8: a denied device that reaches nothing at all is inconclusive", judgeS8({ control, denied: refused, deniedPlain: { ok: false, error: "timeout" }, allowedId: "nME" }), "INCONCLUSIVE"],
    ["S8: a denied device answered on 8688 fails", judgeS8({ control, denied: { ok: true, status: 200 }, deniedPlain: plainOk, allowedId: "nME" }), "FAIL"],
    ["S8: allowed answered, denied refused, denied reaching 8687 passes", judgeS8({ control, denied: refused, deniedPlain: plainOk, allowedId: "nME" }), "PASS"],
  );
  const mac = (nodeId) => ({ ok: true, nodeId, name: `${nodeId === "nMAC" ? "jeremys-mac-mini" : "other"}.example.ts.net.` });
  const entry = (listener, nodeId, { id = 11, run = "r1" } = {}) => ({ id, listener, url: `/probe?pna=0&run=${run}`, whois: nodeId ? mac(nodeId) : { ok: false } });
  const SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
  const CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
  const report = (results, { reporter = "nMAC", run = "r1", userAgent = SAFARI } = {}) => ({ run, results, userAgent, reporter: { whois: mac(reporter) } });
  const macRead = (nodeId, id = 11) => ({ pna: "0", ok: true, status: 200, json: true, id, whois: mac(nodeId) });
  const rejected = { pna: "0", ok: false, json: false, error: "TypeError: Load failed" };
  const safari = (entries, reports, node = "nMAC") => judgeSafari({ entries, reports, node, run: "r1", browser: "safari" });
  cases.push(
    ["Safari: the browser's report and the probe's record agree on the Mac (node ID): pass", safari([entry("tailnet-https-preflight", "nMAC"), entry("tailnet-https", "nMAC")], [report([macRead("nMAC")])]), "PASS"],
    ["Safari: the same, the Mac named by its MagicDNS name: pass", safari([entry("tailnet-https", "nMAC")], [report([macRead("nMAC")])], "jeremys-mac-mini"), "PASS"],
    ["Safari regression: the request reached the probe but the browser rejected the response: fail", safari([entry("tailnet-https-preflight", "nMAC"), entry("tailnet-https", "nMAC")], [report([rejected, rejected])]), "FAIL"],
    ["Safari: a request that arrived without the browser reporting completion is inconclusive", safari([entry("tailnet-https", "nMAC")], []), "INCONCLUSIVE"],
    ["Safari: a report that did not come from the Mac is inconclusive", safari([entry("tailnet-https", "nMAC")], [report([macRead("nMAC")], { reporter: "nOTHER" })]), "INCONCLUSIVE"],
    ["Safari: a reported answer the probe has no record of is inconclusive", safari([], [report([macRead("nMAC", 99)])]), "INCONCLUSIVE"],
    ["Safari: report and record agree on another node: fail", safari([entry("tailnet-https", "nOTHER")], [report([macRead("nOTHER")])]), "FAIL"],
    ["Safari: only a preflight arriving, the browser reporting failure: fail", safari([entry("tailnet-https-preflight", "nMAC")], [report([rejected])]), "FAIL"],
    ["Safari: a refused origin: fail", safari([entry("tailnet-https-refused-origin", "nMAC")], [report([rejected])]), "FAIL"],
    ["Safari: nothing arriving is not run", safari([], []), "NOT RUN"],
    ["Safari: the page opened in Chrome on the Mac is inconclusive", safari([entry("tailnet-https", "nMAC")], [report([macRead("nMAC")], { userAgent: CHROME })]), "INCONCLUSIVE"],
    ["Safari: another run's requests and report do not count", safari([entry("tailnet-https", "nMAC", { run: "r2" })], [report([macRead("nMAC")], { run: "r2" })]), "NOT RUN"],
  );
  for (const [name, got, want] of cases) expect("selftest", name, got.kind === want, got.kind === want ? undefined : { want, got });
}

/** A free port on 127.0.0.1 for the selftest's browser round trip. */
function freePort() {
  return new Promise((done) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => done(port));
    });
  });
}

async function selftest() {
  selftestJudges();
  const dir = mkdtempSync(join(tmpdir(), "varlatch-browser-spike-selftest-"));
  writeFileSync(join(dir, "fake.cjs"), FAKE_LOCALAPI, { mode: 0o644 });
  // The probe runs as varlatchd's uid and the fake socket is created there:
  // the directory holds nothing but the fake.
  chmodSync(dir, 0o777);
  const name = `vlt-spike-selftest-${randomBytes(3).toString("hex")}`;
  const apiPort = await freePort();
  const pagePort = await freePort();
  const docker = (args) => execFileSync("docker", args, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  const inside = (script) => JSON.parse(docker(["exec", name, "node", "-e", script]));
  const get = (port, path) =>
    `require("http").get({host:"127.0.0.1",port:${port},path:${JSON.stringify(path)}},r=>{let b="";r.on("data",d=>b+=d);r.on("end",()=>console.log(b))}).on("error",e=>console.log(JSON.stringify({error:String(e.code||e)})))`;
  try {
    // SPIKE_SELFTEST=1: the page may point at the published port, and
    // ?nocors=1 makes the endpoint answer without CORS (phase three).
    docker([
      "run", "-d", "--name", name, "--user", `${PROBE_UID}:${PROBE_UID}`,
      "-p", `127.0.0.1:${apiPort}:8688`, "-p", `127.0.0.1:${pagePort}:8690`,
      "-v", `${here}:/spike:ro`, "-v", `${dir}:/scratch`,
      "-e", "SPIKE_TS_SOCKET=/scratch/ts.sock", "-e", "SPIKE_SELFTEST=1",
      "-e", `SPIKE_ALLOWED_ORIGINS=https://allowed.example,https://localhost:${pagePort}`,
      NODE_IMAGE, "sh", "-c", "node /scratch/fake.cjs & sleep 1; exec node /spike/probe.mjs",
    ]);
    await until("the probe in the selftest container", () => inside(get(9099, "/status")).status?.ok, 60_000);
    const first = inside(get(8687, "/probe?selftest=1"));
    expect("selftest", "the probe records the socket peer", first.remoteAddress === "127.0.0.1" && first.remotePort > 0, `${first.remoteAddress}:${first.remotePort}`);
    expect("selftest", "WhoIs with the port reaches the LocalAPI", first.whois.ok && first.whois.nodeId === "nFAKEPEER", first.whois);
    expect("selftest", "WhoIs with port 0 is asked separately", first.whoisPort0.ok === false && first.whoisPort0.status === 404, first.whoisPort0);
    const lo = inside(get(8691, "/probe?selftest=2"));
    expect("selftest", "the 127.0.0.1 listener answers", lo.listener === "loopback", lo.listener);
    await sleep(1000);
    const log = inside(get(9099, "/log"));
    expect("selftest", "WhoIs is asked again after the connection closed", log[0]?.whoisAfterClose !== null, log[0]?.whoisAfterClose);
    // The probe's own ctl path (what the harness reads through docker exec)
    // once cut piped output at 64 KB: read a log well past that and parse it.
    inside(`const http=require("http");let n=0;const go=()=>{if(n++>=250)return console.log("{}");http.get({host:"127.0.0.1",port:8687,path:"/probe?bulk="+n},r=>{r.resume();r.on("end",go)})};go()`);
    const big = docker(["exec", name, "node", "/spike/probe.mjs", "ctl", "GET", "/log"]);
    let bigLog = null;
    try {
      bigLog = JSON.parse(big);
    } catch {}
    expect("selftest", "a log over 64 KB arrives whole through the probe's ctl", big.length > 65536 && Array.isArray(bigLog) && bigLog.length >= 250, { bytes: big.length, entries: bigLog?.length });
    const filtered = JSON.parse(docker(["exec", name, "node", "/spike/probe.mjs", "ctl", "GET", "/log?since=" + (bigLog?.at(-1)?.id ?? 0)]));
    expect("selftest", "the log can be read from an entry on", Array.isArray(filtered) && filtered.length === 0, filtered.length);
    expect("selftest", "each entry records how long WhoIs took", typeof bigLog?.[0]?.whoisMs === "number", bigLog?.[0]?.whoisMs);
    const status = inside(get(9099, "/status"));
    expect("selftest", "without cert permission the probe reports the refusal and starts no HTTPS listener", status.cert.ok === false && status.cert.status === 403 && !status.listeners.some((l) => l.port === 8688), status.cert);
    const write = inside(get(9099, "/write-check"));
    expect("selftest", "the write check reports the LocalAPI's answer", write.status === 403, write);
    expect("selftest", "the probe runs as the configured uid", status.uid === Number(PROBE_UID), status.uid);

    // Phase two: with a certificate, the browser endpoint's CORS and TLS swap.
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-days", "2", "-subj", "/CN=spike.example.ts.net", "-addext", "subjectAltName=DNS:spike.example.ts.net"], { stdio: "ignore" });
    writeFileSync(join(dir, "pair.pem"), execFileSync("cat", [join(dir, "key.pem"), join(dir, "cert.pem")]), { mode: 0o644 });
    docker(["restart", name]);
    await until("the probe with a certificate", () => inside(get(9099, "/status")).listeners?.some((l) => l.port === 8688 && l.ok), 60_000);
    const tls = (opts) =>
      inside(
        `const r=require("https").request({host:"127.0.0.1",port:8688,servername:"spike.example.ts.net",rejectUnauthorized:false,...${JSON.stringify(opts)}},res=>{res.resume();res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,headers:res.headers})))});r.on("error",e=>console.log(JSON.stringify({error:String(e)})));r.end()`,
      );
    const allowed = tls({ path: "/probe", headers: { Origin: "https://allowed.example", Authorization: "Bearer x" } });
    expect("selftest", "an allowed origin gets its exact Access-Control-Allow-Origin", allowed.status === 200 && allowed.headers["access-control-allow-origin"] === "https://allowed.example", allowed);
    const refused = tls({ path: "/probe", headers: { Origin: "https://evil.example" } });
    expect("selftest", "another origin is refused, with no CORS header", refused.status === 403 && !refused.headers["access-control-allow-origin"], refused);
    const preflight = (pna) => tls({ method: "OPTIONS", path: `/probe?pna=${pna}`, headers: { Origin: "https://allowed.example", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization", "Access-Control-Request-Private-Network": "true" } });
    const p1 = preflight(1);
    const p0 = preflight(0);
    expect("selftest", "a preflight with ?pna=1 allows Private Network Access", p1.status === 204 && p1.headers["access-control-allow-private-network"] === "true", p1.headers);
    expect("selftest", "a preflight with ?pna=0 does not", p0.status === 204 && !p0.headers["access-control-allow-private-network"], p0.headers);
    const swap = inside(`require("http").request({host:"127.0.0.1",port:9099,method:"POST",path:"/reload-tls"},r=>{let b="";r.on("data",d=>b+=d);r.on("end",()=>console.log(b))}).end()`);
    expect("selftest", "the TLS context can be swapped", swap.swapped === true, swap);
    const page = inside(`require("https").get({host:"127.0.0.1",port:8690,path:"/page",rejectUnauthorized:false},r=>{let b="";r.on("data",d=>b+=d);r.on("end",()=>console.log(JSON.stringify({status:r.statusCode,endpoint:b.includes("https://spike.example.ts.net:8688")})))})`);
    expect("selftest", "the ts.net test page points at the endpoint", page.status === 200 && page.endpoint, page);

    // Phase three: a real browser (Playwright's Chromium) through page,
    // endpoint and report, the way the Safari step uses them, judged by
    // judgeSafari. The fake LocalAPI names every peer nFAKEPEER.
    let pw = null;
    try {
      pw = createRequire(join(root, "apps/web/package.json"))("playwright");
    } catch {}
    if (!pw || !existsSync(pw.chromium.executablePath())) {
      notRun("selftest", "the browser round trip needs Playwright's Chromium (pnpm install; npx playwright install chromium in apps/web)");
    } else {
      const browser = await pw.chromium.launch();
      try {
        const roundTrip = async (extra) => {
          const run = `selftest-${randomBytes(6).toString("hex")}`;
          const context = await browser.newContext({ ignoreHTTPSErrors: true });
          const tab = await context.newPage();
          await tab.goto(`https://localhost:${pagePort}/page?run=${run}&abort_ms=4000&endpoint=${encodeURIComponent(`https://localhost:${apiPort}`)}${extra}`);
          await tab.waitForFunction(() => window.__spikeDone === true, null, { timeout: 30000 });
          const browserSaw = await tab.evaluate(() => ({ results: window.__spike, reported: window.__spikeReported }));
          await context.close();
          const found = judgeSafari({ entries: inside(get(9099, "/log")), reports: inside(get(9099, "/reports")), node: "nFAKEPEER", run });
          return { browserSaw, verdict: found };
        };
        const good = await roundTrip("");
        expect("selftest", "browser round trip: the page reports what it read, and the judge passes it", good.browserSaw.reported === true && good.verdict.kind === "PASS", good);
        const bad = await roundTrip("&nocors=1");
        expect(
          "selftest",
          "regression: the request reaches the probe, the browser rejects the response, and the judge does not pass it",
          bad.browserSaw.reported === true && bad.browserSaw.results.every((r) => !r.ok) && bad.verdict.kind === "FAIL" && /rejected the response/.test(bad.verdict.detail?.problem ?? ""),
          bad,
        );
      } finally {
        await browser.close();
      }
    }
  } finally {
    try {
      docker(["rm", "-f", name]);
    } catch {}
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---- Main.
const args = process.argv.slice(2);
if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
  console.log("usage: run.mjs preflight | plan | all | s1 [s2 ...]   (see README.md)");
  process.exit(args.length === 0 ? 1 : 0);
}
const local = preflight();
if (args[0] === "preflight") {
  local.browsers = await launchableBrowsers();
  printPreflight(local);
  process.exit(local.docker && local.tailnet ? 0 : 1);
}
if (args[0] === "selftest") {
  try {
    await selftest();
  } catch (err) {
    expect("selftest", "selftest ran to completion", false, String(err).slice(0, 400));
  }
  const failed = results.filter((r) => r.kind === "FAIL").length;
  const unsettled = results.filter((r) => r.kind === "NOT RUN" || r.kind === "INCONCLUSIVE").length;
  console.log(`\nselftest: ${results.filter((r) => r.kind === "PASS").length} passed, ${failed} failed, ${unsettled} not run or inconclusive`);
  process.exit(failed ? 1 : unsettled ? 3 : 0);
}
if (args[0] === "plan") {
  scratchDir = mkdtempSync(join(tmpdir(), "varlatch-browser-spike-plan-"));
  try {
    const project = composeProject(scratchDir);
    dc(["config", "--quiet"]);
    console.log(`Compose project ${project} is valid; nothing was started or joined.`);
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
  process.exit(0);
}
const wanted = args[0] === "all" ? SPIKES : args.map((a) => a.toLowerCase());
const unknown = wanted.filter((s) => !SPIKES.includes(s));
if (unknown.length) {
  console.error(`unknown spike(s): ${unknown.join(", ")}`);
  process.exit(1);
}
if (!local.docker || !local.tailnet) {
  printPreflight(local);
  process.exit(1);
}
const steps = { s1, s2, s3, s4, s5, s6, s7, s8 };
let setupError = null;
try {
  // S3 starts without cert permission; S4, S5 and S8 need the HTTPS listener.
  const ctx = await setup(local, { permitCert: !wanted.includes("s3") && wanted.some((s) => ["s4", "s5", "s8"].includes(s)) });
  for (const s of SPIKES.filter((x) => wanted.includes(x))) {
    try {
      await steps[s](ctx, local);
    } catch (err) {
      expect(s, "spike ran to completion", false, String(err).slice(0, 400));
    }
  }
} catch (err) {
  setupError = err;
  emit("FAIL", "setup", "spike setup", String(err).slice(0, 400));
} finally {
  if (scratchDir && process.env.SPIKE_KEEP !== "1") {
    // Logging out deletes an ephemeral node at once; otherwise Tailscale
    // removes it some time after it goes offline. Say which happened.
    for (const svc of ["server-ts", "client-ts"]) {
      try {
        dc(["exec", "-T", svc, "tailscale", "logout"]);
        console.log(`cleanup: ${svc} logged out`);
      } catch (err) {
        console.log(`cleanup: ${svc} did not log out (${String(err.stderr ?? err).trim().split("\n")[0].slice(0, 160)}); as an ephemeral node it is removed after going offline`);
      }
    }
    try {
      dc(["down", "-v", "--remove-orphans"]);
    } catch {}
    rmSync(scratchDir, { recursive: true, force: true });
  } else if (scratchDir) {
    console.log(`SPIKE_KEEP=1: containers kept. Clean up with: docker compose --project-directory ${scratchDir} exec server-ts tailscale logout; ... down -v`);
  }
}
const count = (k) => results.filter((r) => r.kind === k).length;
const spikesWith = (k) => [...new Set(results.filter((r) => r.kind === k).map((r) => r.spike.toUpperCase()))];
const unsettled = [...new Set([...spikesWith("INCONCLUSIVE"), ...spikesWith("NOT RUN")])];
console.log(
  `\n${count("PASS")} passed, ${count("FAIL")} failed, ${count("INCONCLUSIVE")} inconclusive, ${count("NOT RUN")} not run, ${count("OBSERVED")} observed` +
    (unsettled.length ? `\nnot validated: ${unsettled.join(", ")} (inconclusive or not run is not passing)` : ""),
);
console.log(`results: ${resultsFile}`);
// 0 only when every selected spike ran and passed; 3 when any was inconclusive or did not run.
process.exit(count("FAIL") > 0 || setupError ? 1 : count("NOT RUN") > 0 || count("INCONCLUSIVE") > 0 ? 3 : 0);
