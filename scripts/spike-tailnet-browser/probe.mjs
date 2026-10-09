#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// The spike probe: runs in the spike node's network namespace as varlatchd's
// user, the way varlatchd shares the Tailscale sidecar's namespace. For every
// connection it records the socket peer varlatchd would see and what the
// LocalAPI WhoIs says about it (with the port, with port 0, and again after
// the connection closed). It is not varlatchd: it tests the assumptions
// varlatchd's design rests on, nothing else.
//
// Listeners (all inside the namespace; reachable only over Tailscale or the
// spike's own Compose network):
//   8687  HTTP,  0.0.0.0    the tailnet listener's shape (S1, S2 peer, S6 target)
//   8691  HTTP,  127.0.0.1  the loopback bind under test (S2)
//   8688  HTTPS, 0.0.0.0    the browser endpoint, node certificate, CORS (S3-S5, S8)
//   8690  HTTPS, 0.0.0.0    the S5 test page on the ts.net origin, and /report, where
//                           the page posts what the browser saw (same origin)
//   9099  HTTP,  127.0.0.1  control, for `probe.mjs ctl` via docker exec
//
//   node probe.mjs                 serve
//   node probe.mjs ctl GET /log    ask the running probe (prints JSON)
import http from "node:http";
import https from "node:https";
import { pageHtml } from "./page.mjs";

const SOCKET = process.env.SPIKE_TS_SOCKET ?? "/var/run/tailscale/tailscaled.sock";
const ORIGINS = (process.env.SPIKE_ALLOWED_ORIGINS ?? "").split(",").filter(Boolean);
const CONTROL = 9099;
// The harness's own selftest only: lets a local browser point the page at a
// mapped port and makes the endpoint drop CORS on its answer, so the browser
// rejects a response the probe did send. Never set for a tailnet run.
const SELFTEST = process.env.SPIKE_SELFTEST === "1";
const RUN_ID = /^[A-Za-z0-9-]{8,64}$/;

if (process.argv[2] === "ctl") {
  const [method, path] = process.argv.slice(3);
  const req = http.request({ host: "127.0.0.1", port: CONTROL, method, path }, (res) => {
    let body = "";
    res.on("data", (d) => (body += d));
    res.on("end", () => {
      // exitCode, not exit(): exiting at once cut piped output at 64 KB.
      process.exitCode = res.statusCode === 200 ? 0 : 1;
      process.stdout.write(body);
    });
  });
  req.on("error", (err) => {
    console.error(String(err));
    process.exit(2);
  });
  req.end();
} else {
  await serve();
}

function localApi(method, path, body, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const req = http.request(
      { socketPath: SOCKET, path, method, headers: { Host: "local-tailscaled.sock" }, timeout: timeoutMs },
      (res) => {
        let text = "";
        res.on("data", (d) => (text += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("LocalAPI timeout")));
    req.on("error", (err) => resolve({ status: 0, body: String(err) }));
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const hostPort = (addr, port) => (addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`);

async function whois(addr, port) {
  const res = await localApi("GET", `/localapi/v0/whois?addr=${encodeURIComponent(hostPort(addr, port))}`);
  if (res.status !== 200) return { ok: false, status: res.status, error: res.body.trim().slice(0, 200) };
  try {
    const j = JSON.parse(res.body);
    return { ok: true, nodeId: j.Node?.StableID, name: j.Node?.Name, tags: j.Node?.Tags ?? [], user: j.UserProfile?.LoginName };
  } catch {
    return { ok: false, status: 200, error: "unparseable WhoIs response" };
  }
}

async function status() {
  const res = await localApi("GET", "/localapi/v0/status");
  if (res.status !== 200) return { ok: false, status: res.status, error: res.body.slice(0, 200) };
  const s = JSON.parse(res.body);
  return {
    ok: true,
    backendState: s.BackendState,
    nodeId: s.Self?.ID,
    dnsName: s.Self?.DNSName?.replace(/\.$/, ""),
    tailnet: s.MagicDNSSuffix,
    certDomains: s.CertDomains ?? [],
    tailscaleIPs: s.Self?.TailscaleIPs ?? [],
  };
}

/** The node certificate pair from the LocalAPI, as varlatchd would fetch it (S3, S4). */
async function fetchCert(minValidity) {
  const st = await status();
  if (!st.ok) return { ok: false, error: `LocalAPI status failed (${st.status}): ${st.error}` };
  const domain = st.certDomains?.[0] ?? st.dnsName;
  if (!domain) return { ok: false, error: "no cert domain (are HTTPS certificates enabled for the tailnet?)", backendState: st.backendState };
  const query = `type=pair${minValidity ? `&min_validity=${encodeURIComponent(minValidity)}` : ""}`;
  const t0 = Date.now();
  // An ACME order (first issuance or renewal) takes far longer than other calls.
  const res = await localApi("GET", `/localapi/v0/cert/${encodeURIComponent(domain)}?${query}`, undefined, 180000);
  const ms = Date.now() - t0;
  if (res.status !== 200) return { ok: false, domain, status: res.status, ms, error: res.body.trim().slice(0, 300) };
  const blocks = [...res.body.matchAll(/-----BEGIN ([A-Z ]+)-----[\s\S]+?-----END \1-----/g)];
  const key = blocks.filter((b) => b[1].includes("PRIVATE KEY")).map((b) => b[0]).join("\n");
  const cert = blocks.filter((b) => b[1] === "CERTIFICATE").map((b) => b[0]).join("\n");
  if (!key || !cert) return { ok: false, domain, status: 200, ms, error: "pair without key or certificate" };
  const { X509Certificate } = await import("node:crypto");
  const leaf = new X509Certificate(blocks.find((b) => b[1] === "CERTIFICATE")[0]);
  return { ok: true, domain, ms, key, cert, notBefore: leaf.validFrom, notAfter: leaf.validTo, issuer: leaf.issuer, serial: leaf.serialNumber };
}

async function serve() {
  const log = [];
  const reports = [];
  let nextId = 1;

  async function record(listener, req) {
    const sock = req.socket;
    const addr = sock.remoteAddress ?? "";
    const port = sock.remotePort ?? 0;
    const entry = {
      id: nextId++,
      at: new Date().toISOString(),
      listener,
      method: req.method,
      url: req.url,
      origin: req.headers.origin ?? null,
      requestPrivateNetwork: req.headers["access-control-request-private-network"] ?? null,
      // Headers a client could forge: recorded to show they change nothing.
      forgeable: Object.fromEntries(
        ["x-forwarded-for", "forwarded", "x-real-ip", "tailscale-user-login", "tailscale-user-name"]
          .filter((h) => req.headers[h] !== undefined)
          .map((h) => [h, req.headers[h]]),
      ),
      remoteAddress: addr,
      remotePort: port,
      whoisMs: null,
      whois: null,
      whoisPort0: null,
      whoisAfterClose: null,
    };
    const t0 = Date.now();
    entry.whois = await whois(addr, port);
    entry.whoisMs = Date.now() - t0;
    entry.whoisPort0 = await whois(addr, 0);
    log.push(entry);
    // After close: an entry must not outlive its connection.
    sock.once("close", () => {
      setTimeout(async () => {
        entry.whoisAfterClose = await whois(addr, port);
      }, 250);
    });
    return entry;
  }

  const answer = (res, status, body, headers = {}) => {
    res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers });
    res.end(JSON.stringify(body));
  };

  const plain = (listener) => async (req, res) => {
    const entry = await record(listener, req);
    answer(res, 200, entry);
  };

  // The browser endpoint: exact-origin CORS, preflights answered before
  // anything else, Private Network Access only when the query asks for it.
  const endpoint = async (req, res) => {
    const origin = req.headers.origin;
    const url = new URL(req.url ?? "/", "https://spike.invalid");
    const cors = origin && ORIGINS.includes(origin) ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : {};
    if (origin && !cors["Access-Control-Allow-Origin"]) {
      await record("tailnet-https-refused-origin", req);
      return answer(res, 403, { error: "origin not allowed" }, { Vary: "Origin" });
    }
    if (req.method === "OPTIONS") {
      await record("tailnet-https-preflight", req);
      const pna =
        url.searchParams.get("pna") === "1" && req.headers["access-control-request-private-network"] === "true"
          ? { "Access-Control-Allow-Private-Network": "true" }
          : {};
      res.writeHead(204, {
        ...cors,
        ...pna,
        "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Max-Age": "5",
      });
      return res.end();
    }
    const entry = await record("tailnet-https", req);
    // Selftest: the answer goes out without CORS, so the browser must reject it.
    answer(res, 200, entry, SELFTEST && url.searchParams.get("nocors") === "1" ? {} : cors);
  };

  // The page and its report, on the ts.net origin.
  const pageServer = async (req, res) => {
    const url = new URL(req.url ?? "/", "https://spike.invalid");
    if (url.pathname === "/report" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 65536) return answer(res, 413, { error: "report too large" });
      }
      let parsed;
      try {
        parsed = JSON.parse(body);
      } catch {
        return answer(res, 400, { error: "report is not JSON" });
      }
      if (!RUN_ID.test(parsed.run ?? "") || !Array.isArray(parsed.results)) return answer(res, 400, { error: "report needs a run ID and results" });
      const sock = req.socket;
      reports.push({
        at: new Date().toISOString(),
        run: parsed.run,
        results: parsed.results.slice(0, 10),
        userAgent: String(parsed.userAgent ?? "").slice(0, 300),
        // Who sent the report, by the same WhoIs as everything else.
        reporter: { remoteAddress: sock.remoteAddress, remotePort: sock.remotePort, whois: await whois(sock.remoteAddress ?? "", sock.remotePort ?? 0) },
      });
      res.writeHead(204, { "Cache-Control": "no-store" });
      return res.end();
    }
    const run = url.searchParams.get("run");
    const endpointUrl = SELFTEST && url.searchParams.get("endpoint") ? url.searchParams.get("endpoint") : `https://${cert.domain}:8688`;
    const query = SELFTEST && url.searchParams.get("nocors") === "1" ? "&nocors=1" : "";
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    res.end(pageHtml(endpointUrl, Number(url.searchParams.get("abort_ms")) || 60000, RUN_ID.test(run ?? "") ? { run, report: "/report", query } : { query }));
  };

  const listen = (server, port, host) =>
    new Promise((resolve) => {
      server.once("error", (err) => resolve({ port, host, ok: false, error: String(err) }));
      server.listen(port, host, () => resolve({ port, host, ok: true }));
    });

  const listeners = [];
  listeners.push(await listen(http.createServer(plain("tailnet-plain")), 8687, "0.0.0.0"));
  listeners.push(await listen(http.createServer(plain("loopback")), 8691, "127.0.0.1"));

  // HTTPS needs the node certificate; without cert permission it is absent (S3).
  let cert = await fetchCert();
  const tlsServers = [];
  if (cert.ok) {
    const api = https.createServer({ key: cert.key, cert: cert.cert }, endpoint);
    const page = https.createServer({ key: cert.key, cert: cert.cert }, pageServer);
    tlsServers.push(api, page);
    listeners.push(await listen(api, 8688, "0.0.0.0"));
    listeners.push(await listen(page, 8690, "0.0.0.0"));
  }
  const certSummary = (c) => (c.ok ? { ok: true, domain: c.domain, ms: c.ms, notBefore: c.notBefore, notAfter: c.notAfter, issuer: c.issuer, serial: c.serial } : c);

  const control = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://ctl.invalid");
    if (url.pathname === "/log") {
      const run = url.searchParams.get("run");
      const since = Number(url.searchParams.get("since") ?? 0);
      return answer(res, 200, log.filter((e) => e.id > since && (!run || new URL(e.url ?? "/", "https://x.invalid").searchParams.get("run") === run)));
    }
    if (url.pathname === "/reports") return answer(res, 200, reports);
    if (url.pathname === "/status") return answer(res, 200, { status: await status(), listeners, cert: certSummary(cert), uid: process.getuid?.() });
    if (url.pathname === "/cert") return answer(res, 200, certSummary(await fetchCert(url.searchParams.get("min_validity") ?? undefined)));
    if (url.pathname === "/write-check") {
      // A no-op write (empty mask): 200 means this uid has write access.
      const r = await localApi("PATCH", "/localapi/v0/prefs", "{}");
      return answer(res, 200, { status: r.status, body: r.body.trim().slice(0, 200) });
    }
    if (url.pathname === "/reload-tls" && req.method === "POST") {
      const next = await fetchCert(url.searchParams.get("min_validity") ?? undefined);
      if (!next.ok || tlsServers.length === 0) return answer(res, 200, { swapped: false, cert: certSummary(next) });
      for (const s of tlsServers) s.setSecureContext({ key: next.key, cert: next.cert });
      cert = next;
      return answer(res, 200, { swapped: true, cert: certSummary(next) });
    }
    return answer(res, 404, { error: "unknown control path" });
  });
  listeners.push(await listen(control, CONTROL, "127.0.0.1"));
  console.log(JSON.stringify({ probe: "ready", listeners, cert: certSummary(cert) }));
}
