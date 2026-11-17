// SPDX-License-Identifier: Apache-2.0
/**
 * The sync suite's fake platforms (scripts/conformance/suites/sync.mjs):
 * one HTTPS server that answers as GitHub (api.github.com), a Coolify
 * instance (coolify.conformance.test) and a Convex deployment
 * (convex.conformance.test) answer the Platform Adapters, keeping their
 * state; and a plain HTTP control port on loopback for the suite.
 * Dependency-free (it runs inside the TypeScript targets' varlatchd
 * container too). The target points those host names at it: extra_hosts
 * there, the conformance build's VARLATCH_CONFORMANCE_OUTBOUND_HOSTS for
 * the Go server, and its outbound allow list lets the address through.
 *
 *   node platform-fakes.cjs <https port> <control port> <cert.pem> <key.pem> [<installation dir>]
 *
 * (or its source through node -e, in a container). It exits once the
 * installation directory is gone, and after two hours in any case.
 *
 * GitHub: a public key of 32 fixed bytes (sealed values are stored as
 * sent, never opened); a secret whose name starts with BROKEN fails with
 * 500; a credential containing "expiring" is answered with an expiry
 * header. Coolify: an application app-conformance (redeploys record what
 * it runs: its values at that time) and a service svc-conformance with
 * compose files. Convex: the variable list and the batch update.
 *
 * GitHub's endpoints are a route table (GITHUB_ROUTES) so that a GitHub
 * App's (the app's JWT, its installations, installation tokens) can be
 * added beside the repository secrets.
 *
 * Control: GET /_state (the platforms' state and every request, without
 * credentials' values), POST /_drift {"resource", "key", "value"} (a
 * Coolify value changed behind Varlatch's back).
 */
"use strict";
const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");

const args = process.argv.slice(1).filter((a) => !a.endsWith("platform-fakes.cjs"));
const [httpsPort, controlPort, certFile, keyFile, dir] = args;
const EXPIRES = "2031-01-01 00:00:00 UTC";
const PUBLIC_KEY = Buffer.alloc(32, 0x11).toString("base64");
const APP = "/applications/app-conformance";
const SERVICE = "/services/svc-conformance";
const COMPOSE_RAW = "services:\n  web:\n    image: x\n    environment:\n      PORT: 80\n";
const COMPOSE_GENERATED = "services:\n  web:\n    image: x\n    env_file:\n      - .env\n";

const state = {
  github: {}, // repo -> { name: sealed value }
  coolify: { [APP]: [], [SERVICE]: [] },
  running: { [APP]: {}, [SERVICE]: {} },
  convex: {},
  requests: [],
  next: 1,
};

function answer(res, status, value, extra = {}) {
  res.writeHead(status, { "content-type": "application/json", ...extra });
  res.end(status === 204 ? undefined : JSON.stringify(value));
}

function record(req, body, note) {
  // The credential's kind only, never the credential.
  const auth = (req.headers.authorization || "").split(" ")[0];
  state.requests.push({ at: Date.now(), method: req.method, host: (req.headers.host || "").split(":")[0], path: req.url, auth, ...(note ? { note } : {}), ...(body && !note ? { body } : {}) });
}

// GitHub is a route table, so other kinds of credential can be added
// beside the repository secrets without touching them: a GitHub App's
// endpoints (GET /app with the app's JWT, GET /repos/{owner}/{repo}/installation,
// POST /app/installations/{id}/access_tokens minting an installation token)
// are further entries, and githubCredential is where an installation token
// minted here would be recognised. Each route is { method, path (a regular
// expression over the path, without the query), handle(req, res, match, body, credential) }.
const GITHUB_ROUTES = [
  {
    method: "GET",
    path: /^\/repos\/([^/]+)\/([^/]+)\/actions\/secrets\/public-key$/,
    handle: (req, res, m, body, credential) => answer(res, 200, { key_id: "conformance-key", key: PUBLIC_KEY }, credential.expiry),
  },
  {
    method: "PUT",
    path: /^\/repos\/([^/]+)\/([^/]+)\/actions\/secrets\/([^/]+)$/,
    handle: (req, res, m, body, credential) => {
      const secrets = (state.github[`${m[1]}/${m[2]}`] ??= {});
      const name = decodeURIComponent(m[3]);
      if (name.startsWith("BROKEN")) return answer(res, 500, { message: "boom" });
      const existed = name in secrets;
      try {
        secrets[name] = JSON.parse(body).encrypted_value;
      } catch {
        return answer(res, 422, { message: "Invalid request" });
      }
      return answer(res, existed ? 204 : 201, {}, credential.expiry);
    },
  },
  {
    method: "DELETE",
    path: /^\/repos\/([^/]+)\/([^/]+)\/actions\/secrets\/([^/]+)$/,
    handle: (req, res, m) => {
      const secrets = (state.github[`${m[1]}/${m[2]}`] ??= {});
      const name = decodeURIComponent(m[3]);
      if (!(name in secrets)) return answer(res, 404, { message: "Not Found" });
      delete secrets[name];
      return answer(res, 204, null);
    },
  },
];

// What a request's credential is: its kind (the Authorization scheme) and
// the expiry header GitHub answers it with. A fine-grained token
// containing "expiring" is answered with an expiry header.
function githubCredential(req) {
  const [scheme = "", value = ""] = (req.headers.authorization || "").split(" ");
  return { scheme, expiry: value.includes("expiring") ? { "github-authentication-token-expiration": EXPIRES } : {} };
}

function github(req, res, body) {
  const path = req.url.split("?")[0];
  for (const route of GITHUB_ROUTES) {
    const m = route.method === req.method ? route.path.exec(path) : null;
    if (m) return route.handle(req, res, m, body, githubCredential(req));
  }
  return answer(res, 404, { message: "Not Found" });
}

function coolify(req, res, body) {
  const path = req.url.replace(/^\/api\/v1/, "").split("?")[0];
  if (req.method === "GET" && path === "/version") return answer(res, 200, "4.0.0-beta.430");
  if (req.method === "GET" && path === SERVICE) {
    return answer(res, 200, { uuid: "svc-conformance", name: "Stack", docker_compose_raw: COMPOSE_RAW, docker_compose: COMPOSE_GENERATED, compose_parsing_version: "3" });
  }
  const m = /^(\/(?:applications|services)\/[^/]+)(\/envs(?:\/([^/]+))?|\/start|\/restart)$/.exec(path);
  const rows = m ? state.coolify[m[1]] : undefined;
  if (!m || !rows) return answer(res, 404, { message: "Not found." });
  if (m[2] === "/start" || m[2] === "/restart") {
    state.running[m[1]] = Object.fromEntries(rows.map((r) => [r.key, r.value]));
    return answer(res, 200, { message: "Queued." });
  }
  if (req.method === "GET") return answer(res, 200, rows);
  let sent;
  try {
    sent = body ? JSON.parse(body) : {};
  } catch {
    return answer(res, 422, { message: "Invalid JSON" });
  }
  if (req.method === "POST") {
    const row = { uuid: `env-${state.next++}`, ...sent, is_preview: false };
    rows.push(row);
    return answer(res, 201, { uuid: row.uuid });
  }
  if (req.method === "PATCH") {
    const row = rows.find((r) => r.key === sent.key);
    if (!row) return answer(res, 404, { message: "Not found." });
    Object.assign(row, sent);
    return answer(res, 201, { uuid: row.uuid });
  }
  if (req.method === "DELETE" && m[3]) {
    const i = rows.findIndex((r) => r.uuid === m[3]);
    if (i < 0) return answer(res, 404, { message: "Not found." });
    rows.splice(i, 1);
    return answer(res, 200, { message: "Deleted." });
  }
  return answer(res, 404, { message: "Not found." });
}

function convex(req, res, body) {
  if (req.method === "POST" && req.url === "/api/check_admin_key") return answer(res, 200, { success: true });
  if (req.method === "POST" && req.url === "/api/query") {
    return answer(res, 200, { status: "success", value: Object.entries(state.convex).map(([name, value]) => ({ name, value })) });
  }
  if (req.method === "POST" && req.url === "/api/update_environment_variables") {
    let changes;
    try {
      changes = JSON.parse(body).changes;
    } catch {
      return answer(res, 422, {});
    }
    for (const c of changes) {
      if (c.value === null) delete state.convex[c.name];
      else state.convex[c.name] = c.value;
    }
    return answer(res, 200, {});
  }
  return answer(res, 404, {});
}

const platforms = https.createServer({ cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) }, (req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const host = (req.headers.host || "").split(":")[0];
    // A GitHub secret's sealed value is not kept in the log.
    record(req, body, host === "api.github.com" && req.method === "PUT" ? "sealed value" : undefined);
    if (host === "api.github.com") return github(req, res, body);
    if (host === "coolify.conformance.test") return coolify(req, res, body);
    if (host === "convex.conformance.test") return convex(req, res, body);
    answer(res, 421, { message: "Misdirected Request" });
  });
});

const control = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (req.method === "GET" && req.url === "/_state") {
      const coolifyState = {};
      for (const [k, rows] of Object.entries(state.coolify)) coolifyState[k] = Object.fromEntries(rows.map((r) => [r.key, r.value]));
      return answer(res, 200, {
        github: Object.fromEntries(Object.entries(state.github).map(([repo, secrets]) => [repo, Object.keys(secrets).sort()])),
        coolify: coolifyState, running: state.running, convex: state.convex, requests: state.requests,
      });
    }
    if (req.method === "POST" && req.url === "/_drift") {
      const { resource, key, value } = JSON.parse(body);
      const row = (state.coolify[resource] || []).find((r) => r.key === key);
      if (!row) return answer(res, 404, { message: "no such value" });
      row.value = value;
      return answer(res, 200, { drifted: true });
    }
    answer(res, 404, {});
  });
});

platforms.listen(Number(httpsPort), process.env.PLATFORM_FAKES_HOST || "127.0.0.1");
control.listen(Number(controlPort), "127.0.0.1");

const started = Date.now();
setInterval(() => {
  if ((dir && !fs.existsSync(dir)) || Date.now() - started > 2 * 60 * 60 * 1000) process.exit(0);
}, 5000).unref();
