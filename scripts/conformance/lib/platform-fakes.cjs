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
 * header. The repository endpoints take two kinds of credential, as
 * GitHub's do: the suites' fine-grained tokens (a Bearer or token
 * credential starting with "conformance-", the fake's configured tokens)
 * and installation tokens minted here, within their narrowing. Anything
 * else (no Authorization header, an App's JWT, a token the fake did not
 * mint) is refused with 401. Coolify: an application app-conformance (redeploys record what
 * it runs: its values at that time) and a service svc-conformance with
 * compose files. Convex: the variable list and the batch update.
 *
 * GitHub's endpoints are a route table (GITHUB_ROUTES). Beside the
 * repository secrets, a GitHub App's, as GitHub documents them and as
 * services/varlatchd/test/helpers/fake-github-app.ts answers them: the
 * manifest flow's conversion (a code the suite set up hands over an App
 * with a key generated here), GET /app and the installations with the
 * App's JWT (RS256, issued as the client id or the App id, verified
 * against the App's current keys, iat in the past and exp at most ten
 * minutes ahead), installation tokens minted narrowed to repositories and
 * permissions, and the endpoints such a token reads and writes.
 *
 * Control: GET /_state (the platforms' state and every request, without
 * credentials' values), POST /_drift {"resource", "key", "value"} (a
 * Coolify value changed and redeployed behind Varlatch's back: what the
 * resource stores and what it runs), POST /_github {"op", ...} (a GitHub
 * App's side: "manifest-code" {code, app} sets up a code the conversion
 * hands over; "app" {app} registers one directly and answers its private
 * key; "add-key" {appId}, "delete-key" {appId, pem} and "keep-only-key"
 * {appId, pem} change its keys;
 * "install" {appId, account, repos, selection} installs it).
 */
"use strict";
const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");
const crypto = require("node:crypto");

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
  // A GitHub App's side: codes the conversion hands over (code -> app,
  // used once), Apps by id (their public keys), installations by id, and
  // the installation tokens minted.
  codes: {},
  apps: {},
  installations: {},
  tokens: {},
  mints: [],
  nextInstallation: 169698431,
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
  // The manifest flow: the code hands over the App once, with a key made now.
  {
    method: "POST",
    path: /^\/app-manifests\/([^/]+)\/conversions$/,
    handle: (req, res, m) => {
      const code = decodeURIComponent(m[1]);
      const spec = state.codes[code];
      if (!spec || spec.used) return answer(res, 404, { message: "Not Found" }, DATE());
      spec.used = true;
      const key = newKey();
      state.apps[spec.id] = { ...spec, keys: [key.pub] };
      delete state.apps[spec.id].used;
      return answer(res, 201, { ...appView(spec), pem: key.pem, webhook_secret: null, client_secret: "conformance-client-secret" }, DATE());
    },
  },
  {
    method: "GET",
    path: /^\/app$/,
    handle: (req, res) => {
      const got = appFromJwt(req);
      if (!got.app) return answer(res, got.status, got.body, DATE());
      return answer(res, 200, appView(got.app), DATE());
    },
  },
  {
    method: "GET",
    path: /^\/app\/installations$/,
    handle: (req, res) => {
      const got = appFromJwt(req);
      if (!got.app) return answer(res, got.status, got.body, DATE());
      const url = new URL(req.url, "https://api.github.com");
      const perPage = Math.min(Number(url.searchParams.get("per_page") ?? 30), 100);
      const page = Number(url.searchParams.get("page") ?? 1);
      const all = Object.values(state.installations).filter((i) => i.appId === got.app.id);
      return answer(res, 200, all.slice((page - 1) * perPage, page * perPage).map(installationView), DATE());
    },
  },
  {
    method: "GET",
    path: /^\/app\/installations\/(\d+)$/,
    handle: (req, res, m) => {
      const got = appFromJwt(req);
      if (!got.app) return answer(res, got.status, got.body, DATE());
      const i = state.installations[m[1]];
      if (!i || i.appId !== got.app.id) return answer(res, 404, { message: "Not Found" }, DATE());
      return answer(res, 200, installationView(i), DATE());
    },
  },
  {
    method: "POST",
    path: /^\/app\/installations\/(\d+)\/access_tokens$/,
    handle: (req, res, m, body) => {
      const got = appFromJwt(req);
      if (!got.app) return answer(res, got.status, got.body, DATE());
      const i = state.installations[m[1]];
      if (!i || i.appId !== got.app.id) return answer(res, 404, { message: "Not Found" }, DATE());
      let asked;
      try {
        asked = body ? JSON.parse(body) : {};
      } catch {
        return answer(res, 422, { message: "Invalid request" }, DATE());
      }
      const permissions = asked.permissions ?? got.app.permissions;
      for (const [name, level] of Object.entries(permissions)) {
        if (!allows(got.app.permissions[name], level)) return answer(res, 422, { message: "The permissions requested are not granted to this installation." }, DATE());
      }
      let repos = null;
      if (asked.repositories) {
        for (const name of asked.repositories) {
          if (!i.repos.some((r) => r.toLowerCase() === name.toLowerCase())) {
            return answer(res, 422, { message: "There is at least one repository that does not exist or is not accessible to the parent installation." }, DATE());
          }
        }
        repos = asked.repositories.map((n) => n.toLowerCase());
      }
      const token = `ghs_${crypto.randomBytes(18).toString("base64url")}`;
      state.tokens[token] = { installationId: i.id, repos, permissions };
      state.mints.push({ installationId: i.id, repositories: repos, permissions });
      return answer(res, 201, { token, expires_at: new Date(Date.now() + 3600_000).toISOString(), permissions, repository_selection: repos ? "selected" : i.selection }, DATE());
    },
  },
  {
    method: "GET",
    path: /^\/installation\/repositories$/,
    handle: (req, res, m, body, credential) => {
      if (credential.kind !== "installation") return refused(res);
      const i = state.installations[credential.token.installationId];
      const all = i.repos.filter((r) => !credential.token.repos || credential.token.repos.includes(r.toLowerCase()));
      return answer(res, 200, {
        total_count: all.length,
        repository_selection: i.selection,
        repositories: all.map((r) => ({ name: r, full_name: `${i.account.login}/${r}`, owner: { login: i.account.login }, private: true, archived: false })),
      }, DATE());
    },
  },
  {
    method: "GET",
    path: /^\/repos\/([^/]+)\/([^/]+)$/,
    handle: (req, res, m, body, credential) => {
      if (credential.kind !== "installation") return credential.kind === "none" ? refused(res) : answer(res, 404, { message: "Not Found" }, DATE());
      if (!tokenReaches(credential, m[1], m[2], "metadata", "read") && !tokenReaches(credential, m[1], m[2], "secrets", "read")) {
        return answer(res, 404, { message: "Not Found" }, DATE());
      }
      return answer(res, 200, { name: m[2], full_name: `${m[1]}/${m[2]}`, private: true, archived: false }, DATE());
    },
  },
  {
    method: "GET",
    path: /^\/repos\/([^/]+)\/([^/]+)\/actions\/secrets\/public-key$/,
    handle: (req, res, m, body, credential) => {
      if (credential.kind === "none") return refused(res);
      if (!tokenReaches(credential, m[1], m[2], "secrets", "read")) return answer(res, 403, { message: "Resource not accessible by integration" });
      return answer(res, 200, { key_id: "conformance-key", key: PUBLIC_KEY }, credential.expiry);
    },
  },
  {
    method: "PUT",
    path: /^\/repos\/([^/]+)\/([^/]+)\/actions\/secrets\/([^/]+)$/,
    handle: (req, res, m, body, credential) => {
      if (credential.kind === "none") return refused(res);
      if (!tokenReaches(credential, m[1], m[2], "secrets", "write")) return answer(res, 403, { message: "Resource not accessible by integration" });
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
    handle: (req, res, m, body, credential) => {
      if (credential.kind === "none") return refused(res);
      if (!tokenReaches(credential, m[1], m[2], "secrets", "write")) return answer(res, 403, { message: "Resource not accessible by integration" });
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
  const [scheme = "", value = "", ...extra] = (req.headers.authorization || "").split(" ");
  const bearer = extra.length === 0 && (scheme === "Bearer" || scheme === "token");
  // kind: "fine-grained" (a suite's configured token), "installation" (a
  // token minted here: its installation, repositories and permissions), or
  // "none" (no header, a JWT, a token the fake did not mint), refused.
  let kind = "none";
  let token;
  if (bearer && value.startsWith("conformance-")) kind = "fine-grained";
  else if (bearer && value.startsWith("ghs_") && state.tokens[value]) {
    kind = "installation";
    token = state.tokens[value];
  }
  return { scheme, kind, token, expiry: kind === "fine-grained" && value.includes("expiring") ? { "github-authentication-token-expiration": EXPIRES } : {} };
}

// The repository endpoints' refusal for a credential they do not take.
const refused = (res) => answer(res, 401, { message: "Bad credentials" }, DATE());

// An installation token reaches only its installation's account's
// repositories it was narrowed to, with the permission asked.
const LEVELS = ["read", "write", "admin"];
const allows = (granted, needed) => granted !== undefined && LEVELS.indexOf(granted) >= LEVELS.indexOf(needed);
function tokenReaches(credential, owner, repo, permission, level) {
  if (credential.kind === "fine-grained") return true; // a suite's token: the repository's own rules
  if (credential.kind !== "installation") return false;
  const t = credential.token;
  const inst = state.installations[t.installationId];
  if (!inst || inst.account.login.toLowerCase() !== owner.toLowerCase()) return false;
  if (!inst.repos.some((r) => r.toLowerCase() === repo.toLowerCase())) return false;
  if (t.repos && !t.repos.includes(repo.toLowerCase())) return false;
  return allows(t.permissions[permission], level);
}

// The App a request's JWT names, verified as GitHub verifies it, or the
// answer GitHub gives.
function appFromJwt(req) {
  const jwt = (req.headers.authorization || "").match(/^Bearer (.+)$/)?.[1];
  const parts = jwt?.split(".");
  const undecodable = { status: 401, body: { message: "A JSON web token could not be decoded" } };
  if (!parts || parts.length !== 3) return undecodable;
  let header, payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return undecodable;
  }
  if (header.alg !== "RS256") return undecodable;
  const app = Object.values(state.apps).find((a) => a.clientId === payload.iss || String(a.id) === String(payload.iss));
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], "base64url");
  if (!app || !app.keys.some((k) => crypto.verify("RSA-SHA256", signed, crypto.createPublicKey(k), signature))) return undecodable;
  const at = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== "number" || typeof payload.exp !== "number" || payload.iat > at || payload.exp <= at || payload.exp > at + 600) {
    return { status: 401, body: { message: "Bad credentials" } };
  }
  return { app };
}

const appView = (app) => ({ id: app.id, slug: app.slug, client_id: app.clientId, owner: app.owner, name: app.slug, permissions: app.permissions, events: [] });
const installationView = (i) => ({ id: i.id, app_id: i.appId, account: i.account, target_type: i.account.type, repository_selection: i.selection, suspended_at: null });
function newKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { pem: privateKey.export({ type: "pkcs1", format: "pem" }), pub: publicKey.export({ type: "spki", format: "pem" }) };
}
const DATE = () => ({ date: new Date().toUTCString() });

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
        githubApps: Object.fromEntries(Object.values(state.apps).map((a) => [a.id, { slug: a.slug, keys: a.keys.length }])),
        codesUsed: Object.entries(state.codes).filter(([, v]) => v.used).map(([k]) => k),
        mints: state.mints,
      });
    }
    if (req.method === "POST" && req.url === "/_github") {
      let c;
      try {
        c = JSON.parse(body);
      } catch {
        return answer(res, 422, { message: "not JSON" });
      }
      const spec = (a) => ({ id: a.id, slug: a.slug, clientId: a.clientId, owner: a.owner, permissions: a.permissions ?? { secrets: "write", environments: "write", metadata: "read" } });
      if (c.op === "manifest-code") {
        state.codes[c.code] = spec(c.app);
        return answer(res, 200, { code: c.code });
      }
      if (c.op === "app") {
        const key = newKey();
        state.apps[c.app.id] = { ...spec(c.app), keys: [key.pub] };
        return answer(res, 200, { pem: key.pem });
      }
      const app = state.apps[c.appId];
      if (!app) return answer(res, 404, { message: "no such App" });
      if (c.op === "add-key") {
        const key = newKey();
        app.keys.push(key.pub);
        return answer(res, 200, { pem: key.pem });
      }
      if (c.op === "delete-key") {
        const der = crypto.createPublicKey(c.pem).export({ type: "spki", format: "pem" });
        app.keys = app.keys.filter((k) => k !== der);
        return answer(res, 200, { keys: app.keys.length });
      }
      if (c.op === "keep-only-key") {
        const der = crypto.createPublicKey(c.pem).export({ type: "spki", format: "pem" });
        app.keys = app.keys.filter((k) => k === der);
        return answer(res, 200, { keys: app.keys.length });
      }
      if (c.op === "install") {
        const id = state.nextInstallation++;
        state.installations[id] = { id, appId: app.id, account: c.account, selection: c.selection ?? "selected", repos: c.repos ?? [] };
        return answer(res, 200, { installationId: id });
      }
      return answer(res, 404, { message: "unknown op" });
    }
    if (req.method === "POST" && req.url === "/_drift") {
      const { resource, key, value } = JSON.parse(body);
      const row = (state.coolify[resource] || []).find((r) => r.key === key);
      if (!row) return answer(res, 404, { message: "no such value" });
      // Changed and redeployed outside Varlatch: the application runs it.
      row.value = value;
      if (state.running[resource]) state.running[resource][key] = value;
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
