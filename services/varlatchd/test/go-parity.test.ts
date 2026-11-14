// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The answers the Go server must give exactly as this server does
 * (ADR-0059 step 3, varlatchd-core decision 4), from one table both servers
 * run: go/server/httpserver/testdata/known-differences.json. Here each case
 * runs against buildApp (requests from raw targets, through the URL parsing
 * every request gets), Hono's own getPath, and the dashboard's nginx.conf;
 * go/server/httpserver/parity_test.go runs the same table against the Go
 * handler.
 *
 * buildApp is the unwrapped one: these requests are outside the OpenAPI
 * document on purpose (unknown routes, encoded paths, HEAD), which the
 * document check every other test runs (helpers/openapi-check-setup.ts)
 * does not model.
 */
import { readFileSync } from "node:fs";
import { Hono } from "hono";
import { getPath } from "hono/utils/url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { clientAddressResolver, TrustedProxies } from "../src/http/client-address.js";
import { migratedTestDb } from "./helpers/pglite.js";

const { buildApp } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

interface RouteCase {
  method: string;
  target: string;
  credential: "none" | "basic" | "valid" | "invalid";
  status: number;
  expect: "text" | "code" | "meta" | "dashboard";
  code?: string;
  text?: string;
}
const table = JSON.parse(
  readFileSync(new URL("../../../go/server/httpserver/testdata/known-differences.json", import.meta.url), "utf8"),
) as {
  pathVectors: { target: string; hono: string }[];
  nginxVectors: { target: string; nginx: string }[];
  routes: RouteCase[];
  forwardedFor: { peer: string; trusted: string[]; lines: string[]; client: string }[];
  requestWindow: { path: string; allowed: number; status: number; code: string; message: string; retryAfterAtStart: string };
};

let ctx: AppCtx & { close: () => Promise<void> };
let token: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Parity" });
  token = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
});
afterEach(async () => {
  await ctx.close();
});

const authorization = (credential: RouteCase["credential"]): Record<string, string> =>
  credential === "valid"
    ? { Authorization: `Bearer ${token}` }
    : credential === "invalid"
      ? { Authorization: "Bearer vlt_cli_notacredential" }
      : credential === "basic"
        ? { Authorization: "Basic dXNlcjpwYXNz" }
        : {};

describe("the path varlatchd routes on", () => {
  it.each(table.pathVectors.map((v) => [v.target, v] as const))("%s", (_, v) => {
    // As @hono/node-server builds the request URL (the WHATWG parser), then
    // Hono's getPath.
    expect(getPath(new Request(`http://localhost${v.target}`))).toBe(v.hono);
  });
});

// The dashboard's nginx (apps/web/nginx.conf) in front of varlatchd: the
// URI it selects a location with ($uri) is the raw target with every escape
// decoded first, then dot segments resolved and slashes merged
// (ngx_http_parse_complex_uri; nginxVectors are nginx 1.29's own answers).
// It selects an exact location first, else the first regex location that
// matches, else the longest prefix; the location either proxies to
// varlatchd (the request target passed on unchanged), serves the dashboard
// (try_files), or proxies elsewhere (Convex).
const nginxUri = (target: string): string => {
  const raw = target.split("?")[0]!;
  const decoded = raw.replace(/%([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  const segments = decoded.slice(1).split("/");
  const out: string[] = [];
  for (const segment of segments) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") out.pop();
    else out.push(segment);
  }
  const last = segments[segments.length - 1];
  return `/${out.join("/")}${out.length > 0 && (last === "" || last === "." || last === "..") ? "/" : ""}`;
};

type Location = { modifier: "=" | "~" | ""; pattern: string; to: "varlatchd" | "dashboard" | "elsewhere" };
const locations: Location[] = [
  ...readFileSync(new URL("../../../apps/web/nginx.conf", import.meta.url), "utf8").matchAll(/location\s+(?:(=|~)\s+)?(\S+)\s*\{([^}]*)\}/g),
].map((m) => ({
  modifier: (m[1] ?? "") as Location["modifier"],
  pattern: m[2]!,
  to: /proxy_pass http:\/\/varlatchd[:/;]/.test(m[3]!) ? "varlatchd" : /try_files/.test(m[3]!) ? "dashboard" : "elsewhere",
}));

const nginxSends = (target: string): Location["to"] => {
  const uri = nginxUri(target);
  const exact = locations.find((l) => l.modifier === "=" && l.pattern === uri);
  if (exact) return exact.to;
  const regex = locations.find((l) => l.modifier === "~" && new RegExp(l.pattern).test(uri));
  if (regex) return regex.to;
  const prefixes = locations.filter((l) => l.modifier === "" && uri.startsWith(l.pattern)).sort((a, b) => b.pattern.length - a.pattern.length);
  return prefixes[0]?.to ?? "elsewhere";
};

describe("the URI the dashboard's nginx selects a location with", () => {
  it("reads nginx.conf's locations: which proxy to varlatchd and which serve the dashboard", () => {
    expect(locations.filter((l) => l.to === "dashboard").map((l) => `${l.modifier}${l.pattern}`).sort()).toEqual(["/", "=/device"]);
    expect(locations.filter((l) => l.to === "varlatchd").length).toBeGreaterThanOrEqual(4);
  });
  it.each(table.nginxVectors.map((v) => [v.target, v] as const))("%s", (_, v) => {
    expect(nginxUri(v.target)).toBe(v.nginx);
  });
});

describe("routes, as raw request targets", () => {
  it.each(table.routes.map((c) => [`${c.method} ${c.target} (${c.credential})`, c] as const))("%s", async (_, c) => {
    if (c.expect === "dashboard") {
      expect(nginxSends(c.target)).toBe("dashboard");
      return;
    }
    expect(nginxSends(c.target)).toBe("varlatchd");
    const app = buildApp(ctx);
    const res = await app.request(c.target, { method: c.method, headers: authorization(c.credential) });
    expect(res.status).toBe(c.status);
    const body = await res.text();
    if (c.expect === "text") {
      expect(res.headers.get("Content-Type")).toBe("text/plain; charset=UTF-8");
      if (c.method !== "HEAD") expect(body).toBe(c.text);
      return;
    }
    expect(res.headers.get("Content-Type")).toBe("application/json");
    if (c.method === "HEAD") return;
    if (c.expect === "meta") expect(JSON.parse(body).apiMajor).toBe(1);
    else expect(JSON.parse(body).error.code).toBe(c.code);
  });
});

describe("X-Forwarded-For in several header lines", () => {
  it.each(table.forwardedFor.map((c) => [`${c.lines.join(" | ")} from ${c.peer}`, c] as const))("%s", async (_, c) => {
    // As app.ts reads it: c.req.header joins repeated lines with ", ", as
    // Node and the Fetch Headers do, and the resolver walks the result.
    const resolve = clientAddressResolver(() => c.peer, new TrustedProxies(c.trusted.join(",")));
    const probe = new Hono().get("/", (cx) => cx.text(resolve(cx)));
    const headers = new Headers();
    for (const line of c.lines) headers.append("X-Forwarded-For", line);
    const res = await probe.request("/", { headers });
    expect(await res.text()).toBe(c.client);
  });
});

it("the request window refuses the request after the allowed ones, with PERMISSION_DENIED", async () => {
  const w = table.requestWindow;
  // The window's clock (Date.now) held still, so Retry-After is the whole
  // window whatever the requests cost; nothing else is faked.
  vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-11-14T12:00:00Z") });
  try {
    const app = buildApp(ctx, { clientAddress: () => "192.0.2.77" });
    for (let i = 0; i < w.allowed; i++) expect((await app.request(w.path)).status).toBe(200);
    const res = await app.request(w.path);
    expect(res.status).toBe(w.status);
    expect(res.headers.get("Retry-After")).toBe(w.retryAfterAtStart);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe(w.code);
    expect(body.error.message).toBe(w.message);
  } finally {
    vi.useRealTimers();
  }
});
