// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The answers the Go server must give exactly as this server does
 * (ADR-0059 step 3, varlatchd-core decision 4), from one table both servers
 * run: go/server/httpserver/testdata/known-differences.json. Here each case
 * runs against buildApp; go/server/httpserver/parity_test.go runs the same
 * table against the Go handler.
 */
import { readFileSync } from "node:fs";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { clientAddressResolver, TrustedProxies } from "../src/http/client-address.js";
import { migratedTestDb } from "./helpers/pglite.js";

interface RouteCase {
  method: string;
  path: string;
  credential: "none" | "basic" | "valid" | "invalid";
  status: number;
  code?: string;
  text?: string;
}
const table = JSON.parse(
  readFileSync(new URL("../../../go/server/httpserver/testdata/known-differences.json", import.meta.url), "utf8"),
) as {
  unknownRoutes: RouteCase[];
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

describe("routes the OpenAPI document does not describe", () => {
  it.each(table.unknownRoutes.map((c) => [`${c.method} ${c.path} (${c.credential})`, c] as const))("%s", async (_, c) => {
    const app = buildApp(ctx);
    const res = await app.request(c.path, { method: c.method, headers: authorization(c.credential) });
    expect(res.status).toBe(c.status);
    const body = await res.text();
    if (c.text !== undefined) {
      expect(res.headers.get("Content-Type")).toBe("text/plain; charset=UTF-8");
      expect(body).toBe(c.text);
    } else {
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(JSON.parse(body).error.code).toBe(c.code);
    }
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
  const app = buildApp(ctx, { clientAddress: () => "192.0.2.77" });
  for (let i = 0; i < w.allowed; i++) expect((await app.request(w.path)).status).toBe(200);
  const res = await app.request(w.path);
  expect(res.status).toBe(w.status);
  expect(res.headers.get("Retry-After")).toBe(w.retryAfterAtStart);
  const body = (await res.json()) as { error: { code: string; message: string } };
  expect(body.error.code).toBe(w.code);
  expect(body.error.message).toBe(w.message);
});
