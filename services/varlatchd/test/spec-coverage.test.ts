// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";

/**
 * Server/spec drift is a build failure (ADR-0018 §5). Every /v1 route the
 * server registers must appear in packages/protocol/openapi.yaml and vice
 * versa — this is what keeps the OpenAPI file the source of truth instead
 * of an aspiration. (The /requirements endpoints once shipped without ever
 * reaching the spec; this test makes that impossible to repeat.)
 */

/**
 * Routes served under /v1 but deliberately outside the public contract.
 * Additions here need a documented reason, not convenience.
 */
const UNSPECCED = new Set([
  // Application Plane token exchange: Convex is explicitly outside the /v1
  // compatibility promise (ADR-0018 §13); external consumers never need it.
  "POST /v1/tokens/convex",
]);

const METHODS = new Set(["get", "post", "put", "patch", "delete"]);

function specOperations(): Set<string> {
  const yaml = readFileSync(
    fileURLToPath(new URL("../../../packages/protocol/openapi.yaml", import.meta.url)),
    "utf8",
  );
  const ops = new Set<string>();
  let currentPath: string | null = null;
  let inPaths = false;
  for (const line of yaml.split("\n")) {
    if (/^paths:/.test(line)) inPaths = true;
    else if (/^\S/.test(line)) inPaths = false;
    if (!inPaths) continue;
    const path = line.match(/^ {2}(\/\S*):$/);
    if (path) {
      // Spec paths are relative to the /v1 server URL and use {param} form.
      currentPath = `/v1${path[1]!.replace(/\{([^}]+)\}/g, ":$1")}`;
      continue;
    }
    const method = line.match(/^ {4}([a-z]+):$/);
    if (method && currentPath && METHODS.has(method[1]!)) {
      ops.add(`${method[1]!.toUpperCase()} ${currentPath}`);
    }
  }
  return ops;
}

function servedOperations(): Set<string> {
  // Route registration never touches the ctx; handlers do, and none run here.
  const ctx = {
    db: { query: async () => ({ rows: [] }) },
    rootKek: generateKey(),
  } as unknown as AppCtx;
  // Every listener: the ordinary one, and the tailnet browser endpoint,
  // which alone serves GET /v1/tailnet/context (ADR-0046).
  const apps = [
    buildApp(ctx),
    buildApp(ctx, {
      resolveTailnetContext: async () => null,
      tailnetBrowser: { host: "varlatch.example.ts.net", port: 8688, origins: ["https://varlatch.example.com"] },
    }),
  ];
  const ops = new Set<string>();
  for (const route of apps.flatMap((app) => app.routes)) {
    const method = route.method.toLowerCase();
    if (!METHODS.has(method)) continue; // middleware registers as ALL
    if (!route.path.startsWith("/v1")) continue;
    ops.add(`${route.method.toUpperCase()} ${route.path}`);
  }
  return ops;
}

describe("OpenAPI route coverage", () => {
  const spec = specOperations();
  const served = servedOperations();

  it("parses a plausible spec (sanity floor)", () => {
    expect(spec.size).toBeGreaterThan(40);
    expect(spec.has("GET /v1/meta")).toBe(true);
  });

  it("every served /v1 operation is in the spec (or explicitly excluded)", () => {
    const missing = [...served].filter((op) => !spec.has(op) && !UNSPECCED.has(op)).sort();
    expect(missing, "served but not in openapi.yaml").toEqual([]);
  });

  it("every spec operation is served", () => {
    const phantom = [...spec].filter((op) => !served.has(op)).sort();
    expect(phantom, "in openapi.yaml but not served").toEqual([]);
  });

  it("exclusions do not rot: everything allowlisted is actually served", () => {
    const stale = [...UNSPECCED].filter((op) => !served.has(op)).sort();
    expect(stale, "allowlisted but no longer served").toEqual([]);
  });
});
