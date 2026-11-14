// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { ALLOWED, checkExchange, matchOperation, specOperations, specPath } from "./helpers/openapi-check.js";

/**
 * The OpenAPI check itself (helpers/openapi-check.ts, ADR-0059 Decision 3):
 * every /v1 response a test produces is validated against the spec by the
 * setup file; these tests keep that check honest.
 */

type Json = Record<string, unknown>;
const spec = parse(readFileSync(specPath(), "utf8")) as Json;

function walk(node: unknown, path: string, visit: (node: Json, path: string) => void): void {
  if (Array.isArray(node)) node.forEach((n, i) => walk(n, `${path}/${i}`, visit));
  else if (node && typeof node === "object") {
    visit(node as Json, path);
    for (const [k, v] of Object.entries(node)) walk(v, `${path}/${k}`, visit);
  }
}

describe("OpenAPI check", () => {
  it("the spec uses 3.1 schemas only: no OpenAPI 3.0 keywords the validator would ignore", () => {
    const found: string[] = [];
    walk(spec, "", (node, path) => {
      // nullable is 3.0; a 3.1 schema says type: [x, "null"]. Boolean
      // exclusiveMinimum/Maximum are 3.0 too.
      if ("nullable" in node && !path.includes("/properties/nullable")) found.push(`${path}: nullable`);
      for (const k of ["exclusiveMinimum", "exclusiveMaximum"]) {
        if (typeof node[k] === "boolean") found.push(`${path}: boolean ${k}`);
      }
    });
    expect(found).toEqual([]);
  });

  it("every operation documents its errors: a default response with the error envelope", () => {
    // Any operation can answer 401, 429 (rate limit), 503 (maintenance) or
    // 500 before its handler runs; the server sends the ApiError envelope.
    const missing: string[] = [];
    for (const [path, item] of Object.entries(spec.paths as Record<string, Json>)) {
      for (const [method, op] of Object.entries(item)) {
        const responses = (op as Json).responses as Json | undefined;
        if (responses && (responses.default as Json | undefined)?.$ref !== "#/components/responses/Error") missing.push(`${method.toUpperCase()} ${path}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("every $ref resolves", () => {
    const broken: string[] = [];
    walk(spec, "", (node, path) => {
      if (typeof node.$ref !== "string") return;
      let target: unknown = spec;
      for (const raw of node.$ref.replace(/^#\//, "").split("/")) {
        target = (target as Json | undefined)?.[raw.replace(/~1/g, "/").replace(/~0/g, "~")];
      }
      if (target === undefined) broken.push(`${path}: ${node.$ref}`);
    });
    expect(broken).toEqual([]);
  });

  it("matches a literal path segment before a parameter", () => {
    const ops = specOperations();
    expect(ops.length).toBeGreaterThan(100);
    // Every operation matches itself with its parameters filled in.
    for (const op of ops) {
      const [method, template] = op.split(" ") as [string, string];
      const concrete = template.replace(/\{[^}]+\}/g, "x1");
      const matched = matchOperation(method, concrete);
      expect(matched && `${matched.method} ${matched.template}`, op).toBeDefined();
    }
    const me = matchOperation("GET", "/v1/me");
    expect(me?.template).toBe("/v1/me");
  });

  it("flags a schema mismatch, a missing body and an undocumented 2xx path", () => {
    const base = {
      method: "GET",
      pathname: "/v1/meta",
      requestContentType: null,
      requestText: null,
      responseContentType: "application/json",
      responseHasBody: true,
    };
    const ok = checkExchange({ ...base, status: 200, responseText: "{}" });
    expect(ok.exchange?.operation).toBe("GET /v1/meta");
    expect(ok.mismatches.map((m) => m.kind)).toContain("response-schema");
    const error = checkExchange({
      ...base,
      pathname: "/v1/organizations",
      status: 500,
      responseText: JSON.stringify({ error: { code: "INTERNAL", message: "Internal error", requestId: "r" } }),
    });
    // GET /v1/organizations documents a default error; the envelope validates.
    expect(error.mismatches).toEqual([]);
    const bare = checkExchange({ ...base, pathname: "/v1/organizations", status: 500, responseText: JSON.stringify({ message: "x" }) });
    expect(bare.mismatches.map((m) => m.kind)).toEqual(["response-schema"]);
    // A 204 where the spec documents a JSON body.
    const empty = checkExchange({ ...base, status: 200, responseHasBody: false, responseText: "" });
    expect(empty.mismatches.map((m) => m.kind)).toEqual(["missing-response-body"]);
    const unknown = checkExchange({ ...base, pathname: "/v1/nowhere", status: 200, responseText: "{}" });
    expect(unknown.mismatches.map((m) => m.kind)).toEqual(["undocumented-operation"]);
    const notFound = checkExchange({ ...base, pathname: "/v1/nowhere", status: 404, responseText: "{}" });
    expect(notFound.mismatches).toEqual([]);
    const outside = checkExchange({ ...base, pathname: "/auth/session", status: 200, responseText: "[]" });
    expect(outside.mismatches).toEqual([]);
  });

  it("allowlisted mismatches name an operation in the spec and carry a reason", () => {
    const ops = new Set(specOperations());
    for (const [key, reason] of ALLOWED) {
      const [, method, template] = key.split(" ");
      expect(ops.has(`${method} ${template}`), key).toBe(true);
      expect(reason.length, key).toBeGreaterThan(20);
    }
  });
});
