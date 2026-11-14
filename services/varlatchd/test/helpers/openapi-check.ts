// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import { parse } from "yaml";

/**
 * Checks /v1 traffic against packages/protocol/openapi.yaml (ADR-0059
 * Decision 3: the document is checked against the TypeScript server).
 *
 * openapi-check-setup.ts wraps every app that buildApp() returns, so every
 * request a test sends through app.request, app.fetch or a real listener
 * passes through checkExchange() here. It checks:
 *
 * - the response status is documented for the operation (or covered by its
 *   default response);
 * - the response's content type is one the spec lists, and a response the
 *   spec gives no content has no body;
 * - a JSON response body validates against the response schema, errors
 *   included (the ApiError envelope);
 * - a request body the server accepted (2xx) validates against the
 *   operation's requestBody schema, and an operation without one received
 *   no body.
 *
 * Paths outside /v1 (auth, enrollment, health, JWKS, install scripts) and
 * the deliberately unspecced Convex token exchange are not checked.
 */

export type MismatchKind =
  | "undocumented-operation"
  | "undocumented-status"
  | "undocumented-response-body"
  | "missing-response-body"
  | "response-content-type"
  | "response-schema"
  | "response-not-json"
  | "undocumented-request-body"
  | "missing-request-body"
  | "request-content-type"
  | "request-schema";

export interface Mismatch {
  kind: MismatchKind;
  /** "METHOD /v1/template" or, for an unmatched path, the concrete path. */
  operation: string;
  status: number;
  detail: string;
}

export interface Exchange {
  operation: string;
  status: number;
}

export type OpenApiCheckMode = "enforce" | "collect" | "off";

/** VARLATCH_OPENAPI_CHECK: enforce (default), collect or off. */
export function openApiCheckMode(): OpenApiCheckMode {
  const v = process.env.VARLATCH_OPENAPI_CHECK;
  if (v === "enforce" || v === "off") return v;
  // TEMPORARY: collect while the spec is brought in line; enforce next.
  return "collect";
}

/** Served under /v1 but outside the contract (spec-coverage.test.ts). */
const UNSPECCED = new Set(["POST /v1/tokens/convex"]);

/**
 * Mismatches that cannot be fixed in the spec, each with its reason, keyed
 * "kind METHOD /v1/template status". Keep it empty unless a reason holds.
 */
export const ALLOWED: ReadonlyMap<string, string> = new Map<string, string>([]);

type Json = Record<string, unknown>;

interface Operation {
  method: string;
  template: string;
  segments: string[];
  op: Json;
}

const METHODS = ["get", "post", "put", "patch", "delete"];
const SPEC_ID = "varlatch-openapi";

let state: { spec: Json; ops: Operation[]; ajv: Ajv2020; compiled: Map<string, ValidateFunction> } | undefined;

export function specPath(): string {
  return fileURLToPath(new URL("../../../../packages/protocol/openapi.yaml", import.meta.url));
}

function load() {
  if (state) return state;
  const spec = parse(readFileSync(specPath(), "utf8")) as Json;
  const ops: Operation[] = [];
  for (const [path, item] of Object.entries(spec.paths as Record<string, Json>)) {
    for (const method of METHODS) {
      const op = item[method] as Json | undefined;
      if (!op) continue;
      const template = `/v1${path}`;
      ops.push({ method: method.toUpperCase(), template, segments: template.split("/"), op });
    }
  }
  // OpenAPI keywords that are not JSON Schema's are left alone (strict
  // off); spec-lint in openapi-conformance.test.ts refuses the 3.0-only
  // ones that a 3.1 document must not carry.
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  const addFormats = (addFormatsModule as unknown as { default?: typeof addFormatsModule }).default ?? addFormatsModule;
  (addFormats as unknown as (a: Ajv2020) => void)(ajv);
  ajv.addFormat("int32", { type: "number", validate: (n: number) => Number.isInteger(n) && n >= -(2 ** 31) && n < 2 ** 31 });
  ajv.addFormat("int64", { type: "number", validate: (n: number) => Number.isInteger(n) });
  ajv.addFormat("float", { type: "number", validate: () => true });
  ajv.addFormat("double", { type: "number", validate: () => true });
  ajv.addFormat("password", () => true);
  ajv.addFormat("byte", /^[A-Za-z0-9+/]*={0,2}$/);
  ajv.addFormat("binary", () => true);
  ajv.addSchema({ ...spec, $id: SPEC_ID } as never);
  state = { spec, ops, ajv, compiled: new Map() };
  return state;
}

/** Every operation in the spec, as "METHOD /v1/template". */
export function specOperations(): string[] {
  return load().ops.map((o) => `${o.method} ${o.template}`);
}

/** The spec operation a concrete request path matches, most literal first. */
export function matchOperation(method: string, pathname: string): Operation | undefined {
  const parts = pathname.split("/");
  let best: { op: Operation; score: number[] } | undefined;
  for (const op of load().ops) {
    if (op.method !== method || op.segments.length !== parts.length) continue;
    const score: number[] = [];
    let ok = true;
    for (let i = 0; i < parts.length; i++) {
      const seg = op.segments[i]!;
      if (/^\{[^}]+\}$/.test(seg)) {
        if (parts[i] === "") ok = false;
        score.push(0);
      } else if (seg === parts[i]) score.push(1);
      else ok = false;
      if (!ok) break;
    }
    if (!ok) continue;
    if (!best || compareScore(score, best.score) > 0) best = { op, score };
  }
  return best?.op;
}

function compareScore(a: number[], b: number[]): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

function pointer(parts: string[]): string {
  return parts.map((p) => p.replace(/~/g, "~0").replace(/\//g, "~1")).join("/");
}

function deref(node: unknown): Json | undefined {
  let cur = node as Json | undefined;
  const { spec } = load();
  for (let i = 0; cur && typeof cur.$ref === "string" && i < 10; i++) {
    const ref = cur.$ref as string;
    if (!ref.startsWith("#/")) return undefined;
    let target: unknown = spec;
    for (const raw of ref.slice(2).split("/")) {
      target = (target as Json | undefined)?.[raw.replace(/~1/g, "/").replace(/~0/g, "~")];
    }
    cur = target as Json | undefined;
  }
  return cur;
}

function validator(schemaPointer: string): ValidateFunction {
  const s = load();
  let fn = s.compiled.get(schemaPointer);
  if (!fn) {
    fn = s.ajv.compile({ $ref: `${SPEC_ID}#${schemaPointer}` });
    s.compiled.set(schemaPointer, fn);
  }
  return fn;
}

function describeErrors(errors: ErrorObject[] | null | undefined): string {
  // allErrors with oneOf/anyOf lists every branch; the first few suffice to
  // find the field, and the full set is reproducible from the test.
  const seen = new Set<string>();
  for (const e of errors ?? []) {
    const p = e.params as { additionalProperty?: string; allowedValues?: unknown; passingSchemas?: unknown };
    const params = e.keyword === "additionalProperties"
      ? ` (${String(p.additionalProperty)})`
      : e.keyword === "enum"
        ? ` (${JSON.stringify(p.allowedValues)})`
        : e.keyword === "oneOf"
          ? ` (${p.passingSchemas ? `matches ${JSON.stringify(p.passingSchemas)}` : "matches none"} at ${e.schemaPath})`
          : "";
    seen.add(`${e.instancePath || "/"} ${e.message ?? e.keyword}${params}`);
    if (seen.size >= 6) break;
  }
  return [...seen].join("; ");
}

function mediaType(header: string | null): string | null {
  return header ? header.split(";")[0]!.trim().toLowerCase() : null;
}

function isJson(type: string | null): boolean {
  return type !== null && (type === "application/json" || type.endsWith("+json"));
}

function contentFor(content: Json | undefined, type: string | null): string | undefined {
  if (!content || type === null) return undefined;
  if (type in content) return type;
  const [major] = type.split("/");
  if (`${major}/*` in content) return `${major}/*`;
  if ("*/*" in content) return "*/*";
  return undefined;
}

/**
 * Checks one request and its response. The bodies are read beforehand by
 * the caller from clones; responseText is null when the response is not
 * JSON (streams are never read).
 */
export function checkExchange(input: {
  method: string;
  pathname: string;
  requestContentType: string | null;
  requestText: string | null;
  status: number;
  responseContentType: string | null;
  responseHasBody: boolean;
  responseText: string | null;
}): { exchange?: Exchange; mismatches: Mismatch[] } {
  const { method, pathname, status } = input;
  if (pathname !== "/v1" && !pathname.startsWith("/v1/")) return { mismatches: [] };
  const matched = matchOperation(method, pathname);
  if (!matched) {
    const concrete = `${method} ${pathname}`;
    // A path the spec does not have is only a mismatch when the server
    // served it; a 404 or 405 for a made-up path is the expected answer.
    if (UNSPECCED.has(concrete) || status >= 300) return { mismatches: [] };
    return { mismatches: [{ kind: "undocumented-operation", operation: concrete, status, detail: "served with a 2xx but not in the spec" }] };
  }
  const operation = `${matched.method} ${matched.template}`;
  if (UNSPECCED.has(operation)) return { mismatches: [] };
  const mismatches: Mismatch[] = [];
  const add = (kind: MismatchKind, detail: string) => {
    if (ALLOWED.has(`${kind} ${operation} ${status}`)) return;
    mismatches.push({ kind, operation, status, detail });
  };
  const opPointer = ["", "paths", matched.template.slice("/v1".length), matched.method.toLowerCase()];

  // Response.
  const responses = (matched.op.responses ?? {}) as Json;
  const statusKey = String(status) in responses
    ? String(status)
    : `${String(status)[0]}XX` in responses
      ? `${String(status)[0]}XX`
      : "default" in responses
        ? "default"
        : undefined;
  if (!statusKey) {
    add("undocumented-status", `documented: ${Object.keys(responses).join(", ")}`);
  } else {
    const response = deref(responses[statusKey]);
    const content = response?.content as Json | undefined;
    const type = mediaType(input.responseContentType);
    const empty = !input.responseHasBody || input.responseText === "";
    if (!content || Object.keys(content).length === 0) {
      if (!empty) add("undocumented-response-body", `${type ?? "no content type"} body, spec documents none`);
    } else if (empty) {
      add("missing-response-body", `spec documents ${Object.keys(content).join(", ")}`);
    } else {
      const key = contentFor(content, type);
      if (!key) add("response-content-type", `${type ?? "none"}, spec documents ${Object.keys(content).join(", ")}`);
      else if (isJson(type) && input.responseText !== null) {
        let body: unknown;
        try {
          body = JSON.parse(input.responseText);
        } catch {
          add("response-not-json", "body is not JSON");
        }
        const schema = (content[key] as Json | undefined)?.schema;
        if (body !== undefined && schema) {
          // Through the response's own location (or its $ref target), so
          // the schema keeps its place in the document for refs.
          const raw = responses[statusKey] as Json;
          const base = typeof raw.$ref === "string"
            ? (raw.$ref as string).slice(1)
            : `${pointer(opPointer)}/responses/${pointer([statusKey])}`;
          const fn = validator(`${base}/content/${pointer([key])}/schema`);
          if (!fn(body)) add("response-schema", describeErrors(fn.errors));
        }
      }
    }
  }

  // Request, judged only when the server accepted it: a refused request may
  // be malformed on purpose.
  if (status >= 200 && status < 300 && method !== "GET" && method !== "HEAD") {
    const requestBody = deref(matched.op.requestBody);
    const hasBody = input.requestText !== null && input.requestText !== "";
    const content = requestBody?.content as Json | undefined;
    const type = mediaType(input.requestContentType);
    if (!requestBody) {
      if (hasBody) add("undocumented-request-body", `${type ?? "no content type"} body, spec documents none`);
    } else if (!hasBody) {
      if (requestBody.required === true) add("missing-request-body", "requestBody is required");
    } else {
      const key = contentFor(content, type);
      if (!key) add("request-content-type", `${type ?? "none"}, spec documents ${Object.keys(content ?? {}).join(", ")}`);
      else if (isJson(type)) {
        let body: unknown;
        try {
          body = JSON.parse(input.requestText!);
        } catch {
          body = undefined;
        }
        const schema = (content![key] as Json | undefined)?.schema;
        if (body !== undefined && schema) {
          const raw = matched.op.requestBody as Json;
          const base = typeof raw.$ref === "string" ? (raw.$ref as string).slice(1) : `${pointer(opPointer)}/requestBody`;
          const fn = validator(`${base}/content/${pointer([key])}/schema`);
          if (!fn(body)) add("request-schema", describeErrors(fn.errors));
        }
      }
    }
  }
  return { exchange: { operation, status }, mismatches };
}

/** Reads what checkExchange needs from a request/response pair. */
export async function inspect(request: Request, requestText: string | null, response: Response) {
  const pathname = new URL(request.url).pathname;
  if (pathname !== "/v1" && !pathname.startsWith("/v1/")) return { mismatches: [] as Mismatch[] };
  const responseContentType = response.headers.get("content-type");
  const responseText = isJson(mediaType(responseContentType)) || response.status === 204 || !responseContentType
    ? await response.clone().text()
    : null;
  return checkExchange({
    method: request.method,
    pathname,
    requestContentType: request.headers.get("content-type"),
    requestText,
    status: response.status,
    responseContentType,
    responseHasBody: response.body !== null,
    responseText,
  });
}
