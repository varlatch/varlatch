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
 *   no body (a bare {} excepted, which generic test helpers send and such
 *   handlers ignore);
 * - an accepted request body that does not parse as JSON is a mismatch.
 *
 * Not checked: paths outside /v1 (auth, enrollment, health, JWKS, install
 * scripts), CORS preflights, the deliberately unspecced Convex token
 * exchange, request bodies of refused requests, query parameters and
 * headers. ALLOWED lists the excused mismatches, each with its reason.
 */

export type MismatchKind =
  | "undocumented-operation"
  | "undocumented-status"
  | "undocumented-response-body"
  | "missing-response-body"
  | "response-content-type"
  | "response-schema"
  | "response-undocumented-field"
  | "response-not-json"
  | "undocumented-request-body"
  | "missing-request-body"
  | "request-content-type"
  | "request-not-json"
  | "request-schema"
  | "request-undocumented-field";

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
  if (v === "collect" || v === "off") return v;
  return "enforce";
}

/** Served under /v1 but outside the contract (spec-coverage.test.ts). */
const UNSPECCED = new Set(["POST /v1/tokens/convex"]);

/**
 * A mismatch that cannot be fixed in the spec, with its reason. With
 * `field` (a JSON pointer into the body, such as "/slug") it excuses only
 * that one undocumented field: any other field the spec does not name, or
 * any other schema error, in the same body is still a mismatch. Without
 * `field` it excuses every mismatch of its kind for the operation and
 * status, so prefer a field. Keep the list empty unless a reason holds.
 */
export interface Allowance {
  kind: MismatchKind;
  /** "METHOD /v1/template". */
  operation: string;
  status: number;
  field?: string;
  reason: string;
}

export const ALLOWED: readonly Allowance[] = [
  {
    // organization-rename.test.ts sends a slug on purpose, to prove the
    // rename ignores it. The spec rightly names only `name`; the server's
    // parser drops unknown fields.
    kind: "request-undocumented-field",
    operation: "PATCH /v1/organizations/{org}",
    status: 200,
    field: "/slug",
    reason: "a test sends slug on purpose to prove a rename never changes it; the server drops unknown fields",
  },
];

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
  ajv.addSchema({ ...closeWorld(spec), $id: SPEC_ID } as never);
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

/**
 * The spec as the validator sees it: every object schema closed, so a field
 * the server sends (or a test sends) that the spec does not name is a
 * mismatch rather than silently allowed. A schema the spec leaves open on
 * purpose (additionalProperties or unevaluatedProperties set, or an object
 * without properties) stays open.
 *
 * unevaluatedProperties: false goes on every place a schema is used, not
 * where a component is defined, and never on a direct allOf member, so
 * that an allOf composition sees the properties of all its members.
 */
function closeWorld(spec: Json): Json {
  const copy = structuredClone(spec);
  const seen = new Set<object>();
  const close = (node: unknown, inAllOf: boolean): void => {
    if (!node || typeof node !== "object" || Array.isArray(node)) return;
    const n = node as Json;
    const open = "additionalProperties" in n || "unevaluatedProperties" in n;
    const objectish = typeof n.$ref === "string" || "properties" in n || "allOf" in n || "oneOf" in n || "anyOf" in n;
    if (!inAllOf && !open && objectish) n.unevaluatedProperties = false;
    if (seen.has(n)) return;
    seen.add(n);
    for (const child of Object.values((n.properties ?? {}) as Json)) close(child, false);
    for (const key of ["patternProperties", "$defs"]) for (const child of Object.values((n[key] ?? {}) as Json)) close(child, false);
    if (n.items && typeof n.items === "object") close(n.items, false);
    if (n.additionalProperties && typeof n.additionalProperties === "object") close(n.additionalProperties, false);
    for (const child of (n.prefixItems ?? []) as unknown[]) close(child, false);
    for (const child of (n.allOf ?? []) as unknown[]) close(child, true);
    for (const key of ["oneOf", "anyOf"]) for (const child of (n[key] ?? []) as unknown[]) close(child, false);
  };
  const components = (copy.components ?? {}) as Json;
  // A component's own root stays open: it is closed where it is used.
  for (const schema of Object.values((components.schemas ?? {}) as Json)) close(schema, true);
  const contents = (holder: unknown) => {
    for (const media of Object.values(((holder as Json | undefined)?.content ?? {}) as Json)) close((media as Json).schema, false);
  };
  for (const r of Object.values((components.responses ?? {}) as Json)) contents(r);
  for (const r of Object.values((components.requestBodies ?? {}) as Json)) contents(r);
  for (const item of Object.values(copy.paths as Json)) {
    for (const method of METHODS) {
      const op = (item as Json)[method] as Json | undefined;
      if (!op) continue;
      contents(op.requestBody);
      for (const r of Object.values((op.responses ?? {}) as Json)) contents(r);
    }
  }
  return copy;
}

function onlyUndocumentedFields(errors: ErrorObject[] | null | undefined): boolean {
  return (errors ?? []).length > 0 && (errors ?? []).every((e) => e.keyword === "unevaluatedProperties");
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
    const p = e.params as { additionalProperty?: string; unevaluatedProperty?: string; allowedValues?: unknown; passingSchemas?: unknown };
    const params = e.keyword === "additionalProperties" || e.keyword === "unevaluatedProperties"
      ? ` (${String(p.additionalProperty ?? p.unevaluatedProperty)})`
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
  // CORS preflights, which the tailnet browser endpoint answers before any
  // route (ADR-0046), are transport, not operations of the contract.
  if (method === "OPTIONS") return { mismatches: [] };
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
  const allowances = (kind: MismatchKind) => ALLOWED.filter((a) => a.kind === kind && a.operation === operation && a.status === status);
  const add = (kind: MismatchKind, detail: string) => {
    if (allowances(kind).some((a) => a.field === undefined)) return;
    mismatches.push({ kind, operation, status, detail });
  };
  // Schema errors, less those an allowance excuses field by field.
  const schemaErrors = (fn: ValidateFunction, fieldKind: MismatchKind, otherKind: MismatchKind) => {
    const excused = new Set(allowances(fieldKind).flatMap((a) => (a.field === undefined ? [] : [a.field])));
    const errors = (fn.errors ?? []).filter((e) => {
      if (e.keyword !== "unevaluatedProperties") return true;
      const property = (e.params as { unevaluatedProperty?: string }).unevaluatedProperty ?? "";
      return !excused.has(`${e.instancePath}/${pointer([property])}`);
    });
    if (errors.length) add(onlyUndocumentedFields(errors) ? fieldKind : otherKind, describeErrors(errors));
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
          if (!fn(body)) schemaErrors(fn, "response-undocumented-field", "response-schema");
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
      // Generic test helpers send {} to every POST; a server handler
      // without a body ignores it. Anything more is a body the spec omits.
      if (hasBody && input.requestText!.trim() !== "{}") {
        add("undocumented-request-body", `${type ?? "no content type"} body, spec documents none`);
      }
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
          // The server accepted a body that is not JSON: either it never
          // read it, and the spec should say so, or the spec's content type
          // is wrong.
          add("request-not-json", `${type} body that does not parse as JSON`);
        }
        const schema = (content![key] as Json | undefined)?.schema;
        if (body !== undefined && schema) {
          const raw = matched.op.requestBody as Json;
          const base = typeof raw.$ref === "string" ? (raw.$ref as string).slice(1) : `${pointer(opPointer)}/requestBody`;
          const fn = validator(`${base}/content/${pointer([key])}/schema`);
          if (!fn(body)) schemaErrors(fn, "request-undocumented-field", "request-schema");
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
