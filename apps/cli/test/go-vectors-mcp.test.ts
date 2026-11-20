// SPDX-License-Identifier: Apache-2.0
import { createRequire } from "node:module";
import { PassThrough } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's `varlatch mcp` (internal docs/design/go-cli.md,
 * decision 5): what the TypeScript server (packages/mcp-server over
 * @modelcontextprotocol/sdk 1.32.2) writes for each input on stdin, read
 * through the SDK's own StdioServerTransport. Its client fails every call
 * ("no server in the vectors"), so these hold the protocol and the tools'
 * checks before any request; the session transcripts (5.6b-mcp) hold the
 * rest. The Go test (internal/mcp's TestVectors) replays each input and
 * compares the lines written, as a multiset where one input holds several
 * requests. Regenerate after a change to the server or the SDK:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-mcp.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/mcp.json", import.meta.url));
const MCP_PACKAGE = new URL("../../../packages/mcp-server/package.json", import.meta.url);

/** A module as packages/mcp-server resolves it (apps/cli does not depend on the SDK itself). */
async function fromMcpPackage<T>(specifier: string): Promise<T> {
  const path = createRequire(MCP_PACKAGE).resolve(specifier);
  return (await import(pathToFileURL(path).href)) as T;
}

/**
 * The server's configuration: defaults (acme/web/dev) and writes with a
 * client every call of which fails; "bare", no defaults and no writes, with
 * that client; and with defaults and writes, a client answering every call
 * with nothing (an empty body), with null, or with an API error.
 */
type Config = "defaults-writes" | "bare" | "undefined-answers" | "null-answers" | "api-error";

interface McpCase {
  id: string;
  /** The server's configuration. */
  config: Config;
  /** The bytes on stdin. */
  input: string;
  /** The lines written, in the order written. */
  output: string[];
}

const SERVER = "http://vectors.invalid";
const VERSION = "9.9.9-vectors";
const FAILURE = "no server in the vectors";

/** The API error of config "api-error". */
const API_ERROR = { status: 409, code: "VERSION_CONFLICT", message: "the value changed", requestId: "req_vectors" };

/** A client every call of which fails, as a request that never reached a server would, or answers as `config` says. */
function fakeClient(config: Config, VarlatchApiError: new (status: number, body: unknown) => Error): unknown {
  return new Proxy(
    { server: SERVER },
    {
      get(target, name) {
        if (name === "server") return target.server;
        if (name === "then") return undefined;
        return async () => {
          if (config === "undefined-answers") return undefined;
          if (config === "null-answers") return null;
          if (config === "api-error") throw new VarlatchApiError(API_ERROR.status, API_ERROR);
          throw new Error(FAILURE);
        };
      },
    },
  );
}

const j = (v: unknown) => JSON.stringify(v);
const req = (id: unknown, method: string, params?: unknown) => j({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
const call = (id: unknown, name: string, args?: unknown) => req(id, "tools/call", { name, ...(args === undefined ? {} : { arguments: args }) });
const init = (params: unknown) => req(1, "initialize", params);
const CLIENT = { name: "vectors", version: "1" };

const inputs: { id: string; config?: McpCase["config"]; input: string }[] = [];
const add = (id: string, input: string, config?: Config) => inputs.push({ id, input, ...(config ? { config } : {}) });
const line = (id: string, message: string, config?: Config) => add(id, `${message}\n`, config);

// ---- Framing: what is a message, and what is dropped ----------------------------
for (const [id, text] of [
  ["empty", ""],
  ["cr", "\r"],
  ["space", " "],
  ["garbage", "garbage"],
  ["object", "{}"],
  ["array", "[]"],
  ["null", "null"],
  ["number", "1"],
  ["string", '"ping"'],
  ["bom", `﻿${req(1, "ping")}`],
  ["batch", `[${req(1, "ping")}]`],
  ["no-jsonrpc", j({ id: 1, method: "ping" })],
  ["jsonrpc-1", j({ jsonrpc: "1.0", id: 1, method: "ping" })],
  ["jsonrpc-number", j({ jsonrpc: 2, id: 1, method: "ping" })],
  ["extra-key", j({ jsonrpc: "2.0", id: 1, method: "ping", extra: true })],
  ["method-number", j({ jsonrpc: "2.0", id: 1, method: 7 })],
  ["params-null", j({ jsonrpc: "2.0", id: 1, method: "ping", params: null })],
  ["params-array", j({ jsonrpc: "2.0", id: 1, method: "ping", params: [] })],
  ["params-string", j({ jsonrpc: "2.0", id: 1, method: "ping", params: "x" })],
  ["params-extra", j({ jsonrpc: "2.0", id: 1, method: "ping", params: { extra: 1 } })],
  ["meta-token-string", req(1, "ping", { _meta: { progressToken: "t" } })],
  ["meta-token-number", req(1, "ping", { _meta: { progressToken: 3 } })],
  ["meta-token-float", req(1, "ping", { _meta: { progressToken: 1.5 } })],
  ["meta-token-null", req(1, "ping", { _meta: { progressToken: null } })],
  ["meta-null", req(1, "ping", { _meta: null })],
  ["meta-extra", req(1, "ping", { _meta: { other: [1] } })],
  ["meta-related-task", req(1, "ping", { _meta: { "io.modelcontextprotocol/related-task": { taskId: "t" } } })],
  ["meta-related-task-bad", req(1, "ping", { _meta: { "io.modelcontextprotocol/related-task": { taskId: 1 } } })],
  ["result", j({ jsonrpc: "2.0", id: 1, result: {} })],
  ["result-unknown-id", j({ jsonrpc: "2.0", id: 99, result: { x: 1 } })],
  ["error", j({ jsonrpc: "2.0", id: 1, error: { code: -1, message: "x" } })],
  ["error-no-id", j({ jsonrpc: "2.0", error: { code: -1, message: "x" } })],
  ["method-and-result", j({ jsonrpc: "2.0", id: 1, method: "ping", result: {} })],
  ["deep", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":${"[".repeat(5000)}${"]".repeat(5000)}}}`],
  ["duplicate-id-key", '{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}'],
  ["unicode-method", req(1, "pïng")],
] as const) {
  line(`framing.${id}`, text);
}
for (const [id, value] of [
  ["one", 1],
  ["zero", 0],
  ["negative", -7],
  ["string", "a"],
  ["empty-string", ""],
  ["float", 1.5],
  ["exponent", 1e3],
  ["large", 9007199254740991],
  ["unsafe", 9007199254740992],
  ["null", null],
  ["true", true],
  ["object", {}],
  ["array", [1]],
  ["unicode", "é "],
] as const) {
  line(`id.${id}`, req(value, "ping"));
}
line("id.minus-zero", '{"jsonrpc":"2.0","id":-0,"method":"ping"}');
line("id.float-integral", '{"jsonrpc":"2.0","id":2.0,"method":"ping"}');
line("id.exponent-text", '{"jsonrpc":"2.0","id":1E2,"method":"ping"}');
add("framing.crlf", `${req(1, "ping")}\r\n`);
add("framing.no-newline", req(1, "ping"));
add("framing.two", `${req(1, "ping")}\n${req(2, "ping")}\n`);
add("framing.blank-between", `${req(1, "ping")}\n\n${req(2, "ping")}\n`);
add("framing.garbage-between", `${req(1, "ping")}\nnope\n${req(2, "ping")}\n`);
add("framing.split-utf8", `${req("é", "ping")}\n`);

// ---- Methods ------------------------------------------------------------------------
for (const method of ["logging/setLevel", "resources/list", "resources/read", "prompts/list", "prompts/get", "completion/complete", "tasks/get", "tasks/list", "tasks/result", "tasks/cancel", "sampling/createMessage", "roots/list", "elicitation/create", "notifications/initialized", "toString", "constructor", "__proto__", "", "Ping", "tools/List"]) {
  line(`method.${method || "empty"}`, req(1, method));
  line(`method.${method || "empty"}.params`, req(1, method, { x: 1 }));
}
for (const method of ["notifications/initialized", "notifications/cancelled", "notifications/progress", "notifications/unknown", "ping", "tools/list", "initialize"]) {
  line(`notification.${method}`, j({ jsonrpc: "2.0", method }));
  line(`notification.${method}.params`, j({ jsonrpc: "2.0", method, params: { requestId: 1, progressToken: 1, progress: 1 } }));
}

for (const version of ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07", "2099-01-01", "", "2025-11-25 "]) {
  line(`initialize.version.${version || "empty"}`, init({ protocolVersion: version, capabilities: {}, clientInfo: CLIENT }));
}
for (const [id, params] of [
  ["no-params", undefined],
  ["empty", {}],
  ["version-number", { protocolVersion: 1, capabilities: {}, clientInfo: CLIENT }],
  ["no-version", { capabilities: {}, clientInfo: CLIENT }],
  ["no-capabilities", { protocolVersion: "2025-11-25", clientInfo: CLIENT }],
  ["capabilities-null", { protocolVersion: "2025-11-25", capabilities: null, clientInfo: CLIENT }],
  ["no-client", { protocolVersion: "2025-11-25", capabilities: {} }],
  ["client-no-name", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { version: "1" } }],
  ["client-no-version", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x" } }],
  ["client-version-number", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: 1 } }],
  ["client-extra", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { ...CLIENT, extra: 1, title: "t" } }],
  ["client-icons-bad", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { ...CLIENT, icons: [{}] } }],
  ["client-theme-bad", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { ...CLIENT, icons: [{ src: "a", theme: "blue" }] } }],
  ["capabilities-full", { protocolVersion: "2025-11-25", capabilities: { roots: { listChanged: true }, sampling: {}, elicitation: {}, experimental: { a: {} }, tasks: {} }, clientInfo: CLIENT }],
  ["capabilities-roots-bad", { protocolVersion: "2025-11-25", capabilities: { roots: { listChanged: "yes" } }, clientInfo: CLIENT }],
  ["capabilities-experimental-bad", { protocolVersion: "2025-11-25", capabilities: { experimental: { a: 1 } }, clientInfo: CLIENT }],
  ["capabilities-sampling-bad", { protocolVersion: "2025-11-25", capabilities: { sampling: { context: 1 } }, clientInfo: CLIENT }],
  ["capabilities-unknown", { protocolVersion: "2025-11-25", capabilities: { other: 1 }, clientInfo: CLIENT }],
  ["everything-wrong", { protocolVersion: false, capabilities: [], clientInfo: "x" }],
  ["meta", { _meta: { progressToken: "p" }, protocolVersion: "2025-11-25", capabilities: {}, clientInfo: CLIENT }],
  ["task", { task: {}, protocolVersion: "2025-11-25", capabilities: {}, clientInfo: CLIENT }],
] as const) {
  line(`initialize.${id}`, req(1, "initialize", params));
}
const capabilities: [string, unknown][] = [
  ["experimental-number", { experimental: 1 }],
  ["experimental-array", { experimental: [] }],
  ["experimental-array-value", { experimental: { a: [] } }],
  ["extensions-bad", { extensions: { a: 1 } }],
  ["extensions-number", { extensions: 1 }],
  ["sampling-number", { sampling: 1 }],
  ["sampling-tools-bad", { sampling: { tools: null } }],
  ["roots-number", { roots: 1 }],
  ["elicitation-empty", { elicitation: {} }],
  ["elicitation-number", { elicitation: 1 }],
  ["elicitation-null", { elicitation: null }],
  ["elicitation-array", { elicitation: [] }],
  ["elicitation-string", { elicitation: "x" }],
  ["elicitation-form-number", { elicitation: { form: 1 } }],
  ["elicitation-form-bad", { elicitation: { form: { applyDefaults: "x" } } }],
  ["elicitation-form-ok", { elicitation: { form: { applyDefaults: true, other: 1 } } }],
  ["elicitation-url-number", { elicitation: { url: 1 } }],
  ["elicitation-url-ok", { elicitation: { url: {}, other: 2 } }],
  ["elicitation-both-bad", { elicitation: { form: 1, url: 1 } }],
  ["tasks-number", { tasks: 1 }],
  ["tasks-list-bad", { tasks: { list: 1 } }],
  ["tasks-cancel-bad", { tasks: { cancel: null } }],
  ["tasks-requests-number", { tasks: { requests: 1 } }],
  ["tasks-sampling-number", { tasks: { requests: { sampling: 1 } } }],
  ["tasks-create-message-bad", { tasks: { requests: { sampling: { createMessage: 1 } } } }],
  ["tasks-elicitation-create-bad", { tasks: { requests: { elicitation: { create: "x" } } } }],
  ["tasks-ok", { tasks: { list: {}, cancel: {}, requests: { sampling: { createMessage: {} }, elicitation: { create: {} } }, other: 1 } }],
  ["several-bad", { roots: 1, sampling: 1, experimental: 1, tasks: 1 }],
];
for (const [id, caps] of capabilities) {
  line(`initialize.capabilities.${id}`, init({ protocolVersion: "2025-11-25", capabilities: caps, clientInfo: CLIENT }));
}
for (const [id, clientInfo] of [
  ["title-number", { ...CLIENT, title: 1 }],
  ["website-number", { ...CLIENT, websiteUrl: 1 }],
  ["description-number", { ...CLIENT, description: 1 }],
  ["icons-number", { ...CLIENT, icons: 1 }],
  ["icon-null", { ...CLIENT, icons: [null] }],
  ["icon-sizes-bad", { ...CLIENT, icons: [{ src: "a", sizes: [1] }] }],
  ["icon-mime-bad", { ...CLIENT, icons: [{ src: "a", mimeType: 1 }] }],
  ["icons-several", { ...CLIENT, icons: [{ src: "a" }, { src: 1, theme: "x" }, 5] }],
  ["array", []],
  ["null", null],
] as const) {
  line(`initialize.client.${id}`, init({ protocolVersion: "2025-11-25", capabilities: {}, clientInfo }));
}
for (const method of ["ping", "tools/list"]) {
  line(`task.${method}`, req(1, method, { task: {} }));
  line(`task.${method}.bad`, req(1, method, { task: { ttl: "x" } }));
}
line("task.unknown-method", req(1, "nope", { task: {} }));
line("task.call-extra", req(1, "tools/call", { name: "varlatch_whoami", task: { ttl: 5, extra: 1 } }));
line("task.call-unknown-tool", req(1, "tools/call", { name: "nope", task: {} }));
for (const config of ["undefined-answers", "null-answers", "api-error"] as const) {
  for (const [name, args] of [
    ["varlatch_whoami", {}],
    ["varlatch_list_organizations", {}],
    ["varlatch_list_projects", {}],
    ["varlatch_list_environments", {}],
    ["varlatch_effective_configuration", { includeValues: true }],
    ["varlatch_validate_environment", {}],
    ["varlatch_get_active_contract", {}],
    ["varlatch_list_audit_events", { limit: 5, cursor: "c" }],
    ["varlatch_set_value", { item: "A", value: "v" }],
    ["varlatch_set_value", { item: "A", value: "v", replace: "A" }],
    ["varlatch_delete_value", { item: "A", confirm: "A" }],
  ] as const) {
    line(`answers.${config}.${name}.${Object.keys(args).join("-") || "none"}`, call(1, name, args), config);
  }
}
line("initialize.twice", `${init({ protocolVersion: "2024-11-05", capabilities: {}, clientInfo: CLIENT })}\n${req(2, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: CLIENT })}`);
line("ping.before-initialize", req(1, "ping"));
line("ping.meta-extra", req(1, "ping", { _meta: {}, extra: 1 }));
for (const config of ["defaults-writes", "bare"] as const) {
  line(`tools-list.${config}`, req(1, "tools/list"), config);
}
for (const [id, params] of [
  ["cursor", { cursor: "c" }],
  ["cursor-number", { cursor: 1 }],
  ["cursor-null", { cursor: null }],
  ["extra", { other: 1 }],
] as const) {
  line(`tools-list.${id}`, req(1, "tools/list", params));
}

// ---- tools/call: the request ------------------------------------------------------
for (const [id, params] of [
  ["no-params", undefined],
  ["empty", {}],
  ["name-number", { name: 1 }],
  ["name-null", { name: null }],
  ["arguments-array", { name: "varlatch_whoami", arguments: [] }],
  ["arguments-string", { name: "varlatch_whoami", arguments: "x" }],
  ["arguments-null", { name: "varlatch_whoami", arguments: null }],
  ["task", { name: "varlatch_whoami", task: {} }],
  ["task-ttl", { name: "varlatch_whoami", task: { ttl: 1000 } }],
  ["task-bad", { name: "varlatch_whoami", task: { ttl: "x" } }],
  ["task-null", { name: "varlatch_whoami", task: null }],
  ["meta", { name: "varlatch_whoami", _meta: { progressToken: 1 } }],
  ["extra", { name: "varlatch_whoami", extra: 1 }],
  ["everything-wrong", { name: [], arguments: 1, task: 1 }],
] as const) {
  line(`call.${id}`, req(1, "tools/call", params));
}
for (const name of ["nope", "", "VARLATCH_WHOAMI", "varlatch_reveal_value", "toString", "constructor", "__proto__", "hasOwnProperty", "valueOf", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "__defineGetter__", "__lookupSetter__"]) {
  line(`call.unknown.${name || "empty"}`, call(1, name, {}));
}
for (const config of ["defaults-writes", "bare"] as const) {
  for (const name of ["varlatch_set_value", "varlatch_delete_value"]) line(`call.writes.${config}.${name}`, call(1, name, { item: "A", value: "x", confirm: "A" }), config);
}

// ---- tools/call: each tool's arguments -------------------------------------------
const TOOLS = {
  varlatch_whoami: [],
  varlatch_list_organizations: [],
  varlatch_list_projects: ["organization"],
  varlatch_list_environments: ["organization", "project"],
  varlatch_effective_configuration: ["organization", "project", "environment", "includeValues"],
  varlatch_validate_environment: ["organization", "project", "environment"],
  varlatch_get_active_contract: ["organization", "project"],
  varlatch_list_audit_events: ["organization", "limit", "cursor"],
  varlatch_set_value: ["organization", "project", "environment", "item", "value", "expectedVersionId", "replace"],
  varlatch_delete_value: ["organization", "project", "environment", "item", "confirm"],
} as const;
const WRONG: [string, unknown][] = [
  ["number", 1],
  ["null", null],
  ["bool", true],
  ["array", []],
  ["object", {}],
  ["string", "s"],
];
for (const [name, fields] of Object.entries(TOOLS)) {
  for (const config of ["defaults-writes", "bare"] as const) {
    line(`args.${name}.${config}.none`, call(1, name), config);
    line(`args.${name}.${config}.empty`, call(1, name, {}), config);
    line(`args.${name}.${config}.unknown-key`, call(1, name, { item: "A", value: "v", unknown: 1 }), config);
    line(`args.${name}.${config}.given`, call(1, name, { organization: "o", project: "p", environment: "e", item: "A", value: "v" }), config);
  }
  for (const field of fields) {
    for (const [kind, value] of WRONG) line(`args.${name}.${field}.${kind}`, call(1, name, { item: "A", value: "v", [field]: value }));
  }
  if (fields.length > 1) line(`args.${name}.all-wrong`, call(1, name, Object.fromEntries(fields.map((f) => [f, 1]))));
}
for (const limit of [0, 1, 200, 201, -1, 1.5, 0.5, -1.5, 250.5, 1e-7, -1e20, 1e20, 9007199254740991, 9007199254740992, "5"]) {
  line(`args.audit.limit.${String(limit)}`, call(1, "varlatch_list_audit_events", { limit }));
}
for (const [id, args] of [
  ["empty-strings", { organization: "", project: "", environment: "" }],
  ["missing-item", { value: "v" }],
  ["missing-value", { item: "A" }],
  ["replace-other", { item: "A", value: "v", replace: "B" }],
  ["replace-empty", { item: "A", value: "v", replace: "" }],
  ["replace-same", { item: "A", value: "v", replace: "A" }],
  ["item-empty", { item: "", value: "v", replace: "x" }],
] as const) {
  line(`set.${id}`, call(1, "varlatch_set_value", args));
  line(`set.${id}.bare`, call(1, "varlatch_set_value", args), "bare");
}
for (const [id, args] of [
  ["no-confirm", { item: "A" }],
  ["confirm-other", { item: "A", confirm: "B" }],
  ["confirm-empty", { item: "A", confirm: "" }],
  ["confirm-same", { item: "A", confirm: "A" }],
  ["environment-given", { item: "A", environment: "prod" }],
  ["item-empty", { item: "", confirm: "" }],
  ["item-missing", { confirm: "A" }],
] as const) {
  line(`delete.${id}`, call(1, "varlatch_delete_value", args));
}
for (const [name, fields] of Object.entries(TOOLS)) {
  for (const field of fields.filter((f) => ["organization", "project", "environment"].includes(f))) {
    line(`args.${name}.${field}.empty-string`, call(1, name, { item: "A", value: "v", confirm: "A", [field]: "" }));
  }
}
for (const [name] of Object.entries(TOOLS)) line(`args.${name}.bare-no-context`, call(1, name, { item: "A", value: "v", confirm: "A" }), "bare");

describe("Go CLI MCP vectors", () => {
  it("are recorded from the TypeScript server as it is", async () => {
    const { createVarlatchMcpServer } = await import("../../../packages/mcp-server/src/server.js");
    const { VarlatchApiError } = await import("@varlatch/sdk");
    const { StdioServerTransport } = await fromMcpPackage<typeof import("@modelcontextprotocol/sdk/server/stdio.js")>("@modelcontextprotocol/sdk/server/stdio.js");
    const cases: McpCase[] = [];
    const ids = new Set<string>();
    for (const v of inputs) {
      if (ids.has(v.id)) throw new Error(`case ${v.id} twice`);
      ids.add(v.id);
      const config = v.config ?? "defaults-writes";
      const stdin = new PassThrough();
      const stdout = new PassThrough();
      let written = "";
      stdout.on("data", (d: Buffer) => (written += d.toString("utf8")));
      const server = createVarlatchMcpServer({
        client: fakeClient(config, VarlatchApiError as never) as never,
        ...(config !== "bare" ? { defaults: { organization: "acme", project: "web", environment: "dev" }, allowWrites: true } : {}),
        version: VERSION,
      });
      await server.connect(new StdioServerTransport(stdin, stdout));
      stdin.write(Buffer.from(v.input, "utf8"));
      // Every answer comes from microtasks or the failing client: well before this.
      await new Promise((r) => setTimeout(r, 15));
      await server.close();
      expect(written === "" || written.endsWith("\n"), v.id).toBe(true);
      cases.push({ id: v.id, config, input: v.input, output: written === "" ? [] : written.slice(0, -1).split("\n") });
    }
    const text = `${JSON.stringify({ schema: 1, comment: "Recorded from packages/mcp-server over @modelcontextprotocol/sdk by apps/cli/test/go-vectors-mcp.test.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.", server: SERVER, version: VERSION, failure: FAILURE, apiError: API_ERROR, cases }, null, 2)}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "mcp.json is stale: regenerate it (see this file's comment)").toBe(true);
    // Each kind of answer occurs.
    const all = cases.flatMap((c) => c.output).join("\n");
    for (const marker of ['"code":-32601', '"code":-32603', '"isError":true', "Input validation error", '"protocolVersion"', FAILURE]) {
      expect(all.includes(marker), marker).toBe(true);
    }
  }, 120_000);
});
