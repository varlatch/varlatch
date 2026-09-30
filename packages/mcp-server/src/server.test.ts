// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { VarlatchClient } from "@varlatch/sdk";
import { createVarlatchMcpServer, type VarlatchMcpOptions } from "./server.js";

/**
 * The MCP server's tools (ADR-0043 Decision 9): read tools by default, writes
 * with allowWrites, never a disclosure tool, and never a Secret's value written.
 */

interface RecordedRequest {
  method: string;
  url: string;
  body: unknown;
}

function fakeClient(responses: Record<string, unknown>): {
  client: VarlatchClient;
  requests: RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    const path = new URL(url).pathname;
    requests.push({
      method: init?.method ?? "GET",
      url,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    const hit = Object.entries(responses).find(([key]) => path === key);
    if (!hit) {
      return new Response(
        JSON.stringify({ error: { code: "NOT_FOUND", message: `no stub for ${path}`, requestId: "t" } }),
        { status: 404 },
      );
    }
    // A stub `{ status, error }` answers with that API error.
    const stub = hit[1] as { status?: number; error?: string };
    if (stub.status && stub.error) {
      return new Response(JSON.stringify({ error: { code: stub.error, message: stub.error, requestId: "t" } }), { status: stub.status });
    }
    return new Response(JSON.stringify(hit[1]), { status: 200 });
  };
  return {
    client: new VarlatchClient({ server: "https://varlatch.test", token: "tok", fetch: fetchImpl }),
    requests,
  };
}

async function connect(options: VarlatchMcpOptions): Promise<Client> {
  const server = createVarlatchMcpServer(options);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const mcpClient = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), mcpClient.connect(clientTransport)]);
  return mcpClient;
}

const defaults = { organization: "acme", project: "api", environment: "dev" };

describe("varlatch MCP server", () => {
  it("registers only read tools by default", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults });
    const names = (await mcp.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "varlatch_effective_configuration",
      "varlatch_get_active_contract",
      "varlatch_list_audit_events",
      "varlatch_list_environments",
      "varlatch_list_organizations",
      "varlatch_list_projects",
      "varlatch_validate_environment",
      "varlatch_whoami",
    ]);
  });

  it("registers the write tools when enabled, and never a disclosure tool", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults, allowWrites: true });
    const names = (await mcp.listTools()).tools.map((t) => t.name);
    expect(names).toContain("varlatch_set_value");
    expect(names).toContain("varlatch_delete_value");
    expect(names.filter((n) => /disclose|secret|reveal/i.test(n))).toEqual([]);
    // Calling it by name reaches no handler.
    const result = await mcp.callTool({ name: "varlatch_disclose_secrets", arguments: { items: ["API_KEY"] } }).catch((e: unknown) => e);
    expect(JSON.stringify(result)).toMatch(/not found|Tool varlatch_disclose_secrets/i);
  });

  it("lists projects using the default organization", async () => {
    const { client, requests } = fakeClient({
      "/v1/organizations/acme/projects": { items: [{ slug: "api" }], nextCursor: null },
    });
    const mcp = await connect({ client, defaults });
    const result = await mcp.callTool({ name: "varlatch_list_projects", arguments: {} });
    expect(result.isError).toBeFalsy();
    const text = (result.content as { type: string; text: string }[])[0]!.text;
    expect(JSON.parse(text).items[0].slug).toBe("api");
    expect(requests[0]!.method).toBe("GET");
  });

  const CONTRACT = "/v1/organizations/acme/projects/api/contract";
  const contract = {
    id: "crv_1",
    contract: {
      schemaVersion: 1,
      items: [
        { name: "LOG_LEVEL", sensitive: false, type: "string", required: { kind: "never" } },
        { name: "API_KEY", sensitive: true, type: "string", required: { kind: "never" } },
      ],
    },
  };

  it("sets a non-secret value against the resolved environment", async () => {
    const { client, requests } = fakeClient({
      [CONTRACT]: contract,
      "/v1/organizations/acme/projects/api/environments/dev/values/LOG_LEVEL": { versionId: "v1" },
    });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({ name: "varlatch_set_value", arguments: { item: "LOG_LEVEL", value: "debug" } });
    expect(result.isError).toBeFalsy();
    expect(requests.filter((r) => r.method === "PUT")).toMatchObject([{ body: { value: "debug" } }]);
  });

  it.each([
    ["a Secret in the Contract", "API_KEY", { [CONTRACT]: contract }],
    ["an item outside the Contract", "UNLISTED", { [CONTRACT]: contract }],
    ["any item of a project without a Contract", "LOG_LEVEL", {}],
    ["any item when the Contract cannot be read", "LOG_LEVEL", { [CONTRACT]: { status: 403, error: "PERMISSION_DENIED" } }],
  ])("refuses to write %s, and writes nothing", async (_name, item, stubs) => {
    const { client, requests } = fakeClient({
      ...stubs,
      [`/v1/organizations/acme/projects/api/environments/dev/values/${item}`]: { versionId: "v1" },
    });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({ name: "varlatch_set_value", arguments: { item, value: "mcp-secret-value-1" } });
    expect(result.isError).toBe(true);
    const text = (result.content as { type: string; text: string }[])[0]!.text;
    expect(text).toMatch(new RegExp(`${item} is a Secret, and its value is never written through MCP`));
    expect(text).toMatch(/--generate hex:32/);
    expect(text).not.toContain("mcp-secret-value-1");
    expect(requests.filter((r) => r.method !== "GET")).toEqual([]);
  });

  it("deleting a value writes no value, and stays available with --allow-writes", async () => {
    const { client, requests } = fakeClient({ "/v1/organizations/acme/projects/api/environments/dev/values/API_KEY": {} });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({ name: "varlatch_delete_value", arguments: { item: "API_KEY" } });
    expect(result.isError).toBeFalsy();
    expect(requests).toMatchObject([{ method: "DELETE" }]);
  });

  it("returns a tool error when scope cannot be resolved", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults: {} });
    const result = await mcp.callTool({ name: "varlatch_list_projects", arguments: {} });
    expect(result.isError).toBe(true);
    const text = (result.content as { type: string; text: string }[])[0]!.text;
    expect(text).toContain("organization");
  });

  it("surfaces API errors with code and requestId", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults });
    const result = await mcp.callTool({ name: "varlatch_list_organizations", arguments: {} });
    expect(result.isError).toBe(true);
    const text = (result.content as { type: string; text: string }[])[0]!.text;
    expect(text).toContain("NOT_FOUND");
  });
});
