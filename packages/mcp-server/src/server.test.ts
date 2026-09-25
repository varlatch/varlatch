// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { VarlatchClient } from "@varlatch/sdk";
import { createVarlatchMcpServer, type VarlatchMcpOptions } from "./server.js";

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

  it("registers write and disclosure tools when enabled", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults, allowWrites: true, allowDisclose: true });
    const names = (await mcp.listTools()).tools.map((t) => t.name);
    expect(names).toContain("varlatch_set_value");
    expect(names).toContain("varlatch_delete_value");
    expect(names).toContain("varlatch_disclose_secrets");
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

  it("sets a value against the resolved environment", async () => {
    const { client, requests } = fakeClient({
      "/v1/organizations/acme/projects/api/environments/dev/values/DATABASE_URL": {
        versionId: "v1",
      },
    });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({
      name: "varlatch_set_value",
      arguments: { item: "DATABASE_URL", value: "postgres://x" },
    });
    expect(result.isError).toBeFalsy();
    expect(requests[0]).toMatchObject({ method: "PUT", body: { value: "postgres://x" } });
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
