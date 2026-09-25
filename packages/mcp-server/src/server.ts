// SPDX-License-Identifier: Apache-2.0
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";

export interface McpDefaults {
  organization?: string;
  project?: string;
  environment?: string;
}

export interface VarlatchMcpOptions {
  client: VarlatchClient;
  defaults?: McpDefaults;
  /** Enable varlatch_set_value / varlatch_delete_value. Off by default. */
  allowWrites?: boolean;
  /** Enable varlatch_disclose_secrets (plaintext secrets). Off by default. */
  allowDisclose?: boolean;
}

const orgArg = {
  organization: z.string().optional().describe("Organization slug (defaults to the resolved repo context)"),
};
const projectArg = {
  ...orgArg,
  project: z.string().optional().describe("Project slug (defaults to the resolved repo context)"),
};
const envArg = {
  ...projectArg,
  environment: z.string().optional().describe("Environment name (defaults to the resolved repo context)"),
};

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

function ok(payload: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

function toolError(message: string): ToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

async function run(fn: () => Promise<unknown>): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (err) {
    if (err instanceof VarlatchApiError) {
      return toolError(
        `varlatch API error ${err.status} (${err.code}, request ${err.requestId}): ${err.message}`,
      );
    }
    return toolError(err instanceof Error ? err.message : String(err));
  }
}

export function createVarlatchMcpServer(options: VarlatchMcpOptions): McpServer {
  const { client, defaults = {}, allowWrites = false, allowDisclose = false } = options;

  const server = new McpServer({ name: "varlatch", version: "0.3.1" });

  function required(name: keyof McpDefaults, override: string | undefined): string {
    const value = override ?? defaults[name];
    if (!value) {
      throw new Error(
        `No ${name} given and none resolved from context; pass the "${name}" argument or launch varlatch-mcp inside a varlatch repo / with --${name === "organization" ? "org" : name}.`,
      );
    }
    return value;
  }

  server.registerTool(
    "varlatch_whoami",
    {
      title: "Server and context info",
      description:
        "Show the varlatch server, resolved default organization/project/environment, and which optional capabilities (writes, secret disclosure) this MCP server was started with.",
      inputSchema: {},
    },
    () =>
      run(async () => {
        const meta = await client.meta();
        return { server: client.server, meta, defaults, allowWrites, allowDisclose };
      }),
  );

  server.registerTool(
    "varlatch_list_organizations",
    {
      title: "List organizations",
      description: "List organizations the current credential can see.",
      inputSchema: {},
    },
    () => run(() => client.listOrganizations()),
  );

  server.registerTool(
    "varlatch_list_projects",
    {
      title: "List projects",
      description: "List projects in an organization.",
      inputSchema: orgArg,
    },
    (args) => run(() => client.listProjects(required("organization", args.organization))),
  );

  server.registerTool(
    "varlatch_list_environments",
    {
      title: "List environments",
      description: "List environments in a project.",
      inputSchema: projectArg,
    },
    (args) =>
      run(() =>
        client.listEnvironments(
          required("organization", args.organization),
          required("project", args.project),
        ),
      ),
  );

  server.registerTool(
    "varlatch_effective_configuration",
    {
      title: "Effective configuration",
      description:
        "Get the effective configuration of an environment (contract items, provenance, versions). With includeValues, non-secret values are included; secrets are never returned by this tool.",
      inputSchema: {
        ...envArg,
        includeValues: z.boolean().optional().describe("Include non-secret plaintext values"),
      },
    },
    (args) =>
      run(() =>
        client.effectiveConfiguration(
          required("organization", args.organization),
          required("project", args.project),
          required("environment", args.environment),
          { includeValues: args.includeValues ?? false },
        ),
      ),
  );

  server.registerTool(
    "varlatch_validate_environment",
    {
      title: "Validate environment",
      description:
        "Validate an environment against its active contract and return the validation report. " +
        "Items this credential may not read (Secrets need secret.reveal) are listed in notEvaluated; " +
        "valid is true only when every item was evaluated.",
      inputSchema: envArg,
    },
    (args) =>
      run(() =>
        client.validateEnvironment(
          required("organization", args.organization),
          required("project", args.project),
          required("environment", args.environment),
        ),
      ),
  );

  server.registerTool(
    "varlatch_get_active_contract",
    {
      title: "Get active contract",
      description: "Get the active configuration-contract revision for a project.",
      inputSchema: projectArg,
    },
    (args) =>
      run(() =>
        client.getActiveContract(
          required("organization", args.organization),
          required("project", args.project),
        ),
      ),
  );

  server.registerTool(
    "varlatch_list_audit_events",
    {
      title: "List audit events",
      description: "List recent audit events for an organization (paged).",
      inputSchema: {
        ...orgArg,
        limit: z.number().int().min(1).max(200).optional(),
        cursor: z.string().optional(),
      },
    },
    (args) =>
      run(() =>
        client.listAuditEvents(required("organization", args.organization), {
          ...(args.limit !== undefined ? { limit: args.limit } : {}),
          ...(args.cursor !== undefined ? { cursor: args.cursor } : {}),
        }),
      ),
  );

  if (allowWrites) {
    server.registerTool(
      "varlatch_set_value",
      {
        title: "Set value",
        description:
          "Set a configuration value in an environment. Pass expectedVersionId for optimistic concurrency.",
        inputSchema: {
          ...envArg,
          item: z.string().describe("Item name from the contract, e.g. DATABASE_URL"),
          value: z.string(),
          expectedVersionId: z.string().optional(),
        },
      },
      (args) =>
        run(() =>
          client.setValue(
            required("organization", args.organization),
            required("project", args.project),
            required("environment", args.environment),
            args.item,
            {
              value: args.value,
              ...(args.expectedVersionId !== undefined
                ? { expectedVersionId: args.expectedVersionId }
                : {}),
            },
          ),
        ),
    );

    server.registerTool(
      "varlatch_delete_value",
      {
        title: "Delete value",
        description: "Delete a configuration value from an environment.",
        inputSchema: { ...envArg, item: z.string() },
      },
      (args) =>
        run(async () => {
          await client.deleteValue(
            required("organization", args.organization),
            required("project", args.project),
            required("environment", args.environment),
            args.item,
          );
          return { deleted: args.item };
        }),
    );
  }

  if (allowDisclose) {
    server.registerTool(
      "varlatch_disclose_secrets",
      {
        title: "Disclose secrets",
        description:
          "Disclose plaintext secret values for the named items. Every disclosure is audited server-side. Only available because this server was started with secret disclosure enabled.",
        inputSchema: {
          ...envArg,
          items: z.array(z.string()).min(1).describe("Secret item names to disclose"),
        },
      },
      (args) =>
        run(() =>
          client.discloseSecrets(
            required("organization", args.organization),
            required("project", args.project),
            required("environment", args.environment),
            { items: args.items },
          ),
        ),
    );
  }

  return server;
}
