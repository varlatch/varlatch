// SPDX-License-Identifier: Apache-2.0
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";

export interface McpDefaults {
  organization?: string;
  project?: string;
  environment?: string;
}

/**
 * The MCP server (ADR-0043 Decision 9): read tools by default, writes only
 * with `allowWrites`, and no tool that returns a Secret's value. No MCP host
 * can keep a tool result out of the model's context, so there is no
 * disclosure tool at all, and a write that would put a Secret's value into a
 * tool call is refused: Secrets enter through `varlatch import`,
 * `values set --generate`, or the human.
 */
export interface VarlatchMcpOptions {
  client: VarlatchClient;
  defaults?: McpDefaults;
  /** Enable varlatch_set_value / varlatch_delete_value. Off by default. */
  allowWrites?: boolean;
  /** Reported to MCP hosts: the version of the CLI that runs the server. */
  version?: string;
}

/**
 * Whether `item` is a Secret by the active Contract: items outside it, and
 * every item of a project without one, are (ADR-0012), and so is every item
 * when the Contract cannot be read.
 */
export async function isSecretItem(client: VarlatchClient, organization: string, project: string, item: string): Promise<boolean> {
  try {
    const revision = await client.getActiveContract(organization, project);
    const contract = revision.contract as unknown as { items?: { name: string; sensitive: boolean }[] } | undefined;
    return contract?.items?.find((i) => i.name === item)?.sensitive ?? true;
  } catch (err) {
    if (err instanceof VarlatchApiError && (err.status === 404 || err.status === 403)) return true;
    throw err;
  }
}

/** Why a write of a Secret's value through MCP is refused, naming the ways that keep the value out of the model. */
export function secretWriteRefusal(item: string): string {
  return (
    `${item} is a Secret, and its value is never written through MCP: the value would be in the model's context. ` +
    `Store it with \`varlatch --assisted values set ${item} --generate hex:32\` (a new random value), ` +
    `\`--from-file <path>\`, \`--stdin\`, or \`varlatch --assisted import <file>\`; or ask the human to run ` +
    `\`varlatch values set ${item}\` in their own terminal. Nothing was stored.`
  );
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

function errorResult(err: unknown): ToolResult {
  if (err instanceof VarlatchApiError) {
    return toolError(`varlatch API error ${err.status} (${err.code}, request ${err.requestId}): ${err.message}`);
  }
  return toolError(err instanceof Error ? err.message : String(err));
}

async function run(fn: () => Promise<unknown>): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (err) {
    return errorResult(err);
  }
}

export function createVarlatchMcpServer(options: VarlatchMcpOptions): McpServer {
  const { client, defaults = {}, allowWrites = false, version = "0.0.0" } = options;

  const server = new McpServer({ name: "varlatch", version });

  function required(name: keyof McpDefaults, override: string | undefined): string {
    const value = override ?? defaults[name];
    if (!value) {
      throw new Error(
        `No ${name} given and none resolved from context; pass the "${name}" argument or run varlatch mcp inside a varlatch repo / with --${name === "organization" ? "org" : name}.`,
      );
    }
    return value;
  }

  server.registerTool(
    "varlatch_whoami",
    {
      title: "Server and context info",
      description:
        "Show the varlatch server, resolved default organization/project/environment, and whether this MCP server was started with writes enabled. No tool ever returns a Secret's value.",
      inputSchema: {},
    },
    () =>
      run(async () => {
        const meta = await client.meta();
        return { server: client.server, meta, defaults, allowWrites, secretValues: "never returned or written through MCP" };
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
          "Set a non-secret configuration value in an environment. A Secret's value is refused (Secrets, and items " +
          "outside the Contract, never pass through MCP). Pass expectedVersionId for optimistic concurrency.",
        inputSchema: {
          ...envArg,
          item: z.string().describe("Item name from the contract, e.g. DATABASE_URL"),
          value: z.string(),
          expectedVersionId: z.string().optional(),
        },
      },
      async (args) => {
        try {
          const organization = required("organization", args.organization);
          const project = required("project", args.project);
          const environment = required("environment", args.environment);
          // Checked before anything is written; an unreadable Contract counts as a Secret.
          if (await isSecretItem(client, organization, project, args.item)) return toolError(secretWriteRefusal(args.item));
          return ok(
            await client.setValue(organization, project, environment, args.item, {
              value: args.value,
              ...(args.expectedVersionId !== undefined ? { expectedVersionId: args.expectedVersionId } : {}),
            }),
          );
        } catch (err) {
          return errorResult(err);
        }
      },
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

  return server;
}
