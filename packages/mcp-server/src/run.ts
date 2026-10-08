// SPDX-License-Identifier: Apache-2.0
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { AGENT_RUN_ENV, ContextError, agentRunOf, loadToken, resolveContext } from "@varlatch/context";
import { VarlatchClient } from "@varlatch/sdk";
import { createVarlatchMcpServer, type McpDefaults } from "./server.js";

/**
 * Starting the MCP server (ADR-0043 Decision 9). `varlatch mcp` and the old
 * `varlatch-mcp` entry point both come here, so neither can start a server
 * with fewer protections than the other:
 *
 * - there is no disclosure tool, and `--allow-disclose` (or
 *   VARLATCH_MCP_ALLOW_DISCLOSE) is refused rather than ignored;
 * - writes need `--allow-writes`, and a Secret's value is never written;
 * - inside an agent-safe run the credential is the agent-run one or none,
 *   never the operator's stored credential (ADR-0043 Decision 5), and writes
 *   are refused, since that credential is read-only.
 */

export const MCP_USAGE = `Usage: varlatch mcp [--server <url>] [--org <slug>] [--project <slug>] [--environment <name>] [--allow-writes]

Runs a Model Context Protocol server over stdio for MCP hosts without a shell.
Defaults for org/project/environment come from the repository context of the
working directory (varlatch.toml, .varlatch/local.json); flags override.
Authentication uses VARLATCH_TOKEN or the stored credential for the server;
inside an agent-safe run, only the run's agent-run credential.

Read tools only by default. --allow-writes (or VARLATCH_MCP_ALLOW_WRITES=1)
adds varlatch_set_value, which refuses a Secret's value, and
varlatch_delete_value. No tool returns a Secret's value.`;

/** Statuses as the CLI uses them (ADR-0043 Decision 10). */
export const MCP_EXIT = { failure: 1, usage: 64, denied: 77 } as const;

export class McpStartError extends Error {
  override name = "McpStartError";
  readonly exitCode: number;
  constructor(message: string, exitCode: number) {
    super(message);
    this.exitCode = exitCode;
  }
}

export interface McpArgs {
  server?: string;
  organization?: string;
  project?: string;
  environment?: string;
  allowWrites: boolean;
  help: boolean;
}

const DISCLOSE_REFUSAL =
  "secret disclosure through MCP has been removed: no MCP host can keep a tool result out of the model's " +
  "context. Remove --allow-disclose (and VARLATCH_MCP_ALLOW_DISCLOSE). An agent uses a Secret through " +
  "varlatch run, or through the Broker with varlatch request inside an agent-safe run.";

export function parseMcpArgs(argv: string[], env: NodeJS.ProcessEnv): McpArgs {
  if (env.VARLATCH_MCP_ALLOW_DISCLOSE !== undefined && env.VARLATCH_MCP_ALLOW_DISCLOSE !== "" && env.VARLATCH_MCP_ALLOW_DISCLOSE !== "0") {
    throw new McpStartError(DISCLOSE_REFUSAL, MCP_EXIT.usage);
  }
  const args: McpArgs = { allowWrites: env.VARLATCH_MCP_ALLOW_WRITES === "1", help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const next = (): string => {
      const value = argv[++i];
      if (value === undefined) throw new McpStartError(`${arg} needs a value\n${MCP_USAGE}`, MCP_EXIT.usage);
      return value;
    };
    switch (arg) {
      case "--server":
        args.server = next();
        break;
      case "--org":
      case "--organization":
        args.organization = next();
        break;
      case "--project":
        args.project = next();
        break;
      case "--environment":
      case "--env":
      case "-e":
        args.environment = next();
        break;
      case "--allow-writes":
        args.allowWrites = true;
        break;
      case "--allow-disclose":
        throw new McpStartError(DISCLOSE_REFUSAL, MCP_EXIT.usage);
      case "--help":
      case "-h":
        args.help = true;
        break;
      default:
        throw new McpStartError(`unknown option ${arg}\n${MCP_USAGE}`, MCP_EXIT.usage);
    }
  }
  return args;
}

/**
 * The MCP server's User-Agent on every request to varlatchd:
 * `varlatch-mcp/<version> (<platform>; <arch>)`. varlatchd records its
 * summary ("varlatch MCP 0.16.0 on Linux") as the client of each audit event
 * a request records, so the audit log tells a model host's tool calls from
 * the CLI, though both use the same credential. What the server says about
 * itself: never verified, never an authorization input.
 */
export function mcpUserAgent(version: string, platform: string = process.platform, arch: string = process.arch): string {
  return `varlatch-mcp/${version} (${platform}; ${arch})`;
}

export interface PreparedServer {
  client: VarlatchClient;
  defaults: McpDefaults;
  allowWrites: boolean;
}

/**
 * Everything short of connecting: the server, the defaults, and the client
 * with its credential, identified by `version` in its User-Agent. Throws
 * McpStartError with the status to exit with.
 */
export function prepareMcpServer(args: McpArgs, env: NodeJS.ProcessEnv, cwd: string, version?: string): PreparedServer {
  const agentRun = agentRunOf(env);
  if (agentRun && args.allowWrites) {
    throw new McpStartError(
      `this runs inside agent-safe run ${agentRun}, whose only credential is read-only; --allow-writes does not apply here`,
      MCP_EXIT.usage,
    );
  }
  const defaults: McpDefaults = {};
  let server = args.server ?? env.VARLATCH_SERVER;
  try {
    const ctx = resolveContext({
      cwd,
      env,
      ...(args.environment !== undefined ? { environment: args.environment } : {}),
      ...(args.server !== undefined ? { server: args.server } : {}),
    });
    server ??= ctx.server;
    defaults.organization = args.organization ?? ctx.organization;
    defaults.project = args.project ?? ctx.project;
    defaults.environment = args.environment ?? ctx.environment;
  } catch (err) {
    if (!(err instanceof ContextError)) throw err;
    // Not inside a repository: flags and the environment only.
    if (args.organization !== undefined) defaults.organization = args.organization;
    if (args.project !== undefined) defaults.project = args.project;
    if (args.environment !== undefined) defaults.environment = args.environment;
  }
  if (!server) {
    throw new McpStartError("no server configured; pass --server, set VARLATCH_SERVER, or run inside a varlatch repository", MCP_EXIT.usage);
  }
  // Inside an agent-safe run loadToken never reads the operator's default
  // store, whether or not VARLATCH_CONFIG_DIR is set (ADR-0043 Decision 5).
  const token = loadToken(server, env);
  if (!token && agentRun) {
    throw new McpStartError(
      `not authenticated to ${server}: this runs inside agent-safe run ${agentRun}, which gives the Agent no ` +
        `Varlatch credential and never uses the operator's (${AGENT_RUN_ENV} is set). For read access to ` +
        "configuration metadata, the operator relaunches the run with --agent-metadata.",
      MCP_EXIT.denied,
    );
  }
  if (!token) {
    throw new McpStartError(`not authenticated to ${server}; run \`varlatch login\` or set VARLATCH_TOKEN`, MCP_EXIT.denied);
  }
  return {
    client: new VarlatchClient({ server, token, ...(version ? { userAgent: mcpUserAgent(version) } : {}) }),
    defaults,
    allowWrites: args.allowWrites,
  };
}

/**
 * Parse, prepare, and serve over stdio until the host closes the stream.
 * Returns the status to exit with when the server did not start; it never
 * returns while serving.
 */
export async function runMcpServer(
  argv: string[],
  opts: { env: NodeJS.ProcessEnv; cwd: string; version: string; name: string; err: (line: string) => void; out: (text: string) => void },
): Promise<number | null> {
  let prepared: PreparedServer;
  try {
    const args = parseMcpArgs(argv, opts.env);
    if (args.help) {
      opts.out(`${MCP_USAGE}\n`);
      return 0;
    }
    prepared = prepareMcpServer(args, opts.env, opts.cwd, opts.version);
  } catch (err) {
    if (err instanceof McpStartError) {
      opts.err(`${opts.name}: ${err.message}`);
      return err.exitCode;
    }
    throw err;
  }
  const mcp = createVarlatchMcpServer({ ...prepared, version: opts.version });
  await mcp.connect(new StdioServerTransport());
  return null;
}
