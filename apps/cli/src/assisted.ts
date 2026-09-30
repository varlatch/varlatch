// SPDX-License-Identifier: Apache-2.0

/**
 * Assisted mode (ADR-0043 Decision 3): a coding agent is driving the CLI
 * with the human's own credential (Assisted Operation). It changes client
 * behaviour only, never authorization: `varlatch run` masks what it can and
 * refuses what it cannot (Decision 4), and a Secret's value is never taken
 * from the command line (Decision 2). The server never sees it.
 *
 * The documented flow turns it on explicitly with the global `--assisted`
 * option (or VARLATCH_ASSISTED=1), because many coding agents start a fresh
 * shell for every command. The markers coding agents set in their shells are
 * a backstop for an agent that drops the option; an agent that sets none is
 * covered only while it follows the documented flow.
 */

export const ASSISTED_OPTION = "--assisted";
export const ASSISTED_ENV = "VARLATCH_ASSISTED";

/**
 * Variables coding agents set in the shells they start. Data, kept with the
 * compatibility survey (internal docs/design/coding-agents.md); a marker is a
 * hint, trivially set, unset, or missing.
 */
export const AGENT_MARKERS: readonly string[] = [
  "CLAUDECODE", // Claude Code
  "CODEX_THREAD_ID", // Codex (CODEX_SANDBOX is set only under macOS Seatbelt)
  "CURSOR_AGENT", // Cursor
  "COPILOT_CLI", // GitHub Copilot CLI
  "COPILOT_AGENT", // GitHub Copilot in VS Code
  "GEMINI_CLI", // Gemini CLI
  "OPENCODE", // OpenCode
  "AGENT", // proposed convention (agents.md issue 136): OpenCode, Goose
  "AI_AGENT", // @vercel/detect-agent's proposal
];

export type AssistedSource = "option" | "environment" | "marker";

export interface AssistedMode {
  on: boolean;
  /** What turned it on. */
  source: AssistedSource | null;
  /** The marker that turned it on, when a marker did. */
  marker: string | null;
}

const ON = new Set(["1", "true"]);
const OFF = new Set(["0", "false"]);

/**
 * Whether this invocation is in assisted mode, in precedence order: the
 * explicit option; VARLATCH_ASSISTED=1; a coding agent's marker, unless
 * VARLATCH_ASSISTED=0 turned marker detection off. VARLATCH_ASSISTED=0 never
 * overrides the explicit option.
 */
export function resolveAssisted(optionGiven: boolean, env: NodeJS.ProcessEnv): AssistedMode {
  if (optionGiven) return { on: true, source: "option", marker: null };
  const setting = env[ASSISTED_ENV]?.trim().toLowerCase();
  if (setting !== undefined && ON.has(setting)) return { on: true, source: "environment", marker: null };
  if (setting !== undefined && OFF.has(setting)) return { on: false, source: null, marker: null };
  for (const marker of AGENT_MARKERS) {
    const value = env[marker]?.trim().toLowerCase();
    if (value && !OFF.has(value)) return { on: true, source: "marker", marker };
  }
  return { on: false, source: null, marker: null };
}

/**
 * Remove the global option from the CLI's own arguments. Only arguments
 * before a `--` separator are the CLI's: everything after it belongs to the
 * command `varlatch run` starts and is never touched.
 */
export function takeAssistedOption(argv: string[]): { argv: string[]; given: boolean } {
  const separator = argv.indexOf("--");
  const own = separator < 0 ? argv : argv.slice(0, separator);
  const rest = separator < 0 ? [] : argv.slice(separator);
  const kept = own.filter((arg) => arg !== ASSISTED_OPTION);
  return { argv: [...kept, ...rest], given: kept.length !== own.length };
}

/** How the run describes what turned assisted mode on: names only. */
export function describeAssisted(mode: AssistedMode): string {
  switch (mode.source) {
    case "option":
      return "--assisted";
    case "environment":
      return `${ASSISTED_ENV}=1`;
    case "marker":
      return `${mode.marker} is set`;
    default:
      return "off";
  }
}
