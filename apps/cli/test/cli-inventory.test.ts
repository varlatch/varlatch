// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { MCP_USAGE } from "@varlatch/mcp-server/run";
import { describe, expect, it } from "vitest";
import { AGENT_MARKERS } from "../src/assisted.js";
import { REQUEST_USAGE } from "../src/request.js";
import { USAGE } from "../src/usage.js";
import { INVENTORY, extract } from "./cliInventory.js";

/**
 * The Go CLI's inventory (go/cmd/varlatch/testdata/cli-inventory.json;
 * internal docs/design/go-cli.md, decision 16) against the TypeScript CLI's
 * source, both ways: every command, option literal and environment
 * variable the source has is in the inventory with the files it appears in,
 * and the inventory names nothing the source does not have. The Go side
 * (TestInventoryCoverage) checks that what is built is covered.
 */

interface Inventory {
  commands: Record<string, { slice: string }>;
  options: Record<string, { of: string; commands?: string[]; sources: string[] }>;
  environment: Record<string, { slice: string; sources: string[] }>;
}

const inventory = JSON.parse(readFileSync(INVENTORY, "utf8")) as Inventory;
const source = extract(AGENT_MARKERS);

/** The commands whose usage entry names each option (usage.ts, request.ts, mcp-server's run.ts). */
function usageCommands(): Record<string, Set<string>> {
  const byOption: Record<string, Set<string>> = {};
  const note = (text: string, command: string) => {
    for (const m of text.matchAll(/(?<![\w-])(--?[a-zA-Z][a-zA-Z0-9-]*)/g)) (byOption[m[1] as string] ??= new Set()).add(command);
  };
  let current: string | null = null;
  for (const line of USAGE.split("\n")) {
    const start = /^ {2}varlatch (\S+)/.exec(line);
    if (start) current = start[1] as string;
    else if (!/^ {3,}\S/.test(line)) current = null;
    if (current && !current.startsWith("-")) note(line, current);
  }
  note(REQUEST_USAGE, "request");
  note(MCP_USAGE, "mcp");
  return byOption;
}

describe("the Go CLI's inventory", () => {
  it("lists exactly the commands main.ts dispatches", () => {
    expect(Object.keys(inventory.commands).sort()).toEqual([...source.commands].sort());
  });

  it("lists exactly the option literals of the source, with their files", () => {
    expect(Object.keys(inventory.options).sort()).toEqual(Object.keys(source.options).sort());
    for (const [name, files] of Object.entries(source.options)) expect([name, inventory.options[name]?.sources]).toEqual([name, files]);
  });

  it("gives each of the CLI's own options every command whose usage names it", () => {
    for (const [name, commands] of Object.entries(usageCommands())) {
      const entry = inventory.options[name];
      if (!entry || entry.of !== "varlatch" || entry.commands?.includes("*")) continue;
      for (const command of commands) expect([name, entry.commands?.includes(command)]).toEqual([name, true]);
    }
  });

  it("lists exactly the environment variables the source reads, with their files", () => {
    expect(Object.keys(inventory.environment).sort()).toEqual(Object.keys(source.environment).sort());
    for (const [name, files] of Object.entries(source.environment)) expect([name, inventory.environment[name]?.sources]).toEqual([name, files]);
  });
});
