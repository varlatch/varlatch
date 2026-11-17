// SPDX-License-Identifier: Apache-2.0
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * What the CLI inventory (internal docs/design/go-cli.md, decision 16) is
 * derived from: the TypeScript CLI's own source. `extract()` reads every
 * non-test source file of apps/cli and the packages it bundles that hold
 * commands, options or environment variables, and lists
 *
 * - commands: the top-level `case "<name>":` of main.ts's dispatch;
 * - options: every string literal that is an option (`"--name"`, `"-x"`),
 *   with the files it appears in. Some belong to other programs (the
 *   guardrail hook reads ripgrep, grep, git and jq command lines; the host
 *   commands run docker compose and git), which the inventory says;
 * - environment variables: every `env.NAME`, `env["NAME"]`, a string
 *   literal with a known prefix (VARLATCH_, ACTIONS_, GITHUB_, GH_, XDG_,
 *   NODE_), and the agent markers of assisted.ts.
 *
 * cli-inventory.test.ts fails when the inventory and this disagree, either
 * way.
 */

export const REPO = fileURLToPath(new URL("../../../", import.meta.url));
export const INVENTORY = join(REPO, "go/cmd/varlatch/testdata/cli-inventory.json");

const SOURCE_DIRS = [
  "apps/cli/src",
  "packages/context/src",
  "packages/mcp-server/src",
  "packages/matcher/src",
  "packages/env-schema/src",
  "packages/sdk/src",
];

export function sourceFiles(): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(join(REPO, dir)).sort()) {
      const path = `${dir}/${name}`;
      if (statSync(join(REPO, path)).isDirectory()) walk(path);
      else if (path.endsWith(".ts") && !path.endsWith(".test.ts") && !path.endsWith(".generated.ts")) files.push(path);
    }
  };
  for (const dir of SOURCE_DIRS) walk(dir);
  return files;
}

export interface Extracted {
  commands: string[];
  options: Record<string, string[]>;
  environment: Record<string, string[]>;
}

const add = (map: Record<string, string[]>, key: string, file: string): void => {
  const list = (map[key] ??= []);
  if (!list.includes(file)) list.push(file);
};

export function extract(agentMarkers: readonly string[]): Extracted {
  const options: Record<string, string[]> = {};
  const environment: Record<string, string[]> = {};
  for (const file of sourceFiles()) {
    const text = readFileSync(join(REPO, file), "utf8");
    for (const m of text.matchAll(/["'`](--?[a-zA-Z][a-zA-Z0-9-]*)["'`]/g)) add(options, m[1] as string, file);
    for (const m of text.matchAll(/\benv\??\.([A-Z][A-Z0-9_]+)\b/g)) add(environment, m[1] as string, file);
    for (const m of text.matchAll(/\benv\[["']([A-Z][A-Z0-9_]+)["']\]/g)) add(environment, m[1] as string, file);
    for (const m of text.matchAll(/["']((?:VARLATCH|ACTIONS|GITHUB|GH|XDG|NODE)_[A-Z0-9_]+)["']/g)) add(environment, m[1] as string, file);
  }
  for (const marker of agentMarkers) add(environment, marker, "apps/cli/src/assisted.ts");
  // The dispatch: main()'s own switch, whose cases sit six spaces in.
  const source = readFileSync(join(REPO, "apps/cli/src/main.ts"), "utf8");
  const main = source.slice(source.indexOf("async function main(): Promise<void> {"));
  const commands = [...main.matchAll(/^ {6}case "([^"]+)":/gm)].map((m) => m[1] as string);
  const sorted = (map: Record<string, string[]>) =>
    Object.fromEntries(Object.keys(map).sort().map((k) => [k, [...(map[k] as string[])].sort()]));
  return { commands, options: sorted(options), environment: sorted(environment) };
}
