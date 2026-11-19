// SPDX-License-Identifier: Apache-2.0
import { readdirSync, readFileSync } from "node:fs";

/**
 * The CLI a process test runs (internal docs/design/go-cli.md, decision 3):
 * the TypeScript bundle the test built, or, when VARLATCH_TEST_CLI names
 * one, a Go `varlatch` binary, run as itself. go-cli-files.json lists the
 * test files that must pass against Go:
 *
 *   VARLATCH_TEST_CLI=/path/to/varlatch pnpm --filter @varlatch/cli exec vitest run $(node -p 'require("./test/go-cli-files.json").files.join(" ")')
 */
export function cliCommand(bundle: string, args: string[]): [string, string[]] {
  const go = process.env.VARLATCH_TEST_CLI;
  return go ? [go, args] : [process.execPath, [bundle, ...args]];
}

/**
 * The Go CLI's inventory: the slice that builds each command, and which
 * slices are built (go/cmd/varlatch/testdata/built/, one empty file per built
 * slice, so pull requests that build different slices never edit one line).
 */
const inventory = {
  ...(JSON.parse(readFileSync(new URL("../../../go/cmd/varlatch/testdata/cli-inventory.json", import.meta.url), "utf8")) as {
    commands: Record<string, { slice: string }>;
  }),
  built: readdirSync(new URL("../../../go/cmd/varlatch/testdata/built/", import.meta.url)),
};

/**
 * Whether the CLI under test is a Go binary that lacks one of `slices`
 * (internal docs/design/go-cli.md's slices, as "5.2"): a test of what a
 * later slice builds is skipped against Go with `it.skipIf(goLacks("5.2"))`.
 * The TypeScript bundle lacks nothing. A skip ends by itself: the slice's
 * pull request marks it built in the inventory, and the test runs.
 */
export function goLacks(...slices: string[]): boolean {
  return Boolean(process.env.VARLATCH_TEST_CLI) && slices.some((slice) => !inventory.built.includes(slice));
}

/** goLacks for the slices that build `commands` (the first word of each command line). */
export function goLacksCommand(...commands: string[]): boolean {
  return goLacks(...commands.map((command) => inventory.commands[command]?.slice ?? `an unknown command ${command}`));
}
