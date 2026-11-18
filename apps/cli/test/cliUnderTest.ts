// SPDX-License-Identifier: Apache-2.0

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
