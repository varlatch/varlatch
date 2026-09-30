// SPDX-License-Identifier: Apache-2.0

/**
 * Strict option parsing for commands that write files (ADR-0043 Decision
 * 10): an unknown option, a missing value, a repeated single-value option,
 * or an extra argument is a usage error, found before the command reads or
 * writes anything. A typo such as `--chek` must not run the command as if
 * the option were absent.
 */

export class OptionsError extends Error {
  override name = "OptionsError";
}

export interface OptionSpec {
  /** Options that take one value, given at most once. */
  values?: readonly string[];
  /** Options that take one value, repeatable. */
  lists?: readonly string[];
  /** Options without a value. */
  booleans?: readonly string[];
  /** How many positional arguments the command takes (default none). */
  positionals?: number;
}

export interface ParsedOptions {
  values: Map<string, string>;
  lists: Map<string, string[]>;
  booleans: Set<string>;
  positionals: string[];
}

export function parseOptions(args: readonly string[], spec: OptionSpec): ParsedOptions {
  const parsed: ParsedOptions = { values: new Map(), lists: new Map(), booleans: new Set(), positionals: [] };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (spec.booleans?.includes(arg)) {
      parsed.booleans.add(arg);
      continue;
    }
    const single = spec.values?.includes(arg) ?? false;
    if (single || spec.lists?.includes(arg)) {
      const value = args[++i];
      if (value === undefined || value.startsWith("-")) throw new OptionsError(`${arg} needs a value`);
      if (single) {
        if (parsed.values.has(arg)) throw new OptionsError(`${arg} given twice`);
        parsed.values.set(arg, value);
      } else {
        parsed.lists.set(arg, [...(parsed.lists.get(arg) ?? []), value]);
      }
      continue;
    }
    if (arg.startsWith("-")) throw new OptionsError(`unknown option ${arg}`);
    if (parsed.positionals.length >= (spec.positionals ?? 0)) throw new OptionsError(`unexpected argument ${arg}`);
    parsed.positionals.push(arg);
  }
  return parsed;
}
