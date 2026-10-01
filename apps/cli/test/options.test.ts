// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { OptionsError, parseOptions } from "../src/options.js";

describe("parseOptions", () => {
  const spec = { values: ["--scope"], lists: ["--agent"], booleans: ["--check"], positionals: 1 };

  it("takes the options the spec names", () => {
    const parsed = parseOptions(["topic", "--scope", "user", "--agent", "a", "--check", "--agent", "b"], spec);
    expect(parsed.positionals).toEqual(["topic"]);
    expect(parsed.values.get("--scope")).toBe("user");
    expect(parsed.lists.get("--agent")).toEqual(["a", "b"]);
    expect(parsed.booleans.has("--check")).toBe(true);
  });

  it("refuses anything else", () => {
    const cases: [string[], RegExp][] = [
      [["--chek"], /unknown option --chek/],
      [["--check=1"], /unknown option --check=1/],
      [["--scope"], /--scope needs a value/],
      [["--scope", "--check"], /--scope needs a value/],
      [["--agent"], /--agent needs a value/],
      [["--scope", "a", "--scope", "b"], /--scope given twice/],
      [["one", "two"], /unexpected argument two/],
      [["--", "x"], /unknown option --/],
    ];
    for (const [args, message] of cases) expect(() => parseOptions(args, spec), args.join(" ")).toThrow(message);
    expect(() => parseOptions(["x"], {})).toThrow(OptionsError);
  });
});
