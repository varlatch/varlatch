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

  it("an alias is the same option: either name, once", () => {
    const aliased = { values: ["--environment"], aliases: { "-e": "--environment" }, positionals: 1 };
    expect(parseOptions(["x", "-e", "prod"], aliased).values.get("--environment")).toBe("prod");
    expect(parseOptions(["x", "--environment", "prod"], aliased).values.get("--environment")).toBe("prod");
    for (const args of [["-e", "a", "--environment", "b"], ["-e", "a", "-e", "a"], ["--environment", "a", "-e", "b"]]) {
      expect(() => parseOptions(args, aliased), args.join(" ")).toThrow(/--environment \(or -e\) given twice/);
    }
    expect(() => parseOptions(["-e"], aliased)).toThrow(/--environment needs a value/);
  });

  it("with onceBooleans, an option without a value given twice is refused too; without it, it stays accepted", () => {
    const once = { booleans: ["--strict"], onceBooleans: true };
    expect(parseOptions(["--strict"], once).booleans.has("--strict")).toBe(true);
    expect(() => parseOptions(["--strict", "--strict"], once)).toThrow(/--strict given twice/);
    expect(parseOptions(["--check", "--check"], spec).booleans.has("--check")).toBe(true);
  });

  it("with endOfOptions, -- makes the rest positional, so a value may begin with a dash", () => {
    const spec2 = { booleans: ["--stdin"], positionals: 2, endOfOptions: true };
    expect(parseOptions(["x", "--", "-5"], spec2).positionals).toEqual(["x", "-5"]);
    expect(parseOptions(["--", "--stdin"], spec2).booleans.has("--stdin")).toBe(false);
    expect(() => parseOptions(["x", "-5"], spec2)).toThrow(/unknown option -5 \(a value that begins with "-" goes after --\)/);
    expect(() => parseOptions(["x", "--", "a", "b"], spec2)).toThrow(/unexpected argument b/);
    // Without it, -- stays an unknown option (as above).
    expect(() => parseOptions(["--", "x"], { positionals: 1 })).toThrow(/unknown option --/);
  });
});
