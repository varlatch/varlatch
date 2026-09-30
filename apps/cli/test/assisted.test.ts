// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { AGENT_MARKERS, describeAssisted, resolveAssisted, takeAssistedOption } from "../src/assisted.js";

/** Assisted mode's precedence (ADR-0043 Decision 3). */
describe("resolveAssisted", () => {
  it("is off with no option, no setting, and no marker", () => {
    expect(resolveAssisted(false, {})).toEqual({ on: false, source: null, marker: null });
  });

  it("the explicit option turns it on, and VARLATCH_ASSISTED=0 never overrides it", () => {
    expect(resolveAssisted(true, {})).toMatchObject({ on: true, source: "option" });
    expect(resolveAssisted(true, { VARLATCH_ASSISTED: "0" })).toMatchObject({ on: true, source: "option" });
    expect(resolveAssisted(true, { VARLATCH_ASSISTED: "0", CLAUDECODE: "1" })).toMatchObject({ on: true, source: "option" });
  });

  it("VARLATCH_ASSISTED=1 (or true) turns it on without a marker", () => {
    expect(resolveAssisted(false, { VARLATCH_ASSISTED: "1" })).toMatchObject({ on: true, source: "environment" });
    expect(resolveAssisted(false, { VARLATCH_ASSISTED: "true" })).toMatchObject({ on: true, source: "environment" });
  });

  it.each(AGENT_MARKERS)("the marker %s turns it on as a backstop", (marker) => {
    expect(resolveAssisted(false, { [marker]: "1" })).toEqual({ on: true, source: "marker", marker });
  });

  it("a marker that is empty or 0 is not a marker", () => {
    expect(resolveAssisted(false, { CLAUDECODE: "" }).on).toBe(false);
    expect(resolveAssisted(false, { AGENT: "0" }).on).toBe(false);
    expect(resolveAssisted(false, { AGENT: "goose" })).toMatchObject({ on: true, marker: "AGENT" });
  });

  it("VARLATCH_ASSISTED=0 turns marker detection off (the same marker without it turns the mode on)", () => {
    expect(resolveAssisted(false, { CLAUDECODE: "1" }).on).toBe(true);
    expect(resolveAssisted(false, { CLAUDECODE: "1", VARLATCH_ASSISTED: "0" }).on).toBe(false);
    expect(resolveAssisted(false, { CODEX_THREAD_ID: "t", VARLATCH_ASSISTED: "false" }).on).toBe(false);
  });

  it("describes its source by name only", () => {
    expect(describeAssisted(resolveAssisted(true, {}))).toBe("--assisted");
    expect(describeAssisted(resolveAssisted(false, { VARLATCH_ASSISTED: "1" }))).toBe("VARLATCH_ASSISTED=1");
    expect(describeAssisted(resolveAssisted(false, { GEMINI_CLI: "1" }))).toBe("GEMINI_CLI is set");
  });
});

describe("takeAssistedOption", () => {
  it("takes the option from anywhere before the command's `--`", () => {
    expect(takeAssistedOption(["--assisted", "run", "--", "node", "x.js"])).toEqual({ argv: ["run", "--", "node", "x.js"], given: true });
    expect(takeAssistedOption(["run", "--assisted", "-e", "dev", "--", "cmd"])).toEqual({ argv: ["run", "-e", "dev", "--", "cmd"], given: true });
    expect(takeAssistedOption(["values", "set", "X", "--generate", "hex:32", "--assisted"])).toMatchObject({ given: true });
  });

  it("never touches the command's own arguments after `--`", () => {
    expect(takeAssistedOption(["run", "--", "tool", "--assisted"])).toEqual({ argv: ["run", "--", "tool", "--assisted"], given: false });
  });

  it("reports absence", () => {
    expect(takeAssistedOption(["status", "--json"])).toEqual({ argv: ["status", "--json"], given: false });
  });
});
