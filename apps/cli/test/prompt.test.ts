// SPDX-License-Identifier: Apache-2.0
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { terminalPrompter } from "../src/prompt.js";

describe("terminalPrompter", () => {
  it("selects by number or the preselected option, confirms, and reads text with a default", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let shown = "";
    output.on("data", (d: Buffer) => (shown += d.toString()));
    const prompt = terminalPrompter(input, output);
    input.write("7\n2\n\nmaybe\ny\n\n");
    expect(await prompt.select("Pick:", ["a", "b"], 0)).toBe(1);
    expect(await prompt.select("Pick:", ["a", "b"], 1)).toBe(1);
    expect(await prompt.confirm("Sure?", false)).toBe(true);
    expect(await prompt.text("Name", "web")).toBe("web");
    prompt.close();
    expect(shown).toContain("Answer with a number from 1 to 2.");
    expect(shown).toContain("Answer y or n.");
    expect(shown).toContain("[2] b  (Enter)");
  });
});
