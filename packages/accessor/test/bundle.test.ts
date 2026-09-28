// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
// @ts-expect-error: a plain ES module script without type declarations
import { buildRuntimeSource } from "../scripts/bundle.mjs";

describe("the embedded runtime", () => {
  it("is reproducible: building it again from the sources gives the same bytes", async () => {
    const { ACCESSOR_RUNTIME_SOURCE } = (await import(new URL("../dist/embedded.js", import.meta.url).href)) as {
      ACCESSOR_RUNTIME_SOURCE: string;
    };
    const again = (await buildRuntimeSource()) as string;
    expect(again).toBe(ACCESSOR_RUNTIME_SOURCE);
    expect(await buildRuntimeSource()).toBe(again);
  });

  it("is plain ASCII JavaScript that loads nothing and names no machine paths", async () => {
    const source = (await buildRuntimeSource()) as string;
    expect(source).toMatch(/^[\x09\x0a\x20-\x7e]*$/);
    expect(source).not.toMatch(/\brequire\(|\bimport\(|\bimport\s|process\.env\s*\[[^\]]*\]\s*=/);
    expect(source).not.toContain("/home/");
    expect(source).not.toContain("node_modules");
  });
});
