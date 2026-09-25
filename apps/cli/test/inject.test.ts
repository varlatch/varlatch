// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { buildEnv, runChild, withheldItems } from "../src/inject.js";

const effective = {
  environmentId: "env_1",
  items: [
    { name: "DATABASE_URL", sensitive: true, source: "self" as const, value: "postgres://x" },
    { name: "PORT", sensitive: false, source: "parent" as const, value: "3000" },
    { name: "WITHHELD_SECRET", sensitive: true, source: "self" as const, value: null },
  ],
};

describe("environment injection", () => {
  it("injects authorized values over the base env and skips withheld ones", () => {
    const env = buildEnv({ PATH: "/bin", WITHHELD_SECRET: "stale" }, effective);
    expect(env.DATABASE_URL).toBe("postgres://x");
    expect(env.PORT).toBe("3000");
    expect(env.PATH).toBe("/bin");
    // Withheld values are not injected; the pre-existing value is untouched
    // (varlatch never fabricates or clears what it was not authorized to see).
    expect(env.WITHHELD_SECRET).toBe("stale");
    expect(withheldItems(effective)).toEqual(["WITHHELD_SECRET"]);
  });

  it("forwards the child's exit code", async () => {
    expect(await runChild("node", ["-e", "process.exit(0)"], process.env)).toBe(0);
    expect(await runChild("node", ["-e", "process.exit(3)"], process.env)).toBe(3);
  });

  it("child sees injected variables", async () => {
    const env = buildEnv(process.env, effective);
    const code = await runChild(
      "node",
      ["-e", "process.exit(process.env.DATABASE_URL === 'postgres://x' ? 0 : 1)"],
      env,
    );
    expect(code).toBe(0);
  });
});
