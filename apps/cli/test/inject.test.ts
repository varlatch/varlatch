// SPDX-License-Identifier: Apache-2.0
import { constants } from "node:os";
import { describe, expect, it } from "vitest";
import { buildEnv, omitProblem, runChild, signalExitCode, withheldItems } from "../src/inject.js";

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

  it("--omit: an omitted item is not injected, an inherited copy is removed, and it is not reported as withheld", () => {
    const omitted = new Set(["DATABASE_URL", "WITHHELD_SECRET"]);
    const env = buildEnv({ PATH: "/bin", DATABASE_URL: "shell", WITHHELD_SECRET: "stale" }, effective, omitted);
    expect(env.DATABASE_URL).toBeUndefined();
    expect(env.WITHHELD_SECRET).toBeUndefined();
    expect(env.PORT).toBe("3000");
    expect(env.PATH).toBe("/bin");
    expect(withheldItems(effective, omitted)).toEqual([]);
    // Control: without --omit, the delivered value replaces the shell's and the withheld one is inherited.
    expect(buildEnv({ DATABASE_URL: "shell" }, effective).DATABASE_URL).toBe("postgres://x");
  });

  it("--omit names must be known: a misspelled one is named, never ignored", () => {
    const known = new Set(["DATABASE_URL", "PORT"]);
    expect(omitProblem(["PORT", "DATABASE_URL"], known)).toBeNull();
    expect(omitProblem(["PORT", "DATABSE_URL", "ZZ", "ZZ"], known)).toBe(
      "--omit must name an item stored in this environment or in its Contract; not found: DATABSE_URL, ZZ",
    );
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

describe("the exit status of a command ended by a signal", () => {
  it("is 128 plus the signal's number, as a shell reports it", () => {
    expect(signalExitCode("SIGHUP")).toBe(129);
    expect(signalExitCode("SIGINT")).toBe(130);
    expect(signalExitCode("SIGQUIT")).toBe(131);
    expect(signalExitCode("SIGKILL")).toBe(137);
    expect(signalExitCode("SIGSEGV")).toBe(139);
    expect(signalExitCode("SIGPIPE")).toBe(141);
    expect(signalExitCode("SIGTERM")).toBe(143);
    for (const [name, number] of Object.entries(constants.signals)) expect(signalExitCode(name)).toBe(128 + number);
  });

  it("is 143 for a signal the platform does not number", () => {
    for (const name of ["SIGNOTASIGNAL", "", "toString", "__proto__"]) expect(signalExitCode(name)).toBe(143);
  });

  it.each(["SIGINT", "SIGTERM", "SIGHUP"] as const)("runChild reports a child killed by %s", async (signal) => {
    const script = `process.kill(process.pid, ${JSON.stringify(signal)}); setInterval(() => {}, 1000);`;
    expect(await runChild(process.execPath, ["-e", script], process.env)).toBe(128 + constants.signals[signal]);
  });
});
