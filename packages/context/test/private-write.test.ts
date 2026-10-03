// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * The credential store and the pending sign-in state are replaced through a
 * temporary file. writeSync may write fewer bytes than asked without an
 * error: the file must be complete before it is renamed over the old one.
 */

const plan = vi.hoisted(() => ({ mode: "normal" as "normal" | "short-then-ok" | "short-then-enospc" | "no-progress", calls: 0 }));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    writeSync: (fd: number, buffer: Buffer, offset = 0, length = buffer.length - offset) => {
      plan.calls++;
      if (plan.mode === "normal") return actual.writeSync(fd, buffer, offset, length);
      if (plan.mode === "no-progress") return 0;
      if (plan.calls === 1) return actual.writeSync(fd, buffer, offset, Math.min(10, length)); // a short write, no error
      if (plan.mode === "short-then-enospc") throw Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" });
      return actual.writeSync(fd, buffer, offset, length);
    },
  };
});

const { loadCredential, loadPendingSignIn, saveCredential, savePendingSignIn, credentialsPath, pendingSignInsPath } = await import("../src/index.js");

function env(): NodeJS.ProcessEnv {
  return { VARLATCH_CONFIG_DIR: join(mkdtempSync(join(tmpdir(), "varlatch-write-")), "varlatch") };
}
const pending = (server: string, userCode: string) => ({
  server, deviceCode: "device-code", userCode, verificationUri: "https://v.example/device",
  expiresAt: "2030-01-01T00:00:00.000Z", interval: 5, startedAt: "2029-12-31T23:50:00.000Z",
});
const stores = [
  {
    name: "the credential store",
    path: credentialsPath,
    save: (e: NodeJS.ProcessEnv, n: number) => saveCredential("https://v.example", { token: `vlt_cli_${"x".repeat(40)}${n}` }, e),
    read: (e: NodeJS.ProcessEnv) => loadCredential("https://v.example", e)?.token,
  },
  {
    name: "the pending sign-in state",
    path: pendingSignInsPath,
    save: (e: NodeJS.ProcessEnv, n: number) => savePendingSignIn(pending("https://v.example", `WDJB-MJH${n}`), e),
    read: (e: NodeJS.ProcessEnv) => loadPendingSignIn("https://v.example", e)?.userCode,
  },
];

afterEach(() => {
  plan.mode = "normal";
  plan.calls = 0;
});

describe.each(stores)("$name", (store) => {
  it("completes a short write and stores exactly the new, valid JSON", () => {
    const e = env();
    plan.mode = "short-then-ok";
    store.save(e, 1);
    expect(plan.calls).toBeGreaterThan(1);
    const text = readFileSync(store.path(e), "utf8");
    expect(() => JSON.parse(text)).not.toThrow();
    expect(text.endsWith("}\n")).toBe(true);
    expect(store.read(e)).toMatch(/1$/);
  });

  for (const mode of ["short-then-enospc", "no-progress"] as const) {
    it(`fails on ${mode === "no-progress" ? "a write that makes no progress" : "a short write followed by ENOSPC"}, keeping the old file byte for byte`, () => {
      const e = env();
      store.save(e, 1);
      const before = readFileSync(store.path(e));
      plan.mode = mode;
      plan.calls = 0;
      expect(() => store.save(e, 2)).toThrow(mode === "no-progress" ? /bytes written/ : /ENOSPC/);
      expect(readFileSync(store.path(e)).equals(before)).toBe(true);
      expect(readdirSync(join(store.path(e), "..")).filter((f) => f.endsWith(".tmp"))).toEqual([]);
      plan.mode = "normal";
      expect(store.read(e)).toMatch(/1$/);
    });
  }
});
