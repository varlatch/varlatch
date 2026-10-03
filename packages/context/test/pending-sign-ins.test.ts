// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ContextError,
  deletePendingSignIn,
  loadPendingSignIn,
  pendingSignInsPath,
  savePendingSignIn,
  serverKey,
  type PendingSignIn,
} from "../src/index.js";

/** The private state of `varlatch login --start` (design notes "Device-authorization sign-in", Q5). */

const entry = (server: string, userCode = "WDJB-MJHT"): PendingSignIn => ({
  server,
  deviceCode: "device-code-canary",
  userCode,
  verificationUri: "https://varlatch.example.com/device",
  expiresAt: "2030-01-01T00:00:00.000Z",
  interval: 5,
  startedAt: "2029-12-31T23:50:00.000Z",
});

function configEnv(): NodeJS.ProcessEnv {
  return { VARLATCH_CONFIG_DIR: join(mkdtempSync(join(tmpdir(), "varlatch-pending-")), "varlatch") };
}

describe("pending sign-in state", () => {
  it("keys entries by the normalized server URL: scheme, host, port, no trailing slash", () => {
    expect(serverKey("https://Varlatch.Example.com/")).toBe("https://varlatch.example.com");
    expect(serverKey("https://varlatch.example.com:443")).toBe("https://varlatch.example.com");
    expect(serverKey("http://127.0.0.1:8686//")).toBe("http://127.0.0.1:8686");
    expect(serverKey("https://example.com/varlatch/")).toBe("https://example.com/varlatch");
    const env = configEnv();
    savePendingSignIn(entry("https://Varlatch.example.com/"), env);
    expect(loadPendingSignIn("https://varlatch.example.com", env)?.deviceCode).toBe("device-code-canary");
    // Another server is another entry.
    expect(loadPendingSignIn("https://other.example.com", env)).toBeNull();
  });

  it("writes a 0600 file in a 0700 directory, creating or tightening the directory, with no temporary file left", () => {
    const env = configEnv();
    mkdirSync(env.VARLATCH_CONFIG_DIR!, { recursive: true, mode: 0o755 });
    chmodSync(env.VARLATCH_CONFIG_DIR!, 0o755);
    savePendingSignIn(entry("https://a.example.com"), env);
    expect(statSync(pendingSignInsPath(env)).mode & 0o777).toBe(0o600);
    expect(statSync(env.VARLATCH_CONFIG_DIR!).mode & 0o777).toBe(0o700);
    expect(readdirSync(env.VARLATCH_CONFIG_DIR!)).toEqual(["pending-sign-ins.json"]);
  });

  it("replaces a server's entry by renaming a new file into place, returning the replaced entry", () => {
    const env = configEnv();
    savePendingSignIn(entry("https://a.example.com"), env);
    savePendingSignIn(entry("https://b.example.com"), env);
    const inode = statSync(pendingSignInsPath(env)).ino;
    const replaced = savePendingSignIn(entry("https://a.example.com/", "BCDF-GHJK"), env);
    expect(replaced?.userCode).toBe("WDJB-MJHT");
    expect(statSync(pendingSignInsPath(env)).ino).not.toBe(inode);
    const file = JSON.parse(readFileSync(pendingSignInsPath(env), "utf8")) as { servers: Record<string, PendingSignIn> };
    expect(Object.keys(file.servers).sort()).toEqual(["https://a.example.com", "https://b.example.com"]);
    expect(file.servers["https://a.example.com"]!.userCode).toBe("BCDF-GHJK");
  });

  it("removes the file with its last entry", () => {
    const env = configEnv();
    savePendingSignIn(entry("https://a.example.com"), env);
    deletePendingSignIn("https://a.example.com/", env);
    expect(existsSync(pendingSignInsPath(env))).toBe(false);
  });

  it("is never read or written inside an agent-safe run, whatever VARLATCH_CONFIG_DIR says", () => {
    const env = configEnv();
    savePendingSignIn(entry("https://a.example.com"), env);
    for (const runEnv of [{ ...env, VARLATCH_AGENT_RUN: "run_x" }, { VARLATCH_AGENT_RUN: "run_x", HOME: tmpdir() }]) {
      expect(() => loadPendingSignIn("https://a.example.com", runEnv)).toThrow(ContextError);
      expect(() => savePendingSignIn(entry("https://a.example.com"), runEnv)).toThrow(ContextError);
      expect(() => deletePendingSignIn("https://a.example.com", runEnv)).toThrow(ContextError);
    }
    // Control: outside the run, the entry is still there, unchanged.
    expect(loadPendingSignIn("https://a.example.com", env)?.userCode).toBe("WDJB-MJHT");
  });
});
