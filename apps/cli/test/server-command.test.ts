// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultServer, saveToken, setDefaultServer } from "@varlatch/context";
import { ServerCommandError, noteDefaultServer, showServer, useServer } from "../src/serverCommand.js";

/**
 * `varlatch server` and the default server (ADR-0058 Decision 1): it shows
 * what a command here would use; `server use` only picks a server with a
 * stored credential; a sign-in sets the default only when none is set.
 */

function setup() {
  const env = { VARLATCH_CONFIG_DIR: mkdtempSync(join(tmpdir(), "varlatch-server-cmd-")) };
  const cwd = mkdtempSync(join(tmpdir(), "varlatch-server-cwd-"));
  const lines: string[] = [];
  const docs: Record<string, unknown>[] = [];
  return { env, cwd, lines, docs, text: { out: (l: string) => lines.push(l), json: null }, json: { out: (l: string) => lines.push(l), json: (d: Record<string, unknown>) => docs.push(d) } };
}

describe("varlatch server", () => {
  it("shows the server here, its source, the default, and the servers signed in to", () => {
    const t = setup();
    showServer(t.cwd, t.text, t.env);
    expect(t.lines).toEqual(["Server here: none", "Default server: none", "Signed in to: none"]);
    saveToken("https://a.example", "t", t.env);
    saveToken("https://b.example", "t", t.env);
    setDefaultServer("https://b.example", t.env);
    showServer(t.cwd, t.json, t.env);
    expect(t.docs).toEqual([
      { version: 1, server: "https://b.example", serverSource: "default", defaultServer: "https://b.example", signedIn: ["https://a.example", "https://b.example"] },
    ]);
  });

  it("inside a repository the repository's server is shown, whatever the default", () => {
    const t = setup();
    setDefaultServer("https://default.example", t.env);
    writeFileSync(join(t.cwd, "varlatch.toml"), 'server = "https://repo.example"\norganization = "acme"\nproject = "api"\n');
    showServer(t.cwd, t.text, t.env);
    expect(t.lines[0]).toBe("Server here: https://repo.example (from varlatch.toml)");
    expect(t.lines[1]).toBe("Default server: https://default.example");
  });

  it("server use takes only a server with a stored credential", () => {
    const t = setup();
    expect(() => useServer("https://nowhere.example", t.text, t.env)).toThrow(ServerCommandError);
    expect(() => useServer("not a url", t.text, t.env)).toThrow(/not a URL/);
    expect(defaultServer(t.env)).toBeNull();
    saveToken("https://a.example", "t", t.env);
    useServer("https://a.example/", t.text, t.env);
    expect(defaultServer(t.env)).toBe("https://a.example");
    expect(t.lines).toEqual(["Default server: https://a.example"]);
  });

  it("two servers on one origin with different paths stay two servers", () => {
    const t = setup();
    saveToken("https://host.example/team-a", "t", t.env);
    saveToken("https://host.example/team-b/", "t", t.env);
    useServer("https://host.example/team-b", t.text, t.env);
    expect(defaultServer(t.env)).toBe("https://host.example/team-b");
    useServer("https://host.example/team-a/", t.text, t.env);
    expect(defaultServer(t.env)).toBe("https://host.example/team-a");
    expect(() => useServer("https://host.example", t.text, t.env)).toThrow(/not signed in to https:\/\/host\.example\./);
  });

  it("a sign-in notes a new default once, and a failed write never fails it", () => {
    const t = setup();
    const err: string[] = [];
    noteDefaultServer("https://a.example", (l) => err.push(l), t.env);
    noteDefaultServer("https://b.example", (l) => err.push(l), t.env);
    expect(err).toEqual(["Default server: https://a.example, for commands outside a repository. Change it with: varlatch server use <url>"]);
    const blocked = { VARLATCH_CONFIG_DIR: join(t.env.VARLATCH_CONFIG_DIR, "settings.json", "nested") };
    writeFileSync(join(t.env.VARLATCH_CONFIG_DIR, "settings.json"), "{}");
    const errors: string[] = [];
    noteDefaultServer("https://c.example", (l) => errors.push(l), blocked);
    expect(errors[0]).toMatch(/^varlatch: the default server was not saved \(.+\); the sign-in is stored\.$/);
  });
});
