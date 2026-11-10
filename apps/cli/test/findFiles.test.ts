// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { copyKindOf, findFilesExitCode, formatFindFilesHuman, walkForCopies, type FindFilesReport } from "../src/findFiles.js";
import { parseScanArgs, ScanUsageError } from "../src/scanCommand.js";

/**
 * `varlatch scan --find-files` (ADR-0054 Decision 8), the parts that need
 * no Git: the name patterns, the walk and its bounds, the exit status, and
 * the option rules. Git states and the CLI end to end are in scan-cli.test.ts.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-find-files-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

let count = 0;
function tree(files: string[]): string {
  const root = join(dir, `t${++count}`);
  for (const f of files) {
    mkdirSync(join(root, f, ".."), { recursive: true });
    writeFileSync(join(root, f), "VALUE=never-read\n");
  }
  mkdirSync(root, { recursive: true });
  return root;
}

describe("the name patterns", () => {
  it("are the ADR's: .env, .env.* except .env.example and .env.schema, *.pem, *.key, case-sensitive", () => {
    for (const name of [".env", ".env.local", ".env.production", ".env.development.local", ".env.sample", ".env.template", ".env.example.local"]) {
      expect(copyKindOf(name), name).toBe("dotenv");
    }
    for (const name of ["server.pem", "id.key", "tls.key", "chain.cert.pem"]) expect(copyKindOf(name), name).toBe("key");
    for (const name of [".env.example", ".env.schema", ".envrc", ".environment", "env", "x.env", ".ENV", "a.PEM", "id.KEY", "key.txt", "pem", "keys"]) {
      expect(copyKindOf(name), name).toBeNull();
    }
  });
});

describe("the walk", () => {
  it("lists matches in a stable order, skips .git and node_modules, and does not enter linked directories", async () => {
    const root = tree([".env", "b/.env.local", "a/z.pem", "a/.env.example", ".git/x.key", "node_modules/p/.env", "outside/secret.key", "deep/x/y/.env"]);
    symlinkSync(join(root, "outside"), join(root, "linked"));
    symlinkSync(join(dir, "nonexistent"), join(root, "dangling.key"));
    mkdirSync(join(root, "venv.pem")); // a directory with a matching name is entered, not listed
    const walk = await walkForCopies(".", root);
    expect(walk.files.map((f) => [f.path, f.kind, f.symlink])).toEqual([
      [".env", "dotenv", false],
      ["a/z.pem", "key", false],
      ["b/.env.local", "dotenv", false],
      ["dangling.key", "key", true],
      ["deep/x/y/.env", "dotenv", false],
      ["outside/secret.key", "key", false],
    ]);
    expect(walk.stopped).toBe(false);
    expect(walk.notSearched).toEqual([]);
  });

  it("takes a directory relative to the working directory, and refuses a file or a missing path", async () => {
    const root = tree(["sub/.env"]);
    expect((await walkForCopies("sub", root)).files.map((f) => f.path)).toEqual([".env"]);
    await expect(walkForCopies("sub/.env", root)).rejects.toThrow("--find-files takes a directory");
    await expect(walkForCopies("missing", root)).rejects.toThrow("cannot search missing: does not exist");
  });

  it("names the directories past the depth bound, and stops at the entry bound", async () => {
    const root = tree(["a/.env", "a/b/.env", "a/b/c/.env", "z/1", "z/2", "z/3"]);
    const shallow = await walkForCopies(".", root, { maxEntries: 1000, maxDepth: 1 });
    expect(shallow.files.map((f) => f.path)).toEqual(["a/.env"]);
    expect(shallow.notSearched).toEqual([{ path: "a/b/", reason: "below the depth bound of 1 directory levels" }]);

    const few = await walkForCopies(".", root, { maxEntries: 3, maxDepth: 20 });
    expect(few.stopped).toBe(true);
    expect(few.entriesChecked).toBe(3);
    const report: FindFilesReport = { root, files: [], notSearched: [], entriesChecked: 3, stopped: true };
    expect(findFilesExitCode(report)).toBe(2);
    expect(formatFindFilesHuman(report, { maxEntries: 3, maxDepth: 20 }).join("\n")).toContain("The search stopped after 3 entries");
  });
});

describe("exit status and output", () => {
  const base: FindFilesReport = { root: "/r", files: [], notSearched: [], entriesChecked: 10, stopped: false };
  it("is 0 when nothing is found, 1 when anything is, 2 when nothing is but the search was incomplete", () => {
    expect(findFilesExitCode(base)).toBe(0);
    const found = { ...base, files: [{ path: ".env", kind: "dotenv" as const, symlink: false, git: "ignored" as const }] };
    expect(findFilesExitCode(found)).toBe(1);
    expect(findFilesExitCode({ ...found, stopped: true })).toBe(1);
    expect(findFilesExitCode({ ...base, notSearched: [{ path: "x/", reason: "directory unreadable (EACCES)" }] })).toBe(2);
  });

  it("suggests import for dotenv files and values set for key files, and rotation for tracked ones", () => {
    const lines = formatFindFilesHuman({
      ...base,
      files: [
        { path: ".env", kind: "dotenv", symlink: false, git: "tracked" },
        { path: "certs/tls.key", kind: "key", symlink: true, git: "not-ignored" },
      ],
    }).join("\n");
    expect(lines).toContain("  .env: tracked by Git, so it is in the repository's history");
    expect(lines).toContain("  certs/tls.key: a symbolic link, not followed; not ignored by Git, so a commit could add it");
    expect(lines).toContain("varlatch scan: 2 file(s) look like copies of secrets (1 tracked by Git, 1 not ignored)");
    expect(lines).toContain("varlatch import <file> --delete-source");
    expect(lines).toContain("varlatch values set <ITEM> --from-file <file>");
    expect(lines).toContain("rotate the secrets it holds");
  });
});

describe("options", () => {
  it("take at most one directory and --json, and nothing of the value scan", () => {
    expect(parseScanArgs(["--find-files"])).toMatchObject({ findFiles: true, paths: [] });
    expect(parseScanArgs(["--find-files", "src", "--json"])).toMatchObject({ findFiles: true, paths: ["src"], json: true });
    for (const args of [
      ["--find-files", "--staged"],
      ["--find-files", "a", "b"],
      ["--find-files", "-e", "production"],
      ["--find-files", "--install-hook"],
      ["--find-files", "--baseline", "b.json"],
      ["--find-files", "--write-baseline"],
      ["--find-files", "--max-file-size", "1K"],
      ["--find-files", "--server", "https://varlatch.example.com"],
    ]) {
      expect(() => parseScanArgs(args), args.join(" ")).toThrow(ScanUsageError);
    }
  });
});
