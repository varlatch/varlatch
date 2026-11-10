// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  copyKindOf,
  displayBytes,
  findFilesExitCode,
  findFilesJson,
  formatFindFilesHuman,
  walkForCopies,
  type FindFilesReport,
} from "../src/findFiles.js";
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
    expect(walk.files.map((f) => [f.path.toString(), f.kind, f.symlink])).toEqual([
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
    expect((await walkForCopies("sub", root)).files.map((f) => f.path.toString())).toEqual([".env"]);
    await expect(walkForCopies("sub/.env", root)).rejects.toThrow("--find-files takes a directory");
    await expect(walkForCopies("missing", root)).rejects.toThrow("cannot search missing: does not exist");
  });

  it("names the directories past the depth bound, and stops at the entry bound", async () => {
    const root = tree(["a/.env", "a/b/.env", "a/b/c/.env", "z/1", "z/2", "z/3"]);
    const shallow = await walkForCopies(".", root, { maxEntries: 1000, maxDepth: 1 });
    expect(shallow.files.map((f) => f.path.toString())).toEqual(["a/.env"]);
    expect(shallow.notSearched.map((n) => [n.path.toString(), n.reason])).toEqual([["a/b/", "below the depth bound of 1 directory levels"]]);

    // The bound is enforced while a directory is read: no more entries than that are held.
    const wide = tree(Array.from({ length: 50 }, (_, i) => `f${i}.key`));
    const few = await walkForCopies(".", wide, { maxEntries: 3, maxDepth: 20 });
    expect(few.stopped).toBe(true);
    expect(few.entriesChecked).toBe(3);
    expect(few.files).toHaveLength(3);
    const exact = await walkForCopies(".", wide, { maxEntries: 50, maxDepth: 20 });
    expect([exact.stopped, exact.entriesChecked, exact.files.length]).toEqual([false, 50, 50]);
    const report: FindFilesReport = { root: Buffer.from(root), files: [], notSearched: [], entriesChecked: 3, stopped: true };
    expect(findFilesExitCode(report)).toBe(2);
    expect(formatFindFilesHuman(report, { maxEntries: 3, maxDepth: 20 }).join("\n")).toContain("The search stopped after 3 entries");
  });
});

describe("exit status and output", () => {
  const base: FindFilesReport = { root: Buffer.from("/r"), files: [], notSearched: [], entriesChecked: 10, stopped: false };
  it("is 0 when nothing is found, 1 when anything is, 2 when nothing is but the search was incomplete", () => {
    expect(findFilesExitCode(base)).toBe(0);
    const found = { ...base, files: [{ path: Buffer.from(".env"), kind: "dotenv" as const, symlink: false, git: "ignored" as const }] };
    expect(findFilesExitCode(found)).toBe(1);
    expect(findFilesExitCode({ ...found, stopped: true })).toBe(1);
    expect(findFilesExitCode({ ...base, notSearched: [{ path: Buffer.from("x/"), reason: "directory unreadable (EACCES)" }] })).toBe(2);
  });

  it("suggests import for dotenv files and values set for key files, and rotation for tracked ones", () => {
    const lines = formatFindFilesHuman({
      ...base,
      files: [
        { path: Buffer.from(".env"), kind: "dotenv", symlink: false, git: "tracked" },
        { path: Buffer.from("certs/tls.key"), kind: "key", symlink: true, git: "not-ignored" },
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

describe("names that are not UTF-8 or hold controls", () => {
  it("keep their identity: escaped bytes on the terminal, the exact bytes in JSON", () => {
    const fe = Buffer.from([0xfe, 0x2e, 0x6b, 0x65, 0x79]); // \xfe.key
    const ff = Buffer.from([0xff, 0x2e, 0x6b, 0x65, 0x79]); // \xff.key
    expect(displayBytes(fe)).toBe('"\\xfe.key"');
    expect(displayBytes(ff)).toBe('"\\xff.key"');
    expect(displayBytes(Buffer.from([0x61, 0x22, 0x5c, 0xc3, 0xa9, 0x0a, 0xc2, 0x9b, 0x7f, 0xfe]))).toBe('"a\\"\\\\é\\n\\u009b\\u007f\\xfe"');
    expect(displayBytes(Buffer.from("plain/é.env"))).toBe("plain/é.env");
    const doc = findFilesJson({
      root: Buffer.from("/r"),
      files: [
        { path: fe, kind: "key", symlink: false, git: "tracked" },
        { path: ff, kind: "key", symlink: false, git: "not-ignored" },
        { path: Buffer.from("ok.key"), kind: "key", symlink: false, git: "ignored" },
      ],
      notSearched: [],
      entriesChecked: 3,
      stopped: false,
    });
    expect(doc.root).toBe("/r");
    expect(doc.files.map((f) => [f.path, (f as { pathBase64?: string }).pathBase64])).toEqual([
      ["\ufffd.key", fe.toString("base64")],
      ["\ufffd.key", ff.toString("base64")],
      ["ok.key", undefined],
    ]);
  });

  it("show every control escaped, C1 and DEL included, in paths and diagnostics", () => {
    const lines = formatFindFilesHuman({
      root: Buffer.from("/r\u009b"),
      files: [{ path: Buffer.from(".env.\u009b31m\u007f"), kind: "dotenv", symlink: false, git: "unknown", gitError: "fatal: '\u001b[2J'" }],
      notSearched: [{ path: Buffer.from("x\u0085/"), reason: "directory unreadable (EACCES)" }],
      entriesChecked: 2,
      stopped: false,
    }).join("\n");
    expect(lines).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/);
    expect(lines).toContain('under "/r\\u009b":');
    expect(lines).toContain('  ".env.\\u009b31m\\u007f": Git status unknown: "fatal: \'\\u001b[2J\'"');
    expect(lines).toContain('  "x\\u0085/": directory unreadable (EACCES)');
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
