// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { FIND_LIMITS, FindFilesError, findCopies, findFilesJson, formatFindFilesHuman, type FindLimits } from "../src/findFiles.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's `scan --find-files` (internal
 * docs/design/go-cli.md, slice 5.4e): trees of files, links, Git
 * repositories and their configuration, each searched by findFiles.ts's
 * findCopies in this process, with the report as `--json` gives it, its
 * human lines, or the error. HOME, XDG_CONFIG_HOME and GIT_CONFIG_GLOBAL
 * are the case's (HOME is the tree's `home` unless the case says
 * otherwise), so no configuration of the machine that records is read.
 * The Go test (internal/findfiles' TestVectors) builds each tree the same
 * way and compares. Regenerate after a change to findFiles.ts:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-findfiles.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/findfiles.json", import.meta.url));

/** A tree, its paths relative to the case directory; "{{dir}}" in a link target, a content or a variable is that directory. */
interface Tree {
  files?: Record<string, string>;
  /** Files whose name is not UTF-8: the path's bytes in base64. */
  rawFiles?: string[];
  dirs?: string[];
  links?: Record<string, string>;
  /** Second names for files already made. */
  hardLinks?: Record<string, string>;
  /** Directories made Git repositories (`git init`), before the files are written. */
  repos?: string[];
  /** Modes set last (directories made unreadable). */
  modes?: Record<string, number>;
  /** Paths removed after the rest is made. */
  remove?: string[];
}

interface Case {
  id: string;
  tree: Tree;
  env?: Record<string, string>;
  /** The directory searched, from the case directory. */
  dir: string;
  limits?: FindLimits;
  /** The case needs a user the file system holds to its modes (not root). */
  notRoot?: boolean;
  /** The case needs names that are not UTF-8 (Linux). */
  rawNames?: boolean;
  /** The case needs names Windows does not allow (controls, quotes, backslashes). */
  posixNames?: boolean;
  expect?: { error: string } | { exitCode: number; json: unknown; human: string[] };
}

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
const gitConfig = (extra: string) => `[core]\n\trepositoryformatversion = 0\n${extra}`;
const cases: Case[] = [];
const add = (id: string, tree: Tree, extra: Partial<Case> = {}) => cases.push({ id, tree, dir: ".", ...extra });

// ---- Names ---------------------------------------------------------------------
add("names.kinds", {
  files: {
    ".env": "", ".env.local": "", ".env.production.local": "", ".env.example": "", ".env.schema": "", ".envrc": "",
    "env": "", "x.env": "", "server.pem": "", "id.key": "", "A.PEM": "", "B.KEY": "", "x.key.bak": "", ".pem": "", ".key": "", "key": "",
  },
});
add("names.trailing-dot", { files: { ".env.": "", "x.key": "" } }, { posixNames: true });
add("names.empty", { files: { "README.md": "", "src/app.ts": "" } });
add("names.control", { files: { "a\nb.env.x/.env": "", ".env.\u009b": "", "tab\t.key": "", "quote\".pem": "", "back\\slash.key": "" } }, { posixNames: true });
add("names.unicode", { files: { "café/.env": "", "日本/id.key": "", "\u2028.pem": "", "\uFEFFbom/.env": "" } });
add("names.raw", { rawFiles: [Buffer.from([0x66, 0xff, 0x2f, 0x2e, 0x65, 0x6e, 0x76]).toString("base64"), Buffer.from([0x78, 0xc3, 0x28, 0x2e, 0x6b, 0x65, 0x79]).toString("base64"), Buffer.from([0xef, 0xbb, 0xbf, 0xfe, 0x2e, 0x70, 0x65, 0x6d]).toString("base64")], dirs: ["f\u00ff"] }, { rawNames: true });

// ---- The walk ------------------------------------------------------------------
add("walk.skipped-dirs", { files: { ".git/x.env.d/.env": "", "node_modules/a/.env": "", ".hg/.env": "", ".svn/k.key": "", "nodes/.env": "", ".gitx/.env": "" } });
add("walk.links", {
  files: { "real/.env": "", "target.txt": "" },
  dirs: ["empty"],
  links: { ".env": "target.txt", "dangling.key": "nowhere", "linkdir": "real", "real/self.pem": "../real", ".env.abs": "{{dir}}/target.txt" },
});
add("walk.depth", { files: { "a/b/c/.env": "", "a/b/.env": "", "a/.env": "", "x/y/z/w/k.key": "" } }, { limits: { maxEntries: 1000, maxDepth: 2 } });
add("walk.depth-clean", { files: { "a/b/c/d/notes.md": "" } }, { limits: { maxEntries: 1000, maxDepth: 2 } });
add("walk.stopped", { files: { "a/.env": "", "b/.env": "", "c/.env": "", "d/1": "", "d/2": "", "e/.env": "" } }, { limits: { maxEntries: 6, maxDepth: 20 } });
add("walk.stopped-clean", { files: { "a/1": "", "a/2": "", "a/3": "", "b/4": "" } }, { limits: { maxEntries: 3, maxDepth: 20 } });
add("walk.unreadable", { files: { "open/.env": "", "closed/.env": "", "closed2/notes": "" }, modes: { closed: 0o000, closed2: 0o000 } }, { notRoot: true });
add("walk.unreadable-clean", { files: { "closed/notes": "" }, modes: { closed: 0o000 } }, { notRoot: true });
add("walk.subdir", { files: { "app/.env": "", "other/.env": "" } }, { dir: "app" });
add("walk.trailing-slash", { files: { "app/.env": "" } }, { dir: "app/" });
add("walk.dot-dot", { files: { "app/.env": "", "other/id.key": "" } }, { dir: "app/../other" });
add("walk.through-link", { files: { "real/.env": "" }, links: { "via": "real" } }, { dir: "via" });
add("walk.missing", { files: { "a": "" } }, { dir: "nope" });
add("walk.not-a-directory", { files: { "a.txt": "" } }, { dir: "a.txt" });
add("walk.control-in-dir-argument", { files: { "a": "" } }, { dir: "no\u0007pe" });
add("walk.empty-argument", { files: { ".env": "" } }, { dir: "" });

// ---- Git: rules (Git's own) ----------------------------------------------------
const repo = (files: Record<string, string>, extra: Tree = {}): Tree => ({ repos: ["."], files, ...extra });
add("git.plain", repo({ ".gitignore": ".env\n", ".env": "", ".env.local": "", "id.key": "" }));
add("git.no-ignore-file", repo({ ".env": "" }));
add("git.negation", repo({ ".gitignore": ".env*\n!.env.keep\n", ".env.keep": "", ".env.x": "" }));
add("git.directory-only", repo({ ".gitignore": "secrets/\n", "secrets/.env": "", "notsecrets/.env": "" }));
add("git.double-star", repo({ ".gitignore": "**/certs/*.pem\nsub/**\n", "a/b/certs/x.pem": "", "certs/y.pem": "", "sub/q/r.key": "", "c/z.pem": "" }));
add("git.escapes", repo({ ".gitignore": "\\#x.key\n\\!y.key\n#z.key\n", "#x.key": "", "!y.key": "", "#z.key": "" }));
add("git.trailing-spaces", repo({ ".gitignore": "a.key   \nb.key\\ \n", "a.key": "", "b.key ": "", "b.key": "" }), { posixNames: true });
add("git.nested-gitignore", repo({ ".gitignore": "*.pem\n", "sub/.gitignore": "!keep.pem\n.env\n", "sub/keep.pem": "", "sub/other.pem": "", "sub/.env": "", ".env": "" }));
add("git.info-exclude", repo({ ".git/info/exclude": ".env\n", ".env": "", "id.key": "" }));
add("git.repo-excludes-file", repo({ ".git/config": gitConfig("\texcludesFile = {{dir}}/excl/ignore\n"), ".env": "", "id.key": "", "excl/ignore": "*.key\n" }));
add("git.global-excludes", repo({ ".env": "", "id.key": "", "global/gitconfig": "[core]\n\texcludesFile = {{dir}}/global/ignore\n", "global/ignore": "*.key\n" }), { env: { GIT_CONFIG_GLOBAL: "{{dir}}/global/gitconfig" } });
add("git.global-tilde", repo({ ".env": "", "id.key": "", "home/.gitconfig": "[core]\n\texcludesfile = ~/my-ignore\n", "home/my-ignore": ".env\n" }));
add("git.xdg-default-ignore", repo({ ".env": "", "id.key": "", "xdg/git/ignore": ".env\n" }), { env: { XDG_CONFIG_HOME: "{{dir}}/xdg" } });
add("git.xdg-config", repo({ ".env": "", "id.key": "", "xdg/git/config": "[core]\n\texcludesFile = {{dir}}/xdg/other-ignore\n", "xdg/other-ignore": "*.key\n" }), { env: { XDG_CONFIG_HOME: "{{dir}}/xdg" } });
add("git.home-over-xdg", repo({ ".env": "", "id.key": "", "xdg/git/config": "[core]\n\texcludesFile = {{dir}}/xdg/a\n", "home/.gitconfig": "[core]\n\texcludesFile = {{dir}}/b\n", "xdg/a": "*.key\n", "b": ".env\n" }), { env: { XDG_CONFIG_HOME: "{{dir}}/xdg" } });
add("git.global-dev-null", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = {{dir}}/b\n", "b": ".env\n" }), { env: { GIT_CONFIG_GLOBAL: "/dev/null" } });
add("git.global-empty", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = {{dir}}/b\n", "b": ".env\n" }), { env: { GIT_CONFIG_GLOBAL: "" } });
add("git.global-missing", repo({ ".env": "" }), { env: { GIT_CONFIG_GLOBAL: "{{dir}}/nope" } });
add("git.empty-xdg", repo({ ".env": "", "home/.config/git/ignore": ".env\n" }), { env: { XDG_CONFIG_HOME: "" } });

// ---- Git: repositories -----------------------------------------------------------
add("repo.nested", { repos: [".", "inner"], files: { ".gitignore": "*.key\n", "a.key": "", "inner/b.key": "", "inner/.gitignore": ".env\n", "inner/.env": "", ".env": "" } });
add("repo.above-root", { repos: ["."], files: { ".gitignore": "app/.env\n", "app/.env": "", "app/id.key": "" } }, { dir: "app" });
add("repo.none", { files: { ".env": "", "sub/id.key": "" } });
add("repo.gitfile", { repos: ["store"], files: { "wt/.git": "gitdir: {{dir}}/store/.git\n", "wt/.gitignore": ".env\n", "wt/.env": "", "wt/x.key": "" } }, { dir: "wt" });
add("repo.gitfile-relative", { repos: ["store"], files: { "wt/.git": "gitdir: ../store/.git\n", "wt/.env": "" } }, { dir: "wt" });
add("repo.gitfile-bom", { repos: ["store"], files: { "wt/.git": "\uFEFFgitdir: ../store/.git\r\n", "wt/.env": "" } }, { dir: "wt" });
add("repo.gitfile-bad", { files: { "wt/.git": "nonsense\n", "wt/.env": "" } }, { dir: "wt" });
add("repo.gitfile-nowhere", { files: { "wt/.git": "gitdir: ../missing\n", "wt/.env": "" } }, { dir: "wt" });
add("repo.gitfile-big", { files: { "wt/.git": `gitdir: ${"x".repeat(5000)}\n`, "wt/.env": "" } }, { dir: "wt" });
add("repo.commondir", { repos: ["main"], files: { "main/.git/worktrees/w/HEAD": "ref: refs/heads/main\n", "main/.git/worktrees/w/commondir": "../..\n", "w/.git": "gitdir: {{dir}}/main/.git/worktrees/w\n", "w/.env": "", "main/.git/info/exclude": ".env\n" } }, { dir: "w" });
add("repo.commondir-bad", { repos: ["main"], files: { "main/.git/worktrees/w/HEAD": "ref: refs/heads/main\n", "main/.git/worktrees/w/commondir": "../../nope\n", "w/.git": "gitdir: {{dir}}/main/.git/worktrees/w\n", "w/.env": "" } }, { dir: "w" });
add("repo.git-link", { repos: ["real"], files: { "w/.env": "" }, links: { "w/.git": "../real/.git" } }, { dir: "w" });
add("repo.git-fifo-like", { files: { "w/.env": "" }, dirs: ["w/.git"] }, { dir: "w" });
add("repo.bare-above", { dirs: ["objects", "refs"], files: { "app/.env": "" } }, { dir: "app" });
add("repo.bare-at-root", { dirs: ["objects", "refs"], files: { ".env": "" } });

// ---- Git: unusual setups (unknown) ---------------------------------------------------
add("unusual.include", repo({ ".git/config": gitConfig("[include]\n\tpath = other\n"), ".env": "" }));
add("unusual.include-if", repo({ ".git/config": gitConfig('[includeIf "gitdir:/x/"]\n\tpath = other\n'), ".env": "" }));
add("unusual.worktree", repo({ ".git/config": gitConfig("\tworktree = /elsewhere\n"), ".env": "" }));
add("unusual.alternates", repo({ ".git/objects/info/alternates": "/elsewhere\n", ".env": "" }));
add("unusual.config-worktree", repo({ ".git/config.worktree": "[core]\n\texcludesFile = {{dir}}/w-ignore\n", "w-ignore": ".env\n", ".env": "" }));
add("unusual.gitignore-link", repo({ "real-ignore": ".env\n", ".env": "" }, { links: { ".gitignore": "real-ignore" } }));
add("unusual.gitignore-hardlink", repo({ "real-ignore": ".env\n", ".env": "" }, { hardLinks: { ".gitignore": "real-ignore" } }));
add("unusual.gitignore-dir", repo({ ".gitignore/x": "", ".env": "" }));
add("unusual.nested-gitignore-link", repo({ "sub/.env": "", "real": "*\n" }, { links: { "sub/.gitignore": "../real" } }));
add("unusual.exclude-link", repo({ "real": ".env\n", ".env": "" }, { links: { ".git/info/exclude": "../../real" } }));
add("unusual.head-missing", repo({ ".env": "" }, { remove: [".git/HEAD"] }));
add("unusual.excludes-relative", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = relative/ignore\n" }));
add("unusual.excludes-secret-name", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = {{dir}}/x/.env.ignore\n", "x/.env.ignore": ".env\n" }));
add("unusual.excludes-link-to-secret", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = {{dir}}/ign\n", "keys/id.key": "" }, { links: { "ign": "keys/id.key" } }));
add("unusual.excludes-link-chain", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = {{dir}}/ign\n", "real-ignore": ".env\n" }, { links: { "ign": "ign2", "ign2": "real-ignore" } }));
add("unusual.excludes-link-loop", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = {{dir}}/ign\n" }, { links: { "ign": "ign2", "ign2": "ign" } }));
add("unusual.excludes-not-utf8", repo({ ".env": "", "home/.gitconfig": "[core]\n\texcludesFile = /x\u00ff\n" }));
add("unusual.global-include", repo({ ".env": "", "home/.gitconfig": "[include]\n\tpath = x\n" }));
add("unusual.global-worktree", repo({ ".env": "", "home/.gitconfig": "[core]\n\tworktree = /x\n" }));
add("unusual.global-link", repo({ ".env": "", "real-config": "[core]\n\texcludesFile = {{dir}}/b\n", "b": ".env\n" }, { links: { "home/.gitconfig": "../real-config" } }));
add("unusual.global-unreadable-syntax", repo({ ".env": "", "home/.gitconfig": "[core\n\tbroken\n" }));
add("unusual.global-secret-name", repo({ ".env": "", "g/.env.gitconfig": "[core]\n" }), { env: { GIT_CONFIG_GLOBAL: "{{dir}}/g/.env.gitconfig" } });
add("unusual.two-repos-one-unusual", { repos: ["good", "bad"], files: { "good/.env": "", "bad/.env": "", "bad/.git/objects/info/alternates": "/x\n" } });

// ---- Building and recording -------------------------------------------------------------

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "varlatch-go-vectors-findfiles-")));
afterAll(() => {
  spawnSync("chmod", ["-R", "u+rwx", scratch]);
  rmSync(scratch, { recursive: true, force: true });
});

function build(dir: string, tree: Tree): void {
  const fill = (s: string) => s.split("{{dir}}").join(dir);
  mkdirSync(join(dir, "home"), { recursive: true });
  for (const r of tree.repos ?? []) {
    mkdirSync(join(dir, r), { recursive: true });
    spawnSync("git", ["init", "-q"], { cwd: join(dir, r), env: GIT_ENV });
  }
  for (const d of tree.dirs ?? []) mkdirSync(join(dir, d), { recursive: true });
  for (const [path, content] of Object.entries(tree.files ?? {})) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), fill(content));
  }
  for (const raw of tree.rawFiles ?? []) {
    const bytes = Buffer.from(raw, "base64");
    const slash = bytes.lastIndexOf(0x2f);
    if (slash >= 0) mkdirSync(Buffer.concat([Buffer.from(`${dir}/`), bytes.subarray(0, slash)]), { recursive: true });
    writeFileSync(Buffer.concat([Buffer.from(`${dir}/`), bytes]), "");
  }
  for (const [path, target] of Object.entries(tree.links ?? {})) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    rmSync(join(dir, path), { force: true }); // in place of what git init wrote there
    symlinkSync(fill(target), join(dir, path));
  }
  for (const [path, existing] of Object.entries(tree.hardLinks ?? {})) {
    rmSync(join(dir, path), { force: true });
    linkSync(join(dir, existing), join(dir, path));
  }
  for (const path of tree.remove ?? []) rmSync(join(dir, path), { recursive: true });
  for (const [path, mode] of Object.entries(tree.modes ?? {})) chmodSync(join(dir, path), mode);
}

const VARS = ["HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL"] as const;

async function record(c: Case, dir: string): Promise<NonNullable<Case["expect"]>> {
  const saved = Object.fromEntries(VARS.map((k) => [k, process.env[k]]));
  try {
    for (const k of VARS) delete process.env[k];
    process.env.HOME = join(dir, "home");
    for (const [k, v] of Object.entries(c.env ?? {})) process.env[k] = v.split("{{dir}}").join(dir);
    const unfill = (s: string) => s.split(dir).join("{{dir}}");
    const limits = c.limits ?? FIND_LIMITS;
    try {
      const report = await findCopies(c.dir, dir, limits);
      return {
        exitCode: findFilesJson(report).exitCode,
        json: JSON.parse(unfill(JSON.stringify(findFilesJson(report)))),
        human: formatFindFilesHuman(report, limits).map(unfill),
      };
    } catch (err) {
      if (err instanceof FindFilesError) return { error: unfill(err.message) };
      throw err;
    }
  } finally {
    for (const k of VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

describe("Go CLI find-files vectors", () => {
  it("are recorded from findFiles.ts as it is", async () => {
    const ids = new Set<string>();
    const recorded: Case[] = [];
    for (const c of cases) {
      if (ids.has(c.id)) throw new Error(`case ${c.id} twice`);
      ids.add(c.id);
      const dir = realpathSync(mkdtempSync(join(scratch, "c-")));
      build(dir, c.tree);
      recorded.push({ ...c, expect: await record(c, dir) });
    }
    const text = `${JSON.stringify({ schema: 1, comment: "Recorded from apps/cli/src/findFiles.ts by apps/cli/test/go-vectors-findfiles.test.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.", defaultLimits: FIND_LIMITS, cases: recorded }, null, 2)}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "findfiles.json is stale: regenerate it (see this file's comment)").toBe(true);
    // Each answer occurs: every Git state, an unknown with its reason, each exit status, and the errors.
    const all = JSON.stringify(recorded.map((c) => c.expect));
    for (const marker of ['"git":"ignored"', '"git":"not-ignored"', '"git":"no-repository"', '"gitError"', '"exitCode":0', '"exitCode":1', '"exitCode":2', '"stopped":true', "pathBase64", "does not exist", "is not one"]) {
      expect(all, marker).toContain(marker);
    }
  }, 300_000);
});
