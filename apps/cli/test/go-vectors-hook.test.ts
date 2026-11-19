// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { runHook } from "../src/agents/hook.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's guardrail hook (internal docs/design/go-cli.md,
 * slice 5.6a), from apps/cli/src/agents/hook.ts itself: every event of
 * agents-hook.test.ts and agents-guardrails.test.ts, and a command for each
 * option of another program the inventory lists for the hook, each run
 * through runHook. A case gives the format, the environment, the directory,
 * a project's files (and whether it is a git repository, with files git
 * tracks), and the event on stdin; it records the answer's exact bytes. In
 * a project case the project's directory is "{{dir}}". Regenerate and
 * commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-hook.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/hook.json", import.meta.url));
const INVENTORY = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/cli-inventory.json", import.meta.url));

interface HookCase {
  id: string;
  format: "claude" | "codex";
  env: Record<string, string>;
  /** The directory the event names ("{{dir}}" for a project's). */
  cwd: string;
  /** A project: its files, its directories, and git. */
  files?: Record<string, string>;
  dirs?: string[];
  git?: boolean;
  /** Files `git add -f` tracks. */
  gitAdd?: string[];
  stdin: string;
  /** stdin's "{{nest}}" is this many nested arrays (kept out of the file). */
  nest?: number;
  expect?: string;
}

const ENV = { HOME: "/home/dev", XDG_CONFIG_HOME: "/home/dev/.xdg" };
const IN_RUN = { ...ENV, VARLATCH_CONFIG_DIR: "/tmp/agent-run-1" };
const CWD = "/work/app";
const PROJECT = { ".env": "API_KEY=1\n", "src/app.ts": "const key = process.env.API_KEY;\n" };

const cases: HookCase[] = [];
let n = 0;
const event = (tool_name: string, tool_input: unknown, cwd: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name, tool_input, ...extra });

/** A tool call at /work/app (no files). */
function call(label: string, tool: string, input: unknown, env: Record<string, string> = ENV, format: "claude" | "codex" = "claude") {
  cases.push({ id: `${n++}.${label}`, format, env, cwd: CWD, stdin: event(tool, input, CWD) });
}
const bash = (command: string, env: Record<string, string> = ENV) => call("bash", "Bash", { command }, env);
/** A tool call in a project. */
function inProject(label: string, files: Record<string, string>, tool: string, input: unknown, options: { git?: boolean; gitAdd?: string[]; dirs?: string[] } = {}) {
  cases.push({ id: `${n++}.${label}`, format: "claude", env: ENV, cwd: "{{dir}}", files, ...options, stdin: event(tool, input, "{{dir}}") });
}

// ---- agents-hook.test.ts ---------------------------------------------------------

for (const p of [".env", ".env.local", "config/.env.production", ".envrc", ".env*", "/abs/.env.bak", ".env.example", "sub/.env.schema", "env.ts", "dotenv.md", ".gitignore", "x.env"]) {
  call("protected-name", "Read", { file_path: p });
}
for (const p of ["~/.config/varlatch/credentials.json", "$HOME/.config/varlatch", "${XDG_CONFIG_HOME}/varlatch/credentials.json", "/home/dev/.xdg/varlatch/credentials.json", "../../home/dev/.config/varlatch/x", "~/.config/varlatchd/x", "/home/dev/.config/other", "varlatch.toml", "./config/varlatch"]) {
  call("store", "Read", { file_path: p });
}
call("store-in-run", "Read", { file_path: "$VARLATCH_CONFIG_DIR/credentials.json" }, IN_RUN);
call("store-in-run", "Read", { file_path: "/home/dev/.xdg/varlatch/credentials.json" }, IN_RUN);

const DENIED_AND_TWINS = [
  ["cat .env", "cat .env.example"],
  ["head -n 5 config/.env.local", "head -n 5 config/README.md"],
  ["grep API_KEY .env", "grep API_KEY .env.schema"],
  ["source .env && npm start", "source ./scripts/setup.sh && npm start"],
  [". ./.env", ". ./env.sh"],
  ["sort < .env", "sort < names.txt"],
  ["base64 .envrc", "base64 logo.png"],
  ["cp .env /tmp/x", "cp .env.example /tmp/x"],
  ["mv .env.local backup/", "mv notes.txt backup/"],
  ["find . -name '.env*' -exec cat {} +", "find . -name '*.md' -exec cat {} +"],
  ["git show HEAD:.env", "git add .env.example"],
  ["git -C app diff .env", "git -C app status .env"],
  ["echo start; cat .env | head", "echo start; cat notes | head"],
  ["bash -c 'cat .env'", "bash -c 'cat README.md'"],
  ["echo \"$(cat .env)\"", "echo \"$(date)\""],
  ["echo `cat .env`", "echo `date`"],
  ["diff <(cat .env) .env.example", "diff <(cat a) .env.example"],
  ["python3 -c \"print(open('.env').read())\"", "python3 -c \"print(open('app.py').read())\""],
  ["node -e \"require('fs').readFileSync('.env.production')\"", "node -e \"require('fs').readFileSync('.env.example')\""],
  ["sudo -u root cat .env", "sudo -u root cat /etc/hosts"],
  ["docker compose --env-file=.env config", "docker compose --file=compose.yml config"],
  ["cat ~/.config/varlatch/credentials.json", "cat ~/.config/git/config"],
  ["ls $HOME/.config/varlatch", "ls $HOME/.config"],
  ["tar czf /tmp/x.tgz ${XDG_CONFIG_HOME}/varlatch", "tar czf /tmp/x.tgz ${XDG_CONFIG_HOME}/git"],
  ["cat ~/.xdg/varlatch/credentials.json", "cat ~/.xdg/git/config"],
  ["cp $HOME/.xdg/varlatch/credentials.json /tmp", "cp $HOME/.xdg/git/config /tmp"],
  ["echo token > ~/.config/varlatch/credentials.json", "echo token > ./out.txt"],
  ["varlatch run -- env", "varlatch run -- npm test"],
  ["varlatch --assisted run -e staging -- printenv API_KEY", "varlatch --assisted run -e staging -- node app.js"],
  ["varlatch run -- sh -c 'env | sort'", "varlatch run -- sh -c 'npm test | tee log'"],
  ["varlatch run -- export -p", "varlatch run -- export PATH=/usr/bin"],
  ["varlatch run -- node -e 'console.log(process.env)'", "varlatch run -- node -e 'console.log(1)'"],
  ["varlatch run -- python3 -c 'import os; print(os.environ)'", "varlatch run -- python3 -c 'print(1)'"],
  ["varlatch run -- cat /proc/self/environ", "varlatch run -- cat /proc/self/status"],
  ["npx varlatch run -- env", "npx varlatch run -- npm test"],
  ["varlatch run -- cat .env", "varlatch run -- cat .env.example"],
  ['ls -la | grep -E "\\.env|app\\.cjs"', 'ls -la | grep -E "KEY" .env'],
  ["grep -E '\\.env' notes.md", "grep -E 'x' .env"],
  ["grep -n -e .env notes.md", "grep -n -e x .env"],
  ["jq -r '.environment' context.json", "jq -r '.environment' .env.json"],
  ["jq .env package.json", "jq . .env"],
  ["rg '.env.local' docs", "rg x .env.local"],
  ["git grep -n .env -- src", "git grep -n x -- .env"],
  ["varlatch --assisted run -e development -- bash -c 'echo \"STRIPE_KEY=$STRIPE_KEY\"'", "varlatch --assisted run -e development -- bash -c 'echo \"home is $HOME\"'"],
  ["varlatch run -- sh -c 'printf \"%s\\n\" \"${API_KEY}\"'", "varlatch run -- sh -c 'printf \"%s\\n\" \"${PATH}\"'"],
  ["varlatch run -- sh -c 'echo ${API_KEY:-unset}'", "varlatch run -- sh -c 'echo ${HOME:-unset}'"],
  ["varlatch run -- printenv HOME API_KEY", "varlatch run -- printenv HOME PATH"],
];
for (const pair of DENIED_AND_TWINS) for (const command of pair) bash(command);
for (const command of [
  "varlatch --assisted import .env --dry-run --json",
  "varlatch --assisted import .env.production --contract --delete-source -e production",
  "varlatch --assisted scan .env",
  "echo .env >> .gitignore",
  "printf '%s\\n' .env .env.local >> .gitignore",
  "ls -la .env*",
  "rm .env",
  "test -f .env && echo present",
  "git add .gitignore && git status --short .env",
  "wc -l .env",
  "env",
  "printenv PATH",
  "node -e 'console.log(process.env.HOME)'",
  "env NODE_ENV=test npm test",
  "varlatch run -- env NODE_ENV=test npm test",
  "cat <<EOF > notes.md\nsee .env and ~/.config/varlatch\nEOF\nnpm test",
  "cat <<-'EOF' > notes.md\n\tcat .env\n\tEOF",
  "git commit -m 'stop reading .env in tests'",
  "find . -name '.env*' -not -path './node_modules/*'",
  "cp .env.example .env",
  "cp -n .env.example config/.env.local",
  "npm test 2>&1 | tee test.log",
  "echo done >&2",
  "varlatch run -- export",
  "varlatch run -- set",
  "varlatch run -- bash -c 'set -e; npm test'",
  "export -p",
  "echo \"$API_KEY\"",
  "printenv API_KEY",
  'grep "\\.env" "a\\$b" "c\\"d"',
  "A=1 cat 'my file' \"x y\" < in.txt > out.txt 2>&1 && echo $(date) | tee -a log; ls",
  "cat <<EOF >x\ncat .env\nEOF\nls # cat .env",
]) {
  bash(command);
}
for (const p of [".environment", ".env|app.cjs", ".env-old", "!.env*", ".e*", ".*", ".[e]nv", ".en?", ".env.*", "*", "?env", "[.]env"]) call("name-or-glob", "Read", { file_path: p });

call("tool", "Read", { file_path: "/work/app/.env" });
call("tool", "Read", { file_path: "/work/app/.env.example" });
call("tool", "Grep", { pattern: "KEY", path: ".env.local" });
call("tool", "Grep", { pattern: "KEY", glob: ".env*" });
call("tool", "Grep", { pattern: "KEY", glob: "*.ts" });
call("tool", "Grep", { pattern: "KEY", file_paths: ["a.ts", ".env"] });
call("tool", "Write", { file_path: ".env", content: "A=1" });
call("tool", "NotebookEdit", { notebook_path: "~/.config/varlatch/x.ipynb" });
call("tool", "mcp__fs__read_file", { path: "/home/dev/.xdg/varlatch/credentials.json" });
call("tool", "mcp__fs__read_file", { path: "/work/app/src/index.ts" });
call("tool", "Glob", { pattern: "**/.env*" });
call("tool", "Bash", { command: "cat .env" });
call("tool", "Bash", { command: "cat README.md" });
call("tool", "shell", { command: ["cat", ".env"] });
call("tool", "shell", { command: ["bash", "-lc", "varlatch run -- env"] });
call("tool", "shell", { command: ["cat", "README.md"] });
call("tool", "shell", { command: ["cat", 1, ".env"] });
const patch = (file: string) => `*** Begin Patch\n*** Update File: ${file}\n@@\n-A=1\n+A=2\n*** End Patch`;
call("tool", "apply_patch", { command: patch(".env") });
call("tool", "apply_patch", { command: patch("src/app.ts") });
call("tool", "apply_patch", { command: "*** Begin Patch\n*** Add File: a.ts\n*** Move to: .env.local\n*** End Patch" });

// runHook: both formats, other events, input it does not understand, the event's cwd.
for (const format of ["claude", "codex"] as const) {
  cases.push({ id: `${n++}.format`, format, env: ENV, cwd: CWD, stdin: event("Bash", { command: "cat .env" }, CWD) });
  cases.push({ id: `${n++}.format`, format, env: ENV, cwd: CWD, stdin: event("Bash", { command: "npm test" }, CWD) });
}
for (const stdin of [
  event("Bash", { command: "cat .env" }, CWD, { hook_event_name: "PostToolUse" }),
  event("Bash", { command: "cat .env" }, CWD, { hook_event_name: null }),
  "not json",
  "[]",
  "null",
  "",
  JSON.stringify({ tool_input: { command: "cat .env" } }),
  JSON.stringify({ tool_name: 7, tool_input: { command: "cat .env" } }),
  JSON.stringify({ tool_name: "Bash", tool_input: "cat .env" }),
  JSON.stringify({ tool_name: "Bash", tool_input: null }),
  JSON.stringify({ tool_name: "Bash", tool_input: { command: "cat .env" } }),
  `﻿${event("Bash", { command: "cat .env" }, CWD)}`,
]) {
  cases.push({ id: `${n++}.input`, format: "claude", env: ENV, cwd: CWD, stdin });
}
cases.push({ id: `${n++}.cwd`, format: "claude", env: ENV, cwd: CWD, stdin: event("Read", { file_path: "../../home/dev/.config/varlatch/credentials.json" }, "/work/app") });

// Projects: a directory called .env, names that exist, globs, recursive searches.
for (const command of ["python3 -m venv .env", "source .env/bin/activate", "du -sh .env"]) inProject("venv", {}, "Bash", { command }, { dirs: [".env/bin"] });
inProject("venv", {}, "Grep", { pattern: "x", path: ".env" }, { dirs: [".env/bin"] });
inProject("venv-file", { ".env": "A=1\n" }, "Bash", { command: "python3 -m venv .env" });
inProject("venv-file", { ".env": "A=1\n" }, "Grep", { pattern: "x", path: ".env" });
for (const command of ["cat .env-old", "cat .environment", "jq -r '.environments' context.json"]) inProject("exists", { ".env-old": "A=1\n", ".environment": "B=2\n" }, "Bash", { command });
inProject("exists", { "a.txt": "x\n" }, "Bash", { command: "cat .env-old" });
for (const command of ["cat .e*", "cat .*", "head .en?", "cat ./.[e]nv", "grep KEY .e*", "cat *", "cat *.md", "cat n*"]) {
  inProject("glob", { ".env": "A=1\n", "notes.md": "x\n" }, "Bash", { command });
}
inProject("glob", { ".env-old": "A=1\n" }, "Bash", { command: "cat .env-*" });
inProject("glob", { "notes.md": "x\n" }, "Bash", { command: "cat .env-*" });
for (const command of [
  "grep -r KEY", "grep -rn API_KEY .", "grep -R KEY ./", "grep --recursive KEY .", "grep -d recurse KEY .", "rgrep KEY .",
  "grep -r KEY src", "grep -r --exclude='.env*' KEY .", "grep -r --exclude=.env KEY .", "grep -r --include='*.ts' KEY .", "grep -rl KEY .", "grep -rc KEY .", "grep KEY src/app.ts",
  "rg KEY", "ag KEY", "rg --hidden KEY", "rg -uu KEY", "rg -. KEY .", "ag --hidden KEY", "ag -u KEY",
  "rg --hidden -g '!.env*' KEY", "rg --hidden -t ts KEY", "rg --hidden -l KEY", "rg --hidden --files",
]) {
  inProject("search", PROJECT, "Bash", { command });
}
inProject("search-below", { "apps/web/.env.local": "A=1\n", "apps/web/index.ts": "x\n" }, "Bash", { command: "grep -r KEY ." });
inProject("search-below", { "apps/web/.env.local": "A=1\n", "apps/web/index.ts": "x\n" }, "Bash", { command: "grep -r --exclude-dir=web KEY ." });
inProject("search-below", { "src/app.ts": "x\n" }, "Bash", { command: "grep -r KEY ." });
for (const command of ["rg --hidden KEY", "ag --hidden KEY", "rg --hidden --no-ignore KEY", "rg -uuu KEY", "git grep KEY", "git grep --untracked KEY", "git grep --no-index KEY", "git grep --no-index --exclude-standard KEY"]) {
  inProject("git", { ...PROJECT, ".gitignore": ".env\n" }, "Bash", { command }, { git: true });
}
inProject("git-tracked", { ...PROJECT, ".gitignore": ".env\n" }, "Bash", { command: "git grep KEY" }, { git: true, gitAdd: [".env"] });
for (const input of [
  { pattern: "KEY", output_mode: "content" },
  { pattern: "KEY", path: ".", output_mode: "content" },
  { pattern: "KEY" },
  { pattern: "KEY", output_mode: "files_with_matches" },
  { pattern: "KEY", output_mode: "content", glob: "*.ts" },
  { pattern: "KEY", output_mode: "content", glob: "!.env*" },
  { pattern: "KEY", output_mode: "content", type: "ts" },
  { pattern: "KEY", output_mode: "content", path: "src" },
]) {
  inProject("grep-tool", PROJECT, "Grep", input);
}
inProject("grep-tool", { ...PROJECT, ".gitignore": ".env\n" }, "Grep", { pattern: "KEY", output_mode: "content" }, { git: true });
inProject("grep-tool-array", PROJECT, "Grep", ["KEY"]);

// Names that are not ASCII: a directory with an accented or CJK name, quoted and not.
const CAFE = { "café/.env.local": "A=1\n", "café/app.ts": "x\n", "日本/.env.local": "A=1\n", "日本/app.ts": "x\n" };
for (const dir of ["café", "日本"]) {
  for (const word of [dir, `"${dir}"`, `'${dir}'`, `./${dir}/`]) {
    for (const command of [`grep -r KEY ${word}`, `grep -rn KEY ${word}`, `rg --hidden KEY ${word}`, `rg -uu KEY ${word}`, `ag --hidden KEY ${word}`, `rg KEY ${word}`]) {
      inProject("non-ascii", CAFE, "Bash", { command });
    }
  }
  inProject("non-ascii", CAFE, "Grep", { pattern: "KEY", path: dir, output_mode: "content" });
  inProject("non-ascii", { [`${dir}/app.ts`]: "x\n" }, "Bash", { command: `grep -r KEY ${dir}` });
}
for (const command of [
  "cat café/.env-old", `cat "café/.env-old"`, "cat 'café'/.env-old", "cat caf\\é/.env-old", "head -n1 日本/.env-old", `cat "日本"/.env-old`,
  "cat .envé", `cat ".envé"`, "cat .env日本", "cat café/notes.md", "cat café/.e*", `cat "日本"/.e*`,
]) {
  inProject("non-ascii-file", { "café/.env-old": "A=1\n", "café/notes.md": "x\n", "日本/.env-old": "A=1\n", ".envé": "A=1\n", ".env日本": "A=1\n" }, "Bash", { command });
}
inProject("non-ascii-file", { "café/notes.md": "x\n" }, "Bash", { command: "cat café/.env-old" });

// A UNC-shaped store and paths: on POSIX, as recorded here, only names; Windows reads them as
// UNC paths (internal/agents' TestHookStoreWindowsForms), so TestHookVectors skips these there.
const UNC_ENV = { ...ENV, XDG_CONFIG_HOME: "\\\\srv\\share\\cfg" };
for (const path of ["\\\\srv\\share\\cfg\\varlatch\\credentials.json", "\\\\srv\\\\share\\cfg\\varlatch\\credentials.json", "//srv//share/cfg/varlatch/credentials.json"]) {
  call("unc", "Read", { file_path: path }, UNC_ENV);
}

// Deep nesting: JSON.parse reads any depth, so a padded event still gets its decision.
for (const nest of [10_001, 100_000]) {
  for (const command of ["cat .env", "npm test"]) {
    cases.push({ id: `${n++}.nest`, format: "claude", env: ENV, cwd: CWD, nest, stdin: event("Bash", { pad: "{{nest}}", command }, CWD) });
    cases.push({ id: `${n++}.nest`, format: "claude", env: ENV, cwd: CWD, nest, stdin: event("Bash", { command }, CWD, { pad: "{{nest}}" }) });
  }
}

// ---- agents-guardrails.test.ts: the events the CLI is given -----------------------

for (const format of ["claude", "codex"] as const) {
  cases.push({ id: `${n++}.cli`, format, env: ENV, cwd: "{{dir}}", files: {}, stdin: event("Bash", { command: "cat .env" }, "{{dir}}") });
  cases.push({ id: `${n++}.cli`, format, env: ENV, cwd: "{{dir}}", files: {}, stdin: event("Bash", { command: "npm test" }, "{{dir}}") });
  cases.push({ id: `${n++}.cli`, format, env: ENV, cwd: "{{dir}}", files: {}, stdin: event("Read", { file_path: "{{dir}}/.env" }, "{{dir}}") });
}
cases.push({ id: `${n++}.cli`, format: "claude", env: ENV, cwd: "{{dir}}", files: {}, stdin: "garbage" });

// ---- Every option of another program the hook reads (the inventory) ----------------

const inventory = JSON.parse(readFileSync(INVENTORY, "utf8")) as { options: Record<string, { of: string; slice?: string }> };
const hookOptions = Object.entries(inventory.options).filter(([, o]) => o.of === "another program" && o.slice === "5.6a").map(([name]) => name).sort();
// Options hook.ts reads that the inventory files under another program
// (a varlatch or host option spelled the same way).
const sharedOptions = ["--after", "--from-file", "--replace", "-T", "-U", "-q"];
for (const option of [...hookOptions, ...sharedOptions]) {
  for (const command of [
    `grep ${option} v KEY .env`,
    `grep ${option} .env KEY notes.md`,
    `rg ${option} v KEY .env`,
    `rg ${option} v KEY`,
    `ag ${option} v KEY .env`,
    `git grep ${option} v KEY -- .env`,
    `jq ${option} v . .env`,
    `find . ${option} cat {} +`,
    `node ${option} "require('fs').readFileSync('.env')"`,
    `env ${option} X cat .env`,
    `git ls-files ${option} .env`,
  ]) {
    inProject("option", { ...PROJECT, "notes.md": "x\n" }, "Bash", { command });
  }
}

// ---- Recording -------------------------------------------------------------------------

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "varlatch-go-vectors-hook-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

/** Runs one case through runHook, in a project of its own when it has one. */
function record(c: HookCase): string {
  const stdin = c.nest === undefined ? c.stdin : c.stdin.split(JSON.stringify("{{nest}}")).join("[".repeat(c.nest) + "]".repeat(c.nest));
  if (c.cwd !== "{{dir}}") return runHook(c.format, stdin, c.env, c.cwd);
  const dir = mkdtempSync(join(scratch, "p-"));
  for (const d of c.dirs ?? []) mkdirSync(join(dir, d), { recursive: true });
  for (const [path, content] of Object.entries(c.files ?? {})) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  if (c.git) {
    spawnSync("git", ["init", "-q"], { cwd: dir });
    for (const f of c.gitAdd ?? []) spawnSync("git", ["add", "-f", f], { cwd: dir });
  }
  const out = runHook(c.format, stdin.split("{{dir}}").join(dir), c.env, dir);
  return out.split(dir).join("{{dir}}");
}

describe("Go CLI hook vectors", () => {
  it("are recorded from hook.ts as it is", () => {
    const recorded = cases.map((c) => ({ ...c, expect: record(c) }));
    const text = `${JSON.stringify({ schema: 1, comment: "Recorded from apps/cli/src/agents/hook.ts by apps/cli/test/go-vectors-hook.test.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.", cases: recorded }, null, 2)}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "hook.json is stale: regenerate it (see this file's comment)").toBe(true);
    // Both answers occur: denials of each kind, and no decision.
    for (const reason of [".env files are off limits", "credential store is off limits", "printing the environment", "this search would print"]) {
      expect(recorded.some((c) => c.expect.includes(reason)), reason).toBe(true);
    }
    expect(recorded.filter((c) => c.expect === "").length).toBeGreaterThan(50);
    // A padded event and a search of a directory whose name is not ASCII are decided.
    const nested = recorded.filter((c) => c.nest !== undefined && c.stdin.includes('"cat .env"'));
    expect(nested.length).toBe(4);
    for (const c of nested) expect(c.expect, c.id).toContain(".env files are off limits");
    const searches = recorded.filter((c) => c.id.endsWith(".non-ascii") && c.files?.["café/.env.local"] && /grep -r|--hidden|-uu/.test(c.stdin));
    expect(searches.length).toBeGreaterThan(30);
    for (const c of searches) expect(c.expect, c.id).not.toBe("");
  }, 300_000);
});
