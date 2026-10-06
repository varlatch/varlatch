// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkCommand, checkToolCall, isInStore, isProtectedEnvFile, lexShell, runHook, type HookContext } from "../src/agents/hook.js";

/**
 * The guardrail handler (ADR-0043 Decision 8). Every denied case has an
 * allowed twin that differs only in what the guardrail is about (the file,
 * the command under `varlatch run`), so each denial is shown to come from
 * that protection and not from the rest of the command.
 */

const ctx: HookContext = {
  cwd: "/work/app",
  env: { HOME: "/home/dev", XDG_CONFIG_HOME: "/home/dev/.xdg" },
  home: "/home/dev",
};
const inRun: HookContext = { ...ctx, env: { ...ctx.env, VARLATCH_CONFIG_DIR: "/tmp/agent-run-1" } };

const ENV = /\.env files are off limits/;
const STORE = /credential store is off limits/;
const DUMP = /printing the environment of a `varlatch run`/;

describe("which files are protected", () => {
  it(".env files except the two templates", () => {
    for (const p of [".env", ".env.local", "config/.env.production", ".envrc", ".env*", "/abs/.env.bak"]) expect(isProtectedEnvFile(p), p).toBe(true);
    for (const p of [".env.example", "sub/.env.schema", "env.ts", "dotenv.md", ".gitignore", "x.env"]) expect(isProtectedEnvFile(p), p).toBe(false);
  });

  it("the credential store: the configured directory and the default one, however it is spelled", () => {
    for (const p of [
      "~/.config/varlatch/credentials.json",
      "$HOME/.config/varlatch",
      "${XDG_CONFIG_HOME}/varlatch/credentials.json",
      "/home/dev/.xdg/varlatch/credentials.json",
      "../../home/dev/.config/varlatch/x",
    ]) {
      expect(isInStore(p, ctx), p).toBe(true);
    }
    expect(isInStore("$VARLATCH_CONFIG_DIR/credentials.json", inRun)).toBe(true);
    // Inside an agent-safe run, the operator's default store stays protected too.
    expect(isInStore("/home/dev/.xdg/varlatch/credentials.json", inRun)).toBe(true);
    for (const p of ["~/.config/varlatchd/x", "/home/dev/.config/other", "varlatch.toml", "./config/varlatch"]) expect(isInStore(p, ctx), p).toBe(false);
  });
});

describe("shell commands", () => {
  const denied: [string, RegExp, string][] = [
    // [command, denial, the allowed twin]
    ["cat .env", ENV, "cat .env.example"],
    ["head -n 5 config/.env.local", ENV, "head -n 5 config/README.md"],
    ["grep API_KEY .env", ENV, "grep API_KEY .env.schema"],
    ["source .env && npm start", ENV, "source ./scripts/setup.sh && npm start"],
    [". ./.env", ENV, ". ./env.sh"],
    ["sort < .env", ENV, "sort < names.txt"],
    ["base64 .envrc", ENV, "base64 logo.png"],
    ["cp .env /tmp/x", ENV, "cp .env.example /tmp/x"],
    ["mv .env.local backup/", ENV, "mv notes.txt backup/"],
    ["find . -name '.env*' -exec cat {} +", ENV, "find . -name '*.md' -exec cat {} +"],
    ["git show HEAD:.env", ENV, "git add .env.example"],
    ["git -C app diff .env", ENV, "git -C app status .env"],
    ["echo start; cat .env | head", ENV, "echo start; cat notes | head"],
    ["bash -c 'cat .env'", ENV, "bash -c 'cat README.md'"],
    ["echo \"$(cat .env)\"", ENV, "echo \"$(date)\""],
    ["echo `cat .env`", ENV, "echo `date`"],
    ["diff <(cat .env) .env.example", ENV, "diff <(cat a) .env.example"],
    ["python3 -c \"print(open('.env').read())\"", ENV, "python3 -c \"print(open('app.py').read())\""],
    ["node -e \"require('fs').readFileSync('.env.production')\"", ENV, "node -e \"require('fs').readFileSync('.env.example')\""],
    ["sudo -u root cat .env", ENV, "sudo -u root cat /etc/hosts"],
    ["docker compose --env-file=.env config", ENV, "docker compose --file=compose.yml config"],
    ["cat ~/.config/varlatch/credentials.json", STORE, "cat ~/.config/git/config"],
    ["ls $HOME/.config/varlatch", STORE, "ls $HOME/.config"],
    ["tar czf /tmp/x.tgz ${XDG_CONFIG_HOME}/varlatch", STORE, "tar czf /tmp/x.tgz ${XDG_CONFIG_HOME}/git"],
    // A store outside ~/.config is found only by expanding ~ and $HOME.
    ["cat ~/.xdg/varlatch/credentials.json", STORE, "cat ~/.xdg/git/config"],
    ["cp $HOME/.xdg/varlatch/credentials.json /tmp", STORE, "cp $HOME/.xdg/git/config /tmp"],
    ["echo token > ~/.config/varlatch/credentials.json", STORE, "echo token > ./out.txt"],
    ["varlatch run -- env", DUMP, "varlatch run -- npm test"],
    ["varlatch --assisted run -e staging -- printenv API_KEY", DUMP, "varlatch --assisted run -e staging -- node app.js"],
    ["varlatch run -- sh -c 'env | sort'", DUMP, "varlatch run -- sh -c 'npm test | tee log'"],
    ["varlatch run -- export -p", DUMP, "varlatch run -- export PATH=/usr/bin"],
    ["varlatch run -- node -e 'console.log(process.env)'", DUMP, "varlatch run -- node -e 'console.log(1)'"],
    ["varlatch run -- python3 -c 'import os; print(os.environ)'", DUMP, "varlatch run -- python3 -c 'print(1)'"],
    ["varlatch run -- cat /proc/self/environ", DUMP, "varlatch run -- cat /proc/self/status"],
    ["npx varlatch run -- env", DUMP, "npx varlatch run -- npm test"],
    ["varlatch run -- cat .env", ENV, "varlatch run -- cat .env.example"],
  ];

  it.each(denied)("denies %s", (command, denial) => {
    expect(checkCommand(command, ctx)).toMatch(denial);
  });

  it.each(denied)("control for %s: its twin is allowed", (_command, _denial, twin) => {
    expect(checkCommand(twin, ctx), twin).toBeNull();
  });

  it("allows the ways the skill works with .env files, and commands that only name them", () => {
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
    ]) {
      expect(checkCommand(command, ctx), command).toBeNull();
    }
  });

  it("`export` and `set` print the environment only without arguments", () => {
    expect(checkCommand("varlatch run -- export", ctx)).toMatch(DUMP);
    expect(checkCommand("varlatch run -- set", ctx)).toMatch(DUMP);
    expect(checkCommand("varlatch run -- bash -c 'set -e; npm test'", ctx)).toBeNull();
    expect(checkCommand("export -p", ctx)).toBeNull();
  });
});

describe("the shell reader", () => {
  it("splits commands, drops quotes, and keeps inputs and outputs apart from words", () => {
    const { segments, nested } = lexShell("A=1 cat 'my file' \"x y\" < in.txt > out.txt 2>&1 && echo $(date) | tee -a log; ls");
    expect(segments.map((s) => s.words)).toEqual([["A=1", "cat", "my file", "x y"], ["echo", "$SUBST"], ["tee", "-a", "log"], ["ls"]]);
    expect(segments[0]?.inputs).toEqual(["in.txt"]);
    expect(segments[0]?.outputs).toEqual(["out.txt"]);
    expect(nested).toEqual(["date"]);
  });

  it("skips heredoc bodies and comments", () => {
    const { segments } = lexShell("cat <<EOF >x\ncat .env\nEOF\nls # cat .env");
    expect(segments.map((s) => s.words)).toEqual([["cat"], ["ls"]]);
  });
});

describe("a directory called .env", () => {
  it("is not a .env file: a Python virtualenv is often called .env", () => {
    const root = mkdtempSync(join(tmpdir(), "varlatch-hook-venv-"));
    try {
      mkdirSync(join(root, ".env", "bin"), { recursive: true });
      const here: HookContext = { ...ctx, cwd: root };
      for (const command of ["python3 -m venv .env", "source .env/bin/activate", "du -sh .env"]) {
        expect(checkCommand(command, here), command).toBeNull();
      }
      expect(checkToolCall("Grep", { pattern: "x", path: ".env" }, here)).toBeNull();
      // Control: the same commands with .env a file.
      rmSync(join(root, ".env"), { recursive: true });
      writeFileSync(join(root, ".env"), "A=1\n");
      expect(checkCommand("python3 -m venv .env", here)).toMatch(ENV);
      expect(checkToolCall("Grep", { pattern: "x", path: ".env" }, here)).toMatch(ENV);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("tool calls", () => {
  it("file tools: any path argument, in every key name the agents use", () => {
    expect(checkToolCall("Read", { file_path: "/work/app/.env" }, ctx)).toMatch(ENV);
    expect(checkToolCall("Read", { file_path: "/work/app/.env.example" }, ctx)).toBeNull();
    expect(checkToolCall("Grep", { pattern: "KEY", path: ".env.local" }, ctx)).toMatch(ENV);
    expect(checkToolCall("Grep", { pattern: "KEY", glob: ".env*" }, ctx)).toMatch(ENV);
    expect(checkToolCall("Grep", { pattern: "KEY", glob: "*.ts" }, ctx)).toBeNull();
    expect(checkToolCall("Grep", { pattern: "KEY", file_paths: ["a.ts", ".env"] }, ctx)).toMatch(ENV);
    expect(checkToolCall("Write", { file_path: ".env", content: "A=1" }, ctx)).toMatch(ENV);
    expect(checkToolCall("NotebookEdit", { notebook_path: "~/.config/varlatch/x.ipynb" }, ctx)).toMatch(STORE);
    expect(checkToolCall("mcp__fs__read_file", { path: "/home/dev/.xdg/varlatch/credentials.json" }, ctx)).toMatch(STORE);
    expect(checkToolCall("mcp__fs__read_file", { path: "/work/app/src/index.ts" }, ctx)).toBeNull();
    // Listing names reads nothing.
    expect(checkToolCall("Glob", { pattern: "**/.env*" }, ctx)).toBeNull();
  });

  it("shell tools: a command string (Claude Code, Codex) or an argument vector", () => {
    expect(checkToolCall("Bash", { command: "cat .env" }, ctx)).toMatch(ENV);
    expect(checkToolCall("Bash", { command: "cat README.md" }, ctx)).toBeNull();
    expect(checkToolCall("shell", { command: ["cat", ".env"] }, ctx)).toMatch(ENV);
    expect(checkToolCall("shell", { command: ["bash", "-lc", "varlatch run -- env"] }, ctx)).toMatch(DUMP);
    expect(checkToolCall("shell", { command: ["cat", "README.md"] }, ctx)).toBeNull();
  });

  it("apply_patch: the files the patch touches", () => {
    const patch = (file: string) => `*** Begin Patch\n*** Update File: ${file}\n@@\n-A=1\n+A=2\n*** End Patch`;
    expect(checkToolCall("apply_patch", { command: patch(".env") }, ctx)).toMatch(ENV);
    expect(checkToolCall("apply_patch", { command: patch("src/app.ts") }, ctx)).toBeNull();
  });
});

/** A project directory with files, optionally a git repository, removed after `body`. */
function inProject(files: Record<string, string>, body: (here: HookContext, root: string) => void, options: { git?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "varlatch-hook-project-"));
  try {
    for (const [path, content] of Object.entries(files)) {
      mkdirSync(join(root, path, ".."), { recursive: true });
      writeFileSync(join(root, path), content);
    }
    if (options.git) spawnSync("git", ["init", "-q"], { cwd: root });
    body({ ...ctx, cwd: root }, root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const SEARCH = /this search would print lines of \.env files/;

describe("names that only look like .env files", () => {
  it("a pattern or filter that starts with .env is not a file the command reads", () => {
    for (const p of [".environment", ".env|app.cjs", ".env-old", "!.env*"]) expect(isProtectedEnvFile(p), p).toBe(false);
    for (const p of [".e*", ".*", ".[e]nv", ".en?", ".env.*"]) expect(isProtectedEnvFile(p), p).toBe(true);
    // A leading dot is matched only by a dot, as the shell does.
    for (const p of ["*", "?env", "[.]env"]) expect(isProtectedEnvFile(p), p).toBe(false);
  });

  // Each allowed command has a denied twin that reads a .env file the same way.
  const allowed: [string, string][] = [
    ['ls -la | grep -E "\\.env|app\\.cjs"', 'ls -la | grep -E "KEY" .env'],
    ["grep -E '\\.env' notes.md", "grep -E 'x' .env"],
    ["grep -n -e .env notes.md", "grep -n -e x .env"],
    ["jq -r '.environment' context.json", "jq -r '.environment' .env.json"],
    ["jq .env package.json", "jq . .env"],
    ["rg '.env.local' docs", "rg x .env.local"],
    ["git grep -n .env -- src", "git grep -n x -- .env"],
  ];

  it.each(allowed)("allows %s", (command) => {
    expect(checkCommand(command, ctx)).toBeNull();
  });

  it.each(allowed)("control for %s: its twin is denied", (_command, twin) => {
    expect(checkCommand(twin, ctx), twin).toMatch(ENV);
  });

  it("the shell keeps a backslash in double quotes unless it escapes $ ` \" or \\", () => {
    expect(lexShell('grep "\\.env" "a\\$b" "c\\"d"').segments[0]?.words).toEqual(["grep", "\\.env", "a$b", 'c"d']);
  });

  it("another name starting with .env is one when it exists as a file", () => {
    inProject({ ".env-old": "A=1\n", ".environment": "B=2\n" }, (here) => {
      expect(checkCommand("cat .env-old", here)).toMatch(ENV);
      expect(checkCommand("cat .environment", here)).toMatch(ENV);
      // Control, same directory: a name that is no file is a filter, not a read.
      expect(checkCommand("jq -r '.environments' context.json", here)).toBeNull();
    });
    inProject({ "a.txt": "x\n" }, (here) => {
      expect(checkCommand("cat .env-old", here)).toBeNull();
    });
  });
});

describe("globs", () => {
  it("a glob that matches a .env file reads it", () => {
    inProject({ ".env": "A=1\n", "notes.md": "x\n" }, (here) => {
      for (const command of ["cat .e*", "cat .*", "head .en?", "cat ./.[e]nv", "grep KEY .e*"]) expect(checkCommand(command, here), command).toMatch(ENV);
      // Controls: the shell's * does not match a leading dot, and a glob that matches no .env file.
      for (const command of ["cat *", "cat *.md", "cat n*"]) expect(checkCommand(command, here), command).toBeNull();
    });
  });

  it("a glob is checked against the files in its directory, for .env names the name rule does not cover", () => {
    inProject({ ".env-old": "A=1\n" }, (here) => {
      expect(checkCommand("cat .env-*", here)).toMatch(ENV);
    });
    inProject({ "notes.md": "x\n" }, (here) => {
      expect(checkCommand("cat .env-*", here)).toBeNull();
    });
  });
});

describe("recursive searches", () => {
  const project = { ".env": "API_KEY=1\n", "src/app.ts": "const key = process.env.API_KEY;\n" };

  it("grep -r prints the .env files under the directory it searches", () => {
    inProject(project, (here) => {
      for (const command of ["grep -r KEY", "grep -rn API_KEY .", "grep -R KEY ./", "grep --recursive KEY .", "grep -d recurse KEY .", "rgrep KEY ."]) {
        expect(checkCommand(command, here), command).toMatch(SEARCH);
      }
      // Controls, same directory: a directory without .env files, the .env files left out, names or counts only.
      for (const command of [
        "grep -r KEY src",
        "grep -r --exclude='.env*' KEY .",
        "grep -r --exclude=.env KEY .",
        "grep -r --include='*.ts' KEY .",
        "grep -rl KEY .",
        "grep -rc KEY .",
        "grep KEY src/app.ts",
      ]) {
        expect(checkCommand(command, here), command).toBeNull();
      }
    });
  });

  it("finds a .env file below the top level, unless its directory is left out", () => {
    inProject({ "apps/web/.env.local": "A=1\n", "apps/web/index.ts": "x\n" }, (here) => {
      expect(checkCommand("grep -r KEY .", here)).toMatch(SEARCH);
      expect(checkCommand("grep -r --exclude-dir=web KEY .", here)).toBeNull();
    });
    // Control: no .env file anywhere.
    inProject({ "src/app.ts": "x\n" }, (here) => {
      expect(checkCommand("grep -r KEY .", here)).toBeNull();
    });
  });

  it("rg and ag search hidden files only when asked, and skip what git ignores", () => {
    inProject(project, (here) => {
      expect(checkCommand("rg KEY", here)).toBeNull();
      expect(checkCommand("ag KEY", here)).toBeNull();
      for (const command of ["rg --hidden KEY", "rg -uu KEY", "rg -. KEY .", "ag --hidden KEY", "ag -u KEY"]) {
        expect(checkCommand(command, here), command).toMatch(SEARCH);
      }
      for (const command of ["rg --hidden -g '!.env*' KEY", "rg --hidden -t ts KEY", "rg --hidden -l KEY", "rg --hidden --files"]) {
        expect(checkCommand(command, here), command).toBeNull();
      }
    });
    inProject({ ...project, ".gitignore": ".env\n" }, (here) => {
      expect(checkCommand("rg --hidden KEY", here)).toBeNull();
      expect(checkCommand("ag --hidden KEY", here)).toBeNull();
      // Control: told to ignore nothing, it searches the ignored file.
      expect(checkCommand("rg --hidden --no-ignore KEY", here)).toMatch(SEARCH);
      expect(checkCommand("rg -uuu KEY", here)).toMatch(SEARCH);
    }, { git: true });
  });

  it("git grep searches tracked files, or the directory with --no-index", () => {
    inProject({ ...project, ".gitignore": ".env\n" }, (here, root) => {
      expect(checkCommand("git grep KEY", here)).toBeNull();
      expect(checkCommand("git grep --untracked KEY", here)).toBeNull();
      expect(checkCommand("git grep --no-index KEY", here)).toMatch(SEARCH);
      // Control: once .env is tracked, a plain git grep prints it.
      spawnSync("git", ["add", "-f", ".env"], { cwd: root });
      expect(checkCommand("git grep KEY", here)).toMatch(SEARCH);
    }, { git: true });
  });

  it("Claude Code's Grep tool prints .env lines in content mode, unless git ignores the file or a filter leaves it out", () => {
    inProject(project, (here) => {
      expect(checkToolCall("Grep", { pattern: "KEY", output_mode: "content" }, here)).toMatch(SEARCH);
      expect(checkToolCall("Grep", { pattern: "KEY", path: ".", output_mode: "content" }, here)).toMatch(SEARCH);
      // Controls: names only (the default), a glob or type that leaves .env out, another directory.
      expect(checkToolCall("Grep", { pattern: "KEY" }, here)).toBeNull();
      expect(checkToolCall("Grep", { pattern: "KEY", output_mode: "files_with_matches" }, here)).toBeNull();
      expect(checkToolCall("Grep", { pattern: "KEY", output_mode: "content", glob: "*.ts" }, here)).toBeNull();
      expect(checkToolCall("Grep", { pattern: "KEY", output_mode: "content", glob: "!.env*" }, here)).toBeNull();
      expect(checkToolCall("Grep", { pattern: "KEY", output_mode: "content", type: "ts" }, here)).toBeNull();
      expect(checkToolCall("Grep", { pattern: "KEY", output_mode: "content", path: "src" }, here)).toBeNull();
    });
    inProject({ ...project, ".gitignore": ".env\n" }, (here) => {
      expect(checkToolCall("Grep", { pattern: "KEY", output_mode: "content" }, here)).toBeNull();
    }, { git: true });
  });
});

describe("printing a variable inside varlatch run", () => {
  const denied: [string, string][] = [
    ["varlatch --assisted run -e development -- bash -c 'echo \"STRIPE_KEY=$STRIPE_KEY\"'", "varlatch --assisted run -e development -- bash -c 'echo \"home is $HOME\"'"],
    ["varlatch run -- sh -c 'printf \"%s\\n\" \"${API_KEY}\"'", "varlatch run -- sh -c 'printf \"%s\\n\" \"${PATH}\"'"],
    ["varlatch run -- sh -c 'echo ${API_KEY:-unset}'", "varlatch run -- sh -c 'echo ${HOME:-unset}'"],
    ["varlatch run -- printenv HOME API_KEY", "varlatch run -- printenv HOME PATH"],
  ];

  it.each(denied)("denies %s, as printenv NAME is", (command) => {
    expect(checkCommand(command, ctx)).toMatch(DUMP);
  });

  it.each(denied)("control for %s: a shell variable such as HOME holds no Secret", (_command, twin) => {
    expect(checkCommand(twin, ctx), twin).toBeNull();
  });

  it("outside varlatch run, printing a variable is not printing the run's environment", () => {
    expect(checkCommand("echo \"$API_KEY\"", ctx)).toBeNull();
    expect(checkCommand("printenv API_KEY", ctx)).toBeNull();
  });
});

describe("runHook", () => {
  const event = (tool_name: string, tool_input: unknown, extra: Record<string, unknown> = {}) =>
    JSON.stringify({ session_id: "s", cwd: "/work/app", hook_event_name: "PreToolUse", tool_name, tool_input, ...extra });

  it("answers a denial in the PreToolUse decision format both coding agents read", () => {
    for (const format of ["claude", "codex"] as const) {
      const out = runHook(format, event("Bash", { command: "cat .env" }), ctx.env, "/");
      const parsed = JSON.parse(out);
      expect(parsed).toEqual({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: expect.stringMatching(ENV) },
      });
    }
  });

  it("gives no decision for an allowed call, another event, or input it does not understand", () => {
    expect(runHook("claude", event("Bash", { command: "npm test" }), ctx.env, "/")).toBe("");
    expect(runHook("claude", event("Bash", { command: "cat .env" }, { hook_event_name: "PostToolUse" }), ctx.env, "/")).toBe("");
    expect(runHook("claude", "not json", ctx.env, "/")).toBe("");
    expect(runHook("claude", "[]", ctx.env, "/")).toBe("");
    expect(runHook("codex", JSON.stringify({ tool_input: { command: "cat .env" } }), ctx.env, "/")).toBe("");
  });

  it("resolves relative paths against the event's cwd", () => {
    const out = runHook("claude", event("Read", { file_path: "../../home/dev/.config/varlatch/credentials.json" }, { cwd: "/work/app" }), ctx.env, "/");
    expect(out).toMatch(/credential store/);
  });
});
