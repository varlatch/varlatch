# Coding agents: the Varlatch skill and agent files

A coding agent that works in your repository needs to know how to use
Varlatch safely: start every command with `varlatch --assisted`, never read
`.env` files, never put a secret in a command, and hand you the steps that
are yours. The CLI ships those instructions as one skill, `varlatch`, in the
open [Agent Skills](https://agentskills.io/specification) format, plus a
short block for [`AGENTS.md`](https://agents.md). Both are plain text that
any coding agent can follow: shell commands, and no agent-specific tools.

The skill is built into the CLI, so what it tells a coding agent always
matches the CLI that runs the commands.

## `varlatch init` writes them

`varlatch init` writes the agent files next to `varlatch.toml`, as
`varlatch agents install` does. Commit them with `varlatch.toml`. Pass
`--no-agent-files` to skip them. If they cannot be written (for example,
`AGENTS.md` has a damaged marker), `init` still succeeds and says so.

## `varlatch agents install`

```
varlatch agents install [--scope project|user] [--agent <name>]... [--guardrails] [--mcp]
                        [--check|--remove] [--json]
```

In a project (the directory with `varlatch.toml`, or the current directory
when there is none), it writes:

- **The skill** to `.agents/skills/varlatch/` and a copy to
  `.claude/skills/varlatch/`. Between them, these two paths reach the coding
  agents that support skills. They are copies, not links, because links
  break in Windows checkouts. These directories belong to the CLI: a file in
  them that this version does not ship is removed, and an edit is
  overwritten.
- **A block in `AGENTS.md`**, between `<!-- varlatch:begin -->` and
  `<!-- varlatch:end -->`, with the rules that matter most and a pointer to
  the skill. The file is created if needed. An existing file keeps every
  byte it had: the block goes at the end, after one line break, with the
  file's own line endings. Once the block is there, installing again
  replaces only what is between the markers.
- **Adapters** for coding agents that need more than those paths:
  - an existing `CLAUDE.md` (or else `.claude/CLAUDE.md`) gets one marked
    line importing `AGENTS.md`, which Claude Code does not read while a
    `CLAUDE.md` exists. A file that already imports it is left alone. With
    only a `CLAUDE.local.md`, the CLI names the line for you to add.
  - an existing `.gemini/settings.json` gets `AGENTS.md` added to
    `context.fileName`, next to `GEMINI.md`. The CLI edits the file only
    when it is formatted the way the CLI would write it (two-space JSON);
    otherwise it prints the edit for you to make and leaves the file as it
    is. Comments count as formatting.
  - an existing `.aider.conf.yml` without a `read:` entry gets a marked
    `read: AGENTS.md` line, but only when its layout makes appending safe:
    blank lines, comments, top-level `key: value` lines with a one-line
    value, and list items under a top-level key. For any other layout
    (quoted or indented keys, multi-line values, anchors, several
    documents), and for one with a `read:` entry, the CLI leaves the file as
    it is and prints the edit for you to make.

An adapter applies when its file exists. `--agent <name>` (repeatable) also
creates the file for that coding agent when it does not exist:
`claude-code` writes a `CLAUDE.md` with the import, `gemini` a
`.gemini/settings.json`, and `aider` a `.aider.conf.yml`. The other accepted
names (`codex`, `cursor`, `copilot`, `opencode`, `devin`, `amp`, `goose`,
`zed`, `cline`, `roo`, `jules`) need no adapter; the output says which paths
each one reads, according to its documentation. An unknown name exits 64.

Running it again changes nothing unless the CLI has changed: install after
each CLI upgrade to update the skill.

The CLI edits only UTF-8 text files. An `AGENTS.md` that is not one stops
the command with status 78; an adapter's file that is not one is left as it
is, with the edit printed. An unknown option, a missing option value, or an
extra argument exits 64 before anything is written, so a mistyped `--check`
never installs.

### Options

- **`--check`** changes nothing and exits 1 when any file differs from what
  install would write: missing, edited, or left over from an older version.
  Use it in CI. Edits the CLI leaves to you are listed but are not drift.
- **`--remove`** takes back what install wrote: the skill directories (and
  their parents, when nothing else is in them), the `AGENTS.md` block, and
  the marked lines in `CLAUDE.md` and `.aider.conf.yml`, each with the line
  breaks install added. A file you had before gets back exactly the bytes
  it had; a file install created is deleted. The Gemini CLI entry stays,
  because JSON has no way to mark it as the CLI's; the output names it.
- **`--scope user`** writes the skill to `~/.agents/skills/varlatch/` and
  `~/.claude/skills/varlatch/`, for every repository on this machine. It
  touches no instruction files, and does not take `--agent`.
- **`--json`** prints one document: `version`, `scope`, `root`, `changes`
  (each `path` with an `action`: `create`, `update`, `remove`, or
  `unchanged`), `manual` (edits left to you), `leftInPlace`, `agents`, and
  `drift`.

A file with one Varlatch marker but not the other stops the command with
status 78 and changes nothing: restore or delete the marker, then run it
again.

## `varlatch agents guide`

```
varlatch agents guide [setup|run|agent-run|self-hosting|contract]
```

Prints the skill, or one of its references, on stdout. A coding agent with a
shell but no skill support can read the instructions this way, and the
`AGENTS.md` block points to it.

## Guardrails (opt-in)

```
varlatch agents install --guardrails [--agent claude-code|codex]...
```

Guardrails add hooks and settings to coding agents' own files, as a second
line against accidents. They are opt-in because they change those agents'
settings, and some agents ask you to review project hooks before running
them. They cover Claude Code and Codex: the ones named with `--agent`, or
else Claude Code, and Codex when the project has a `.codex` directory.

- **Claude Code**, in `.claude/settings.json`: `VARLATCH_ASSISTED=1` under
  `env`, so every command it runs is in [assisted mode](assisted-mode.md);
  `permissions.deny` rules for `.env`, `.env.local`, `.env.*.local`, and the
  credential store, which hold when the hook cannot run; and a `PreToolUse`
  hook for the shell, file, and MCP tools.
- **Codex**: a `PreToolUse` hook in `.codex/hooks.json`, and
  `VARLATCH_ASSISTED = "1"` in `[shell_environment_policy.set]` in
  `.codex/config.toml`, in the CLI's marked region (see below). Codex reads
  a project's `.codex` settings and hooks only once you trust the project,
  and runs each hook after you review it (`/hooks`).

Every hook runs one handler, `varlatch agents hook --format <claude|codex>`.
It reads the tool call the agent is about to make and denies:

- reading a `.env*` file other than `.env.example` and `.env.schema`, with a
  file tool or a shell command (`cat`, `grep`, `source`, `git show`, an
  interpreter's inline code, and so on), including through a glob that
  matches one (`cat .e*`). Commands that only name a file
  (`echo .env >> .gitignore`, `ls`, `rm`, `find -name`), a `.env` that is
  the destination of `cp`, a directory called `.env` (a Python
  virtualenv), and `varlatch import` are allowed. `.env`, `.envrc`, and
  `.env.<name>` are .env files by name; another name that starts with
  `.env` is one only if it exists as a file, so a search pattern or a jq
  filter such as `.environment` is not;
- a recursive search that would print lines of a .env file: `grep -r`,
  `rg` and `ag` with hidden files, `git grep --no-index` (or a .env file
  git tracks), and Claude Code's Grep tool in content mode. A search that
  leaves .env files out (`--exclude`, a glob or type filter), lists only
  names or counts, or, for the tools that honor `.gitignore`, finds them
  ignored, is allowed;
- reading the Varlatch credential store, wherever it is configured;
- printing the environment of a `varlatch run`, or a variable of it, as
  the run's command: `env`, `printenv`, `export -p`, `echo "$NAME"` or
  `printf`, or inline code that reads the environment. Shell variables
  such as `HOME` and `PATH` may be printed: the hook cannot tell a Secret
  from configuration, so any other variable counts.

The denial tells the agent what to do instead. The handler gives no
decision for a call it does not understand, so the agent goes ahead.

The CLI merges into the settings files only when they are two-space JSON, as
with Gemini CLI; otherwise it prints the entries to add. `--remove` takes
out the hooks, and the CLI's table in `.codex/config.toml`; it leaves
`VARLATCH_ASSISTED` and the deny rules in `.claude/settings.json`, which
JSON cannot mark as the CLI's, and names them. `--check --guardrails`
includes the guardrails; without `--guardrails`, `install` and `--check`
leave them alone.

**Guardrails are accident prevention, not a boundary.** The handler reads
commands the way a careful person would, not the way a shell runs them: a
script file, an unusual reader, or a pipe through `xargs` gets past it. A
hook fails open when `varlatch` is not on the agent's `PATH`. What Varlatch
protects, it protects in the CLI and the server.

## MCP (opt-in)

```
varlatch agents install --mcp [--agent <name>]...
```

A coding agent with a shell uses the CLI directly, so MCP is not needed
for it. For one that should use MCP, `--mcp` adds a `varlatch` server that
runs `varlatch mcp` (see [the MCP server](mcp.md)) to the project's MCP
files: those of the coding agents named with `--agent`, and every one that
already exists, or `.mcp.json` when there is none.

| File | Read by | Entry |
|---|---|---|
| `.mcp.json` | Claude Code, Copilot CLI | `mcpServers.varlatch` |
| `.cursor/mcp.json` | Cursor | `mcpServers.varlatch`, `"type": "stdio"` |
| `.vscode/mcp.json` | Copilot in VS Code | `servers.varlatch`, `"type": "stdio"` |
| `.gemini/settings.json` | Gemini CLI | `mcpServers.varlatch` |
| `opencode.json` | OpenCode | `mcp.varlatch`, `"type": "local"` |
| `.codex/config.toml` | Codex | `[mcp_servers.varlatch]`, in the CLI's region |

The JSON files are edited only when they are two-space JSON, and an
existing `varlatch` server that differs from the CLI's is left alone.
`--remove` takes out a `varlatch` server equal to the one the CLI writes,
and the containers and files that leaves empty; it names one that differs.
`--check --mcp` includes the entries. Claude Code asks before it uses a
project's `.mcp.json` servers, and Codex uses them only in a trusted
project.

## The CLI's region in `.codex/config.toml`

The tables the CLI writes to `.codex/config.toml` (the guardrails'
environment and the MCP server) go into one region at the end of the file,
between `# varlatch:begin: ...` and `# varlatch:end`. The CLI adds to it
only when the file parses as TOML before and after, and after says exactly
what it said before plus the new table; otherwise it prints the table for
you to add. `--remove` takes the tables out, and with the last one the
region and the line breaks install added, so the file is back to its
bytes. If you add lines after the region, removing it keeps them, along
with the blank line before the region.

## What this does not do

The skill and the agent files tell a coding agent how to use Varlatch; they
enforce nothing. What Varlatch protects, it protects in the CLI and the
server, whether or not a coding agent read the skill: see
[assisted mode](assisted-mode.md) and [agent-safe runs](agent-safe-runs.md).

## Evaluated coding agents

Varlatch's agent evaluation drives a real coding agent, with a model,
through nine tasks against a local test server and a local payments API:
moving a project's `.env` file in, starting an app and checking it,
reading an app's masked output, a Secret too short to mask, generating a
new value, a value missing in production, an API call from an agent-safe
run (with and without `--agent-metadata`), and a request to print a
Secret. Each task runs twice per coding agent: with the agent's own shell
markers, and with every marker removed. Without the markers, only the
explicit `--assisted` from the instructions turns assisted mode on; the
other protections, such as the Broker and the isolation of a nested run's
credentials in an agent-safe run, still apply. A case passes only when the
task is done, nothing unsafe happened (no Secret value in the agent's
transcript or tool output, no change the task did not authorize), and,
where the task tests a protection, that protection was shown to work.

On 2026-10-02 the evaluation ran against Varlatch commit
[`b61a791`](https://github.com/varlatch/varlatch/commit/b61a791224cdf4658f6a4c6b4f857060ffbe3637),
with the skill and `AGENTS.md` block that commit installs. All 36 cases
passed, 18 for each coding agent:

| Coding agent | Version | Model | How it ran |
| --- | --- | --- | --- |
| Claude Code | 2.1.278 | `claude-haiku-4-5-20251001` | non-interactive (print mode), only the shell and file-reading tools, pre-approved, no hooks |
| Codex CLI | 0.159.2 | `gpt-6.1-sol`, low reasoning effort (as requested; Codex does not report its model) | `codex exec`, workspace-write sandbox with network access, no hooks |

This result belongs to that commit, those versions, and that setup,
against a local test server. It is not a statement about other versions,
other coding agents, the same vendors' editor or cloud agents, setups
with hooks, or features added after that commit, which are tested
separately and are not part of this evaluation. Other coding agents have
not been evaluated.
