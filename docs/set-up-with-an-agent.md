# Set up with a coding agent

Your coding agent can set Varlatch up in a repository for you. It installs
the CLI, connects the repository, and moves your `.env` files in. You do
the steps that need you: signing in with your passkey, choosing names, and
typing any secret it does not have. Give your agent this, with your
installation's address:

```text
Set up Varlatch in this repository, following
https://docs.varlatch.com/set-up-with-an-agent/
Our Varlatch server is https://vault.example.com
```

The steps below are plain shell commands, the same ones
[Getting started](getting-started.md) shows you. Nothing is piped into a
shell, and you can read every step before your agent runs it.

## Before you start

- **An installation.** One person on your team runs it, once, on a Linux
  host with Docker: [Run an installation](getting-started.md#run-an-installation).
  Your agent does not set up the server for you. `varlatch setup` asks you
  to choose the address, creates the first passkey, and hands you the
  recovery keys, which no agent should see.
- **An account on it.** You ran the setup, or you opened an invitation and
  created your passkey ([Join a project](getting-started.md#join-a-project)).
- **Node.js** 22, 24 or 26, at least 22.23.4, 24.22.1 or 26.12.1
  ([Node.js version](getting-started.md#nodejs-version)).
- **[cosign](https://docs.sigstore.dev/cosign/system_config/installation/)**,
  to check that the CLI was published by Varlatch's release workflow
  ([Verifying a release](operations/verify-release.md)).

## What you do, and what your agent does

| Step | Your agent | You |
|---|---|---|
| Install the CLI | downloads the release your installation runs and checks its signature | |
| Sign in | starts the sign-in and gives you an address and a code | approve it with your passkey |
| Connect the repository | runs `varlatch init` | choose the organization and project |
| Move `.env` files in | shows the names it found, without values, then imports | say which items are not secret, and approve each value Varlatch already has |
| Missing values | names them, and gives you a command for each | type each value into the hidden prompt |

Your agent never sees a secret value on this path. Assisted mode
([Assisted mode](reference/assisted-mode.md)) protects against accidents:
your agent runs as you, so your approvals are what stop deliberate misuse.

## For the coding agent

Follow these steps in order. They hold until `varlatch init` has installed
the Varlatch skill; from then on, follow the skill and the `AGENTS.md`
block too.

**Rules.** Start every Varlatch command with `varlatch --assisted`. Never
read, print, or create `.env` files, and never put a secret value in a
command. Signing in, choosing names, and typing a secret belong to the
human: when a step needs them, give them what the step says and wait for
their answer. When a command is refused for missing permission, stop and
tell the human: never work around it.

### 1. Find the installation

Use the address the human gave you. If they gave none, ask for it. If they
have no installation yet, stop: point them to
[Run an installation](getting-started.md#run-an-installation), and
continue when they give you its address.

The installation reports its version without signing in:

```sh
curl -fsS https://vault.example.com/v1/meta
```

`serverVersion` in the reply is the release to install.

If the repository already has `varlatch.toml`, it is already set up:
never run `varlatch init` there. Install the CLI (step 2), sign in
(step 3), and go to step 6.

### 2. Install the CLI

If `varlatch --assisted --version` already prints the installation's version, skip
this step. Check `node --version` against the versions under
[Before you start](#before-you-start), and check that `cosign version`
works. If Node.js or cosign is missing, or Node.js is older, stop and tell
the human: installing them is theirs to decide.

On Linux and macOS, check the release's signature, then the CLI against
`SHA256SUMS`, and only then install it in `~/.local/bin`. Run the block as
it is: each step runs only when the one before it succeeded (`&&`), so a
failed download or check never reaches `install`.

```sh
V=0.20.0  # serverVersion from step 1
REPO=varlatch/varlatch
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v${V}"
ISSUER=https://token.actions.githubusercontent.com
BASE="https://github.com/$REPO/releases/download/v$V"
curl -fLO "$BASE/varlatch-cli-$V.cjs" &&
  curl -fLO "$BASE/SHA256SUMS" &&
  curl -fLO "$BASE/SHA256SUMS.sigstore.json" &&
  cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" &&
  if command -v sha256sum >/dev/null; then
    sha256sum --ignore-missing -c SHA256SUMS
  else
    grep " varlatch-cli-$V.cjs\$" SHA256SUMS | shasum -a 256 -c -
  fi &&
  mkdir -p ~/.local/bin &&
  install -m 755 "varlatch-cli-$V.cjs" ~/.local/bin/varlatch &&
  varlatch --assisted --version
```

`sha256sum` is on Linux; macOS uses `shasum`. If the block stops, or the
release has no `SHA256SUMS.sigstore.json`, tell the human what failed: do
not install the file another way. Releases 0.15.0 and earlier are not signed: for those,
stop and point the human to
[Verifying a release](operations/verify-release.md). On Windows, follow
[On Windows](getting-started.md#on-windows), with the signature check
first. If `~/.local/bin` is not on the `PATH`, tell the human.

### 3. Sign in

```sh
varlatch --assisted login --server https://vault.example.com --start
```

It prints an address and a code. Give the human both: they open the
address on any device, enter the code, and approve with their passkey.
Wait until they say they approved it. Then:

```sh
varlatch --assisted login --server https://vault.example.com --wait
```

Exit 75 means the approval is still pending: ask the human, and run
`--wait` again when they say so. Exit 77 means the sign-in was denied or
expired (a code lasts 10 minutes): start again. Never approve the sign-in
yourself.

### 4. Connect the repository

List the organizations the human can use:

```sh
varlatch --assisted org list --server https://vault.example.com --json
```

Ask the human which organization and which project to use. A project
usually matches one repository. Create only what they asked for:

```sh
varlatch --assisted org create acme "Acme" --server https://vault.example.com
varlatch --assisted project create api --org acme --server https://vault.example.com
```

Then connect the repository:

```sh
varlatch --assisted init --org acme --project api --server https://vault.example.com
varlatch --assisted env list --json
```

`init` writes `varlatch.toml`, which holds no credential, and the agent
files: the Varlatch skill and a block in `AGENTS.md`. The default
environment is `development`. If `env list` does not show it, create it:

```sh
varlatch --assisted env-create development --tier development
```

Create other environments, such as `production`, only when the human asks
(`--tier staging` or `--tier production`).

### 5. Move `.env` files in

List the repository's `.env` files by name only (`ls -a`, never their
contents). Leave out templates and examples, such as `.env.example`,
`.env.sample`, and `.env.template`, and the `.env.schema` file: they are
not configuration, and an import would store their placeholders and delete
them. Ask the human about any file whose role is unclear. Then agree with
the human which environment each file belongs to (`.env` is usually
`development`, `.env.production` is `production`); create a missing
environment only when they ask (step 4).

For each file, look first:

```sh
varlatch --assisted import .env -e development --dry-run --json
```

The dry run lists names, inferred types, and which items would be Secrets,
never values, and marks the names the environment already has. Show the
human the names. Every new item is a Secret unless the human confirms it is
not secret (a port, a log level). Replace a value Varlatch already has only
when the human approves that item. Tell the human that the import deletes
the file once every value is stored. Then:

```sh
varlatch --assisted import .env -e development --contract --plain PORT --delete-source --json
```

`--plain` names only items the human confirmed; `--replace <NAME>` only
items they approved. If the import's JSON output has a Contract revision
(`contract.revision.id` is not null), activate it:

```sh
varlatch --assisted contract activate <revision>
```

A file whose items the Contract already has creates no revision: there is
nothing to activate. A failed import names the items it stored and those it
did not, never values: fix the cause and run it again.

### 6. Check each environment

See which environment and server the repository uses:

```sh
varlatch --assisted context --json
```

Check every environment you imported into, and the one `context` shows,
each by name, and keep any `--server` the human gave you:

```sh
varlatch --assisted validate -e development --json
```

Exit 0 means the environment satisfies the Contract. Exit 1 means it does
not, and exit 2 means not every item could be checked. Either way, read all
four lists in the JSON, `missing`, `invalid`, `unresolved`, and
`notEvaluated`, and report every entry to the human by name.

For each missing value, give the human this command for their own terminal,
with the same environment, where a hidden prompt asks for the value:

```text
varlatch values set <NAME> -e development
```

Never run that command yourself. When the human asks for a new random value
(a session key, say), generate it instead, in that same environment:
`varlatch --assisted values set <NAME> -e development --generate hex:32`.
When the human says they entered the values, validate again. Start the
application only when the human asks:
`varlatch --assisted run -e development -- <command>`.

### 7. Finish

Tell the human:

- the installation, organization, project, and environments you used;
- the items you imported, by name, and which ones are not secret;
- each environment's validation result, and the items still missing or
  invalid, with the command for each;
- the files you wrote: `varlatch.toml`, `.agents/skills/varlatch/`,
  `.claude/skills/varlatch/`, and the block in `AGENTS.md`. They should be
  committed, so everyone on the repository uses the same project. Commit
  only if the human asks.

## Next

- [Invite your team](getting-started.md#invite-your-team).
- [Connect CI and other machines](getting-started.md#connect-ci-and-other-machines).
- [Coding agents](reference/coding-agents.md): the skill, and optional
  guardrails for Claude Code and Codex.
