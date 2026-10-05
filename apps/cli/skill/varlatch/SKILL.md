---
name: varlatch
description: >-
  Use in a repository that has varlatch.toml, or when the user mentions
  Varlatch, secrets, environment variables, or .env files for running,
  testing, deploying, or setting up a project, or asks whether an
  environment is ready to deploy. Covers moving .env files into Varlatch
  without reading them, running commands with configuration injected,
  checking an environment's readiness, adding or generating secrets without
  seeing them, Contracts and generated types, and working inside an
  agent-safe run.
license: Apache-2.0
metadata:
  generator: varlatch {{VERSION}}
---

# Varlatch

This project keeps its configuration and secrets in Varlatch. You drive the
`varlatch` CLI with the human's own credential. Their secret values must
never pass through your context, and the CLI is built to keep them out as
long as you follow these rules.

## Rules

1. **Start every Varlatch command with `varlatch --assisted`**, in every
   shell, even if an earlier command used it. Assisted mode masks secrets in
   command output and refuses unsafe forms; a shell variable does not carry
   over to the next command. A command printed for the human's own terminal
   (without `--assisted`) is theirs: never run it yourself.
2. **Never read, print, or create `.env` files**, and never read the
   Varlatch credential store. To see which names a `.env` file sets, without
   their values: `varlatch --assisted import <file> --dry-run`. A `.env`
   file may hold values not yet in Varlatch, or older copies of values that
   are: the dry run (`-e <environment>` for the environment you work in)
   marks the names it already has. Import only with the human's approval for
   each such name (see below). A repository
   with `varlatch.toml` is already set up: never run `varlatch init` there.
3. **Never put a secret value in a command.** Store a secret with
   `varlatch --assisted import`, `values set <NAME> --generate hex:32`,
   `--from-file <path>`, or `--stdin`, or ask the human to enter it. When the
   human asks for a new random value, generate it with `--generate`. A
   credential issued elsewhere (a provider's API key, a password someone
   chose) is the human's to enter: hand it over, and never invent one.
   (Inside an agent-safe run your variables hold Placeholders, not secrets:
   see rule 8.)
4. **Work in the environment the human named; otherwise in the project's
   default**, which `varlatch --assisted context --json` shows
   (`environment`, with `environmentSource`, and `server`). Never switch to
   another environment or server to get around missing configuration.
   **Run anything that needs configuration with**
   `varlatch --assisted run -- <command>`. Exit status 78 means the
   configuration cannot run as it is: a Contract violation, or a secret too
   short to mask. When the command does not need a secret that is too short
   to mask, leave it out and rerun, with no approval needed (the command
   then never gets it):
   `varlatch --assisted run -e <environment> --omit <NAME> -- <command>`.
   Otherwise report the names in the error, then stop and ask. Each
   remedy is the human's decision, for the named item (and environment)
   only. After they approve one, you may carry it out yourself, with
   `--assisted`:
   - a new random value replacing the item: `varlatch --assisted values set
     <NAME> -e <environment> --replace <NAME> --generate hex:32` (keep
     `--server <url>` when the server was overridden). A credential a
     provider issued is the human's to enter instead;
   - marking the item as not secret: a Contract change for the whole
     project, done as `references/contract.md` describes.

   Showing a Secret unmasked is the human's alone: never add
   `--allow-unmasked` or `--no-redact` (assisted mode refuses both). Their
   override, in their own terminal, shows only the named item and keeps
   every other Secret masked:

   ```text
   varlatch run -e <environment> --allow-unmasked <NAME> -- <command>
   ```

   If `run`
   says no values are stored in Varlatch, the command gets only what it
   inherits: check what it needs (`validate`, or its own output) and report
   that, rather than calling the run a success or a failure on that alone.
5. **Never replace an existing value or change an item's sensitivity
   without the human's approval for that named item.** Approval for one item
   does not cover another: never regenerate or reclassify items the human did
   not name, even to make a command run. In assisted mode, `values set`,
   `values rotate`, and `import` refuse (78) to replace an existing value
   unless that item is named with `--replace <NAME>`; add it only with the
   human's approval for that item. A value inherited from a parent
   environment counts: setting it in the child overrides it. `--replace`
   records the override, not an approval. **Create values only when the
   task asks for it** (setting up, importing, or a requested new value), in
   the environment it is for, or after the human approves that item in that
   environment. A task that already asks for the creation needs no second
   approval: an import may create the file's items in the intended
   environment, and a requested new random value is generated without
   asking again. Starting or checking an app that is already configured
   never authorizes creating values: report a missing one and hand it over
   (rule 6). Never invent configuration to make a run succeed. An item's sensitivity is part of
   the Contract and applies to the whole project: approval to change it
   covers that item, in every environment, and nothing else. **Never delete a value without
   the human's approval for that item in that environment.** In assisted
   mode `values delete` refuses (78) without `--confirm <NAME>`; add it only
   after that approval. It records the intent, not an approval.
6. **To find out whether an environment is ready** (to deploy, or what is
   missing or invalid), run `varlatch --assisted validate -e <environment> --json`.
   Listing values does not check the Contract. **When a value is missing**,
   report its name and environment, and give
   the human this command for their own terminal, where it prompts without
   showing the value (no `--assisted`: assisted mode never prompts; add
   `--server <url>` when the server was overridden), or point them to the
   dashboard. Never invent a value.

   ```text
   varlatch values set <NAME> -e <environment>
   ```
7. **When a step needs the human** (signing in, entering a secret, approving
   a change to a value, launching an agent-safe run), give them the exact
   command or URL, then stop and wait. To sign in, run
   `varlatch --assisted login --server <url> --start`, give them the address
   and the code it prints, wait until they say they approved it, then run
   `varlatch --assisted login --server <url> --wait` (see `references/setup.md`).
8. **Inside an agent-safe run** (`VARLATCH_AGENT_RUN` is set), your
   variables hold Placeholders, not secret values. Putting a Placeholder in
   a `varlatch --assisted request` header or body target is how you use a
   secret there; a real secret value stays forbidden. curl and fetch are
   refused by the Broker. For example:
   `varlatch --assisted request -X POST -H "Authorization: Bearer $STRIPE_KEY" --json '{"amount": 500}' https://api.example.com/v1/charges`
   The double quotes let the shell put the Placeholder in; in single quotes
   the request would carry the literal text `$STRIPE_KEY`, which the Broker
   cannot substitute. A tool that passes arguments without a shell must
   pass the Placeholder itself.
   `varlatch --assisted context --json` lists the run's Placeholders (names
   only, under `agentRun.placeholders`). Showing a listed one discloses
   nothing: when the human asks you to check it, `varlatch --assisted run --
   printenv <NAME>` shows its Placeholder. Never show any other variable
   there: the run also carries credentials (masked in a nested run's output)
   and inherited values that are not Placeholders.
9. **Read machine output.** Pass `--json` and parse it, never the human
   format. Exit statuses: 64 the command line is wrong, 69 the server cannot
   be reached, 75 a sign-in still waiting for the human's approval, 77 not
   signed in or denied, 78 configuration that cannot run.
   On 69, a sandbox around your commands may be blocking the connection: tell
   the human which server the command tried to reach (`varlatch --assisted
   context --json` shows it), and ask them to allow that connection. Do not
   try to work around it.
10. **Know the limits.** Output is masked only for values Varlatch delivered
    or knows by name, and only in the forms it recognises. Never print,
    encode, or transform environment values (the one exception: a listed
    Placeholder inside an agent-safe run, rule 8).

## Moving a project's `.env` into Varlatch

```sh
varlatch --assisted import .env --dry-run --json
varlatch --assisted import .env --contract --plain LOG_LEVEL --delete-source --json
varlatch --assisted contract activate <revision>
varlatch --assisted run -- <command>
```

1. The dry run lists names, inferred types, and sensitivity; no values. It
   marks the names the environment already has: the file may be an older
   copy. Ask the human about each of those; the import replaces one only
   with `--replace <NAME>` for it, and otherwise refuses (78) and stores
   nothing.
2. The import stores every value and adds the new items to a Contract
   revision. New items are Secrets unless named with `--plain`: use it only
   for items the human confirmed are not secret (a port, a log level), and
   ask when unsure. `--delete-source` deletes the file only after every
   value was stored.
3. If the import created a revision, activate it (`contract.revision.id` in
   its JSON output; none when every item was already in the Contract).
4. Start the app with its configuration.

## Common commands

```sh
varlatch --assisted context --json
varlatch --assisted values list --json
varlatch --assisted validate --json
varlatch --assisted validate -e production --json
varlatch --assisted run -- npm test
varlatch --assisted values set SESSION_SECRET --generate hex:32
```

## More

Read the reference for the task at hand. Each is also printed by
`varlatch --assisted agents guide <topic>`.

- `references/setup.md` (topic `setup`): signing in, `init`, moving `.env`
  files in with `import`, Contracts, generated types, CI checks.
- `references/run.md` (topic `run`): running commands, strict startup,
  output masking, storing and rotating values, exit statuses.
- `references/agent-run.md` (topic `agent-run`): agent-safe runs,
  Placeholders, and `varlatch request`.
- `references/self-hosting.md` (topic `self-hosting`): installing and
  operating a Varlatch server.
- `references/contract.md` (topic `contract`): correcting an item's
  sensitivity in the Contract.
