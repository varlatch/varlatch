---
name: varlatch
description: >-
  Use in a repository that has varlatch.toml, or when the user mentions
  Varlatch, secrets, environment variables, or .env files for running,
  testing, deploying, or setting up a project. Covers moving .env files into
  Varlatch without reading them, running commands with configuration
  injected, adding or generating secrets without seeing them, Contracts and
  generated types, and working inside an agent-safe run.
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
   over to the next command.
2. **Never read, print, or create `.env` files**, and never read the
   Varlatch credential store. To see which names a `.env` file sets, without
   their values: `varlatch --assisted import <file> --dry-run`.
3. **Never put a secret value in a command.** Store a secret with
   `varlatch --assisted import`, `values set <NAME> --generate hex:32`,
   `--from-file <path>`, or `--stdin`, or ask the human to enter it. (Inside
   an agent-safe run your variables hold Placeholders, not secrets: see rule 8.)
4. **Run anything that needs configuration with**
   `varlatch --assisted run -- <command>`. Exit status 78 means the
   configuration cannot run as it is: a Contract violation, or a secret too
   short to mask. Report the names in the error, then stop and ask. Never add
   `--allow-unmasked` or `--no-redact` yourself; when the human approves
   showing one item unmasked, the option goes before `--`:
   `varlatch --assisted run --allow-unmasked <NAME> -- <command>`.
5. **Never replace an existing value or change an item's sensitivity
   without the human's approval for that named item.** Approval for one item
   does not cover another: never regenerate or reclassify items the human did
   not name, even to make a command run.
6. **When a value is missing**, report its name and environment, and give
   the human this command for their own terminal, where it prompts without
   showing the value (no `--assisted`: assisted mode never prompts), or point
   them to the dashboard. Never invent a value.

   ```text
   varlatch values set <NAME> -e <environment>
   ```
7. **When a step needs the human** (signing in, entering a secret, approving
   a change to a value, launching an agent-safe run), give them the exact
   command or URL, then stop and wait.
8. **Inside an agent-safe run** (`VARLATCH_AGENT_RUN` is set), your
   variables hold Placeholders, not secret values. Putting a Placeholder in
   a `varlatch --assisted request` header or body target is how you use a
   secret there; a real secret value stays forbidden. curl and fetch are
   refused by the Broker. For example:
   `varlatch --assisted request -X POST -H "Authorization: Bearer $STRIPE_KEY" --json '{"amount": 500}' https://api.example.com/v1/charges`
9. **Read machine output.** Pass `--json` and parse it, never the human
   format. Exit statuses: 64 the command line is wrong, 69 the server cannot
   be reached, 77 not signed in or denied, 78 configuration that cannot run.
   On 69, a sandbox around your commands may be blocking the connection: tell
   the human which server the command tried to reach (`varlatch --assisted
   context --json` shows it), and ask them to allow that connection. Do not
   try to work around it.
10. **Know the limits.** Output is masked only for values Varlatch delivered
    or knows by name, and only in the forms it recognises. Never print,
    encode, or transform environment values.

## Moving a project's `.env` into Varlatch

```sh
varlatch --assisted import .env --dry-run --json
varlatch --assisted import .env --contract --plain LOG_LEVEL --delete-source --json
varlatch --assisted contract activate <revision>
varlatch --assisted run -- <command>
```

1. The dry run lists names, inferred types, and sensitivity; no values.
2. The import stores every value and adds the new items to a Contract
   revision. New items are Secrets unless named with `--plain`: use it only
   for items confirmed not secret (a port, a log level), and ask the human
   when unsure. `--delete-source` deletes the file only after every value
   was stored.
3. Activate the revision the import printed (`contract.revision.id` in its
   JSON output).
4. Start the app with its configuration.

## Common commands

```sh
varlatch --assisted context --json
varlatch --assisted values list --json
varlatch --assisted validate --json
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
