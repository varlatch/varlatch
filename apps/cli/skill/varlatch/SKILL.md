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
   their values: `varlatch --assisted import --dry-run <file>`.
3. **Never put a secret value in a command.** Store a secret with
   `varlatch --assisted import`, `values set <NAME> --generate hex:32`,
   `--from-file <path>`, or `--stdin`, or ask the human to enter it.
4. **Run anything that needs configuration with**
   `varlatch --assisted run -- <command>`. Exit status 78 means the
   configuration cannot run as it is: a Contract violation, or a secret too
   short to mask. Report the names in the error. Never add `--allow-unmasked`
   or `--no-redact` yourself; those are the human's decisions.
5. **When a value is missing**, report its name and environment and ask the
   human. Never invent a value.
6. **When a step needs the human** (signing in, entering a secret, allowing
   an unmaskable value, launching an agent-safe run), give them the exact
   command or URL, then stop and wait.
7. **Inside an agent-safe run** (`VARLATCH_AGENT_RUN` is set), secrets are
   Placeholders. Call allowed APIs with `varlatch request`, not curl or
   fetch, which the Broker refuses.
8. **Read machine output.** Pass `--json` and parse it, never the human
   format. Exit statuses: 64 the command line is wrong, 69 the server cannot
   be reached, 77 not signed in or denied, 78 configuration that cannot run.
   On 69, a sandbox around your commands may be blocking the connection: tell
   the human which server the command tried to reach (`varlatch --assisted
   context --json` shows it), and ask them to allow that connection. Do not
   try to work around it.
9. **Know the limits.** Output is masked only for values Varlatch delivered
   or knows by name, and only in the forms it recognises. Never print,
   encode, or transform environment values.

## Common commands

```sh
varlatch --assisted context --json
varlatch --assisted values list --json
varlatch --assisted validate --json
varlatch --assisted run -- npm test
varlatch --assisted values set SESSION_SECRET --generate hex:32
varlatch --assisted import .env --dry-run
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
