# Setting up a project with Varlatch

## Signing in

Signing in is the human's step: they approve it with their passkey. You can
start it, and finish it once they have approved:

```sh
varlatch --assisted login --server https://varlatch.example.com --start
```

It prints an address and a code. Give the human both: they open the
address in a browser, on any device, sign in, enter the code, and approve.
Then stop and wait until they say they approved it. Only then run:

```sh
varlatch --assisted login --server https://varlatch.example.com --wait
```

It stores the credential and exits 0. Exit 75 means it is still waiting
for the approval: ask the human whether they approved, and run `--wait`
again when they say so. Exit 77 means the sign-in was denied or expired (a
code lasts 10 minutes): start again with `--start`. Never ask for the
code's approval on the human's behalf, and never approve it yourself.

A human who signs in with a credential instead (a service token, say)
pipes it in, so it never appears on a command line:

```text
op read op://vault/varlatch/token | varlatch login --server https://varlatch.example.com --token-stdin
```

Inside an agent-safe run (`VARLATCH_AGENT_RUN` is set) there is no
sign-in: every `login` exits 64. The run's read-only access comes from the
operator relaunching it with `--agent-metadata`.

Check the result yourself:

```sh
varlatch --assisted status --json
```

## Connecting the repository

```sh
varlatch --assisted init --org <org> --project <project> --server https://varlatch.example.com
```

This writes `varlatch.toml` (commit it; it holds no credential) and the
agent files: this skill and a short block in `AGENTS.md`. Pick the
environment with `varlatch --assisted env list --json` and
`varlatch --assisted env use <name>`.

## Moving `.env` files in

`varlatch import` reads the file itself: its values never appear in your
output. A task to move the file in authorizes creating its items in the
intended environment: the one the human named, or the project's default
(`varlatch --assisted context --json`). Look first, then import:

```sh
varlatch --assisted import .env --dry-run --json
varlatch --assisted import .env --contract --plain LOG_LEVEL --delete-source --json
varlatch --assisted contract activate <revision>
```

- `--dry-run` lists the names, inferred types, and sensitivity.
- `--contract` adds the file's new items to a Contract revision. New items
  are Secrets unless named with `--plain <NAME>`; use it only for items
  confirmed not secret (a port, a log level), and ask the human when
  unsure. Activate the revision the import printed
  (`contract.revision.id` in its JSON output).
- `--delete-source` deletes the file only after every value was stored.
- `-e <environment>` imports into another environment, for example
  `.env.production` into `production`.

A failed import names the items stored and not stored, never values; run it
again after fixing the cause.

## Contracts and types

A Contract declares the items the project needs, their types, and which are
Secrets. From an `.env.schema` file:

```sh
varlatch --assisted contract push --schema .env.schema
varlatch --assisted contract activate <revision>
varlatch --assisted contract show
```

Generate a typed configuration module (TypeScript or Python, by extension):

```sh
varlatch --assisted types --out src/config.ts
```

## Checks for CI

```sh
varlatch --assisted validate -e production --json
varlatch --assisted types --out src/config.ts --check
varlatch --assisted scan --staged
```

`validate` exits 1 when the environment is invalid and 2 when not every item
could be checked. `types --check` exits 1 when the module is stale. `scan`
looks for this project's Secrets in staged files and never prints them;
`varlatch --assisted scan --install-hook` adds it as a pre-commit hook.
