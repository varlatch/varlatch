# Setting up a project with Varlatch

## Signing in

Signing in is the human's step: it opens a browser for a passkey. Give them
this command, with the server's URL, and wait:

```text
varlatch login --server https://varlatch.example.com
```

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
output. Look first, then import:

```sh
varlatch --assisted import .env --dry-run --json
varlatch --assisted import .env --contract --delete-source
```

- `--dry-run` lists the names, inferred types, and sensitivity.
- `--contract` adds the file's new items to a Contract revision. New items
  are Secrets unless named with `--plain <NAME>`; use it only for values
  that are clearly not secret (a port, a log level). Activate the revision
  with `varlatch --assisted contract activate <revision>`.
- `--delete-source` deletes the file once every value is stored.
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
