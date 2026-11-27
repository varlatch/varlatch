# Connect a project

Connect a repository to a Varlatch server you can sign in to.
No server yet? [Install Varlatch](self-hosting.md) first.
No CLI yet? [Install the CLI](reference/install-the-cli.md).

Varlatch organizes configuration into **Organizations → Projects →
Environments** (such as `development` and `production`). A project usually maps
to one repository and has a **Contract** declaring which keys the app needs,
their types, and which ones are Secrets.

## The quick way

In your repository directory, run one interactive command:

```sh
varlatch init
```

The wizard walks you through everything and prints the equivalent command at
each step:

1. **Sign in** to your server if you aren't already.
2. **Pick or create** the organization and project.
3. **Create environments** (`development` and `production` by default if none exist).
4. **Write `varlatch.toml`** and the instruction files coding agents read.
5. **Import your `.env` files**—showing names, inferred types, and sensitivity
   (never values), adding new items to the Contract, and asking before
   overwriting existing values or activating the Contract.
6. **Clean up** by offering to delete each `.env` file once every value is
   safely stored.

Once that finishes, jump straight to [Run your application](#run-your-application)
below.

---

## Step-by-step (manual or scripted)

Use the individual commands below if you prefer doing each step manually, or in
scripts / CI where `varlatch init` does not prompt interactively.

### Create the project

Sign in from your machine. The CLI opens your browser, or prints the address to
open, and you approve with your passkey:

```sh
varlatch login --server https://vault.example.com
```

The first server you sign in to becomes your default server, so the
commands below need no `--server` outside a repository
([The default server](reference/passkeys-and-sessions.md#the-default-server)).
If you use more than one installation, check which one that is with
`varlatch server` first, or pass `--server`.

Create an organization and a project, either in the dashboard, which walks
you through the same steps, or with the CLI:

```sh
varlatch org create acme "Acme"
varlatch project create api --org acme
```

A project created with the CLI takes its contract from the repository.
Pass `--managed` to `project create` to edit the contract in the dashboard
instead.

Then, in the repository:

```sh
varlatch init --org acme --project api
varlatch env-create development --tier development
varlatch env-create production --tier production
```

`varlatch init` writes `varlatch.toml`, which names the server (your default
server, unless you pass `--server`), organization, project, and default
environment (`development`). It holds no credentials:
commit it, so everyone working on the repository uses the same project. It
also writes the files coding agents read, described in
[Coding agents](reference/coding-agents.md); `--no-agent-files` skips them.

## Add the configuration

### Move an existing `.env` file in

If the project already has a `.env` file, import it. The CLI reads the file
itself, so values never appear on the command line or in its output:

```sh
varlatch import .env --dry-run                    # the plan: names, types, Secrets; stores nothing
varlatch import .env --contract --delete-source   # store the values, then delete the file
varlatch contract activate <revision>             # the revision import printed
```

`--contract` adds the items the contract does not have yet, each as a
Secret unless you name it with `--plain <NAME>`. The values go to the
default environment; fill another one the same way, for example with
`varlatch import .env.production -e production`.
[Importing](reference/import.md) has the details.

### Or start from a contract

Describe the items in a `.env.schema` file in the repository:

```
# @required
# @type=url
DATABASE_URL=

# @public
PORT=8080
```

Then push and activate it, and set the values:

```sh
varlatch contract push --schema .env.schema
varlatch contract activate <revision>    # the revision push printed
varlatch values set DATABASE_URL         # a hidden prompt asks for the value
```

Items are Secrets unless marked `@public`.
[The `.env.schema` format](reference/env-schema.md) lists everything a
contract can say.

## Run your application

```sh
varlatch validate                 # does the environment satisfy the contract?
varlatch run -- npm run dev       # the default environment
varlatch run -e production -- node server.js
```

`varlatch run` gives the values to your command as environment variables.
No file of secrets is written to disk. To go further:

- `varlatch types --out src/config.ts` (or `app/varlatch_config.py`)
  generates typed access to the configuration:
  [Type generation](reference/type-generation.md).
- `varlatch scan --install-hook` adds a pre-commit hook that stops you from
  committing one of your Secrets: [Secret scanning](reference/secret-scanning.md).

## Invite your team

```sh
varlatch invite "Ada Lovelace"                 # a member
varlatch invite "Grace Hopper" --role admin    # an organization admin
```

Each invitation is a one-time link: send it to that person, who follows
[Join a team](join-a-team.md). The dashboard does the same under Access,
then Members. What members can reach, and removing someone, are in
[Members and access](reference/members.md).

## With coding agents

Varlatch lets a coding agent use a credential without being able to read it.
`varlatch init` already wrote the instructions agents read. Then:

- [Coding agents](reference/coding-agents.md): the skill, guardrails, and the
  agents Varlatch was evaluated with.
- [Assisted mode](reference/assisted-mode.md): an agent driving the CLI with
  your sign-in, with every Secret masked in what it sees.
- [Agent-safe runs](reference/agent-safe-runs.md): an agent that gets
  placeholders instead of Secrets.
- [The MCP server](reference/mcp.md), for MCP hosts without a shell.

A change that needs your approval (such as turning a security control
down) never goes through on an agent's word: the agent stops and shows you
an address, and you approve with your passkey. See [Security controls and
approvals](reference/security-controls.md#coding-agents).

## Where to go next

- [CI and other machines](reference/ci-and-machines.md): OIDC for CI,
  credentials for servers, and pushing values to platforms.
- [Removing Varlatch](reference/uninstall.md): deleting a project or an
  organization, and what the CLI leaves in a repository.
- [`CONTEXT.md`](../CONTEXT.md): the vocabulary, from planes and identities
  to grants and contracts.
- [Scripting](reference/scripting.md): JSON output and exit statuses.
