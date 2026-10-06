# Getting started

Varlatch is self-hosted. One person on your team runs an installation, and
everyone else connects to it with the CLI and a passkey. This page takes you
from nothing to `varlatch run`:

1. [Get the CLI](#get-the-cli), on the installation's host and on every
   developer's machine.
2. [Run an installation](#run-an-installation), once per team.
3. [Set up a project](#set-up-a-project), once per repository.
4. [Invite your team](#invite-your-team), and [join](#join-a-project) as a
   teammate.
5. [Connect CI and other machines](#connect-ci-and-other-machines).

Already invited to an installation? Get the CLI, then go to
[Join a project](#join-a-project).

## What you need

- **For the installation:** a Linux host, amd64 or arm64, with Docker and
  Docker Compose, and a way for people to reach it: a domain name pointing
  at the host, a Tailscale network, or your own reverse proxy.
  [Run an installation](#run-an-installation) explains the choice, and
  [Host requirements](self-hosting/requirements.md) lists memory, disk,
  and ports.
- **For each person:** Node.js 22 or newer for the CLI, and a browser that
  supports passkeys. Varlatch has no passwords: you sign in with a passkey
  kept on your device, in a password manager, or on a security key.

## Get the CLI

The CLI is one file, `varlatch-cli-<version>.cjs`, attached to every
release. It needs only Node.js 22 or newer. Use the version your
installation runs: the CLI and the installation are released together.

```sh
V=0.14.2  # the release your installation runs
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/varlatch-cli-$V.cjs
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

While the repository is private, download the same files with
`gh release download v$V -R varlatch/varlatch -p "varlatch-cli-*" -p SHA256SUMS`.
Releases from the public repository also sign `SHA256SUMS`: check that
signature first, as [Verifying a release](operations/verify-release.md)
describes. On macOS, check the file with
`grep " varlatch-cli-$V.cjs\$" SHA256SUMS | shasum -a 256 -c -`.

Then put it on your `PATH` as `varlatch`:

- **On your own machine,** a directory you own, so that
  `varlatch self-update` can replace it without `sudo`:

  ```sh
  mkdir -p ~/.local/bin
  install -m 755 varlatch-cli-$V.cjs ~/.local/bin/varlatch
  varlatch --version
  ```

- **On the installation's host,** root-owned, as the backup runbook's
  [Install the operator CLI](operations/backup.md#install-the-operator-cli)
  describes. Replace it after every upgrade.
- **On Windows,** run it as `node varlatch-cli-<version>.cjs`.

`varlatch self-update` installs a newer release the same way: it checks the
file against `SHA256SUMS`, and the signature when the release is signed and
cosign is installed.

## Run an installation

Skip this if someone already runs one for you.

On the host, download the deployment bundle of the same release, check it,
and unpack it where the installation will live:

```sh
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/varlatch-compose-$V.tar.gz
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf varlatch-compose-$V.tar.gz
cd varlatch-$V
varlatch setup
```

Run it as a user who can use Docker. `varlatch setup` first asks how people
will reach Varlatch:

| Choice | Address | You need |
|---|---|---|
| **public** | `https://vault.example.com`, with a certificate a bundled Caddy obtains | the name resolving to this host in public DNS, and ports 80 and 443 reachable from the internet |
| **tailnet** | `https://<machine>.<tailnet>.ts.net`, for members of your tailnet only | a Tailscale auth key, and MagicDNS and HTTPS certificates enabled in the Tailscale admin console |
| **external** | whatever your reverse proxy serves; also for a LAN-only installation | a proxy forwarding to `127.0.0.1:8787`, WebSocket upgrades included |

Choose carefully: the address is where passkeys are registered, so changing
it later means everyone registers their passkey again.

Then setup does the rest, and tells you what it is doing:

1. It generates every key and password the installation needs, as files in
   `./secrets`, and starts the services.
2. It prints a one-time link. Open it and create the first administrator's
   passkey. Setup waits until you have.
3. It walks you through keeping the two recovery keys off this host: the
   Root KEK, which every stored value depends on, and the backup key. Without
   a copy of the Root KEK, a backup cannot be restored. Do not skip this.
4. It finishes with `varlatch doctor`, a read-only health check you can run
   on the host at any time.

If setup stops halfway, for a failed download, a reboot, or a cancelled
passkey prompt, run it again: it continues where it stopped and never
replaces a key it already made.

Next, schedule backups: [Backup and recovery](operations/backup.md) covers
where they go and how to test a restore. The
[deployment guide](../infra/compose/README.md) covers every setup option,
running on Coolify, and upgrades.

## Set up a project

Varlatch keeps configuration in **organizations**, which contain
**projects**, which contain **environments** such as `development` and
`production`. A project usually matches one repository. Its **contract**
lists the items the application needs, with a type for each and whether it
is a Secret, and Varlatch checks every environment against it.

Sign in from your machine. The CLI opens your browser, or prints the
address to open, and you sign in with your passkey:

```sh
varlatch login --server https://vault.example.com
```

Create an organization and a project, either in the dashboard, which walks
you through the same steps, or with the CLI:

```sh
varlatch org create acme "Acme" --server https://vault.example.com
varlatch project create api --org acme --server https://vault.example.com
```

A project created with the CLI takes its contract from the repository.
Pass `--managed` to `project create` to edit the contract in the dashboard
instead.

Then, in the repository:

```sh
varlatch init --org acme --project api --server https://vault.example.com
varlatch env-create development --tier development
varlatch env-create production --tier production
```

`varlatch init` writes `varlatch.toml`, which names the server, organization,
project, and default environment (`development`). It holds no credentials:
commit it, so everyone working on the repository uses the same project. It
also writes the files coding agents read, described in
[Coding agents](reference/coding-agents.md); `--no-agent-files` skips them.

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

### Run your application

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

Invite each person from the dashboard (Access, then Members), or from the
repository with the CLI:

```sh
varlatch invite "Ada Lovelace"                 # a member
varlatch invite "Grace Hopper" --role admin    # an organization admin
```

Each invitation is a one-time link: send it to that person. No email is
involved. Opening it creates their account and passkey.

Access is denied unless something allows it. A **member** can read and
change development environments, read staging environments, and see only the
names of production items. An **admin** can do everything in the
organization. For anything else, such as a member who deploys to
production, add a grant in the dashboard under Access.

## Join a project

When you have been invited:

1. Open the link you were sent and create your passkey.
2. [Get the CLI](#get-the-cli).
3. In your copy of the repository, which already has `varlatch.toml`:

   ```sh
   varlatch login --server https://vault.example.com
   varlatch run -- npm run dev
   ```

On a machine without a browser, such as a server over SSH or a container,
sign in with a code instead, approving it with your passkey on any other
device:

```sh
varlatch login --server https://vault.example.com --start   # prints an address and a code
varlatch login --server https://vault.example.com --wait    # after you approved it
```

`varlatch status` shows where you are signed in and when the credential
expires.

## Connect CI and other machines

Machines never use a person's passkey. Create a machine identity in the
dashboard, under Access, then Machines, and grant it the environments it
needs: like a person, it starts with no access.

- **CI that issues OIDC tokens,** such as GitHub Actions, needs no stored
  secret at all. Give a `ci` identity an OIDC binding: the token issuer
  (filled in for GitHub Actions), an audience you choose, and the subject
  your jobs' tokens carry, such as `repo:acme/api:*`. In the job, get the
  CLI as above, then sign in and run; on GitHub Actions, the job needs the
  `id-token: write` permission:

  ```sh
  varlatch login --server https://vault.example.com --oidc --org acme --audience <audience>
  varlatch run -e production -- ./deploy.sh
  ```

  On another CI system, pass its token with `--oidc-token`.

- **Servers and other workloads** use a credential shown once when you create
  the identity. Store it where the machine keeps its secrets, and sign in
  with `varlatch login --server <url> --token-stdin < credential-file`.

Varlatch can also push an environment's values to GitHub Actions, Coolify,
or Convex, for platforms that read their own settings: add a Sync Target in
the dashboard under Connections.

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

## Where to go next

- [`CONTEXT.md`](../CONTEXT.md): the vocabulary, from planes and identities to
  grants and contracts.
- [Scripting](reference/scripting.md): JSON output and exit statuses.
- [Threat model](THREAT-MODEL.md): what Varlatch guarantees, and what it does
  not.
- [`CHANGELOG.md`](../CHANGELOG.md): what each release changed, and how to
  upgrade.
