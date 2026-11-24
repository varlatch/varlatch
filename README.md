<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="apps/docs/src/assets/varlatch-mark-on-dark.png">
    <img src="apps/docs/src/assets/varlatch-mark-on-light.png" width="88" alt="">
  </picture>
</p>

<h1 align="center">Varlatch</h1>

<p align="center">
  <strong>Self-hosted secrets and environment configuration, built for AI coding agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/varlatch/varlatch/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/varlatch/varlatch?sort=semver&label=release"></a>
  <a href="https://github.com/varlatch/varlatch/actions/workflows/ci.yml?query=branch%3Amain+event%3Aschedule"><img alt="Nightly CI on main" src="https://img.shields.io/github/actions/workflow/status/varlatch/varlatch/ci.yml?branch=main&event=schedule&label=CI"></a>
  <a href="LICENSE"><img alt="License: AGPL-3.0 and Apache-2.0" src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20Apache--2.0-blue"></a>
</p>

<p align="center">
  <a href="https://varlatch.com">Website</a> ·
  <a href="https://docs.varlatch.com">Documentation</a> ·
  <a href="docs/getting-started.md">Getting started</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/dashboard-dark.webp">
    <img src="docs/assets/readme/dashboard-light.webp" alt="The Varlatch dashboard: the configuration items of a project across its development, staging, and production environments, with secret values masked">
  </picture>
</p>

Varlatch is a self-hosted platform for secrets and environment configuration.
It stores, authorizes, audits, and delivers the configuration your
applications need, from a developer's laptop to CI and production. It is
designed from the start for teams that work with AI coding agents: an agent
can use a credential without ever being able to read it.

Varlatch is pre-1.0 and in daily use. The [changelog](CHANGELOG.md) lists what
each release added.

## Features

- **Environments and values.** Organizations, projects, and environments with
  versioned values. An environment can derive from another, and values can
  reference each other (`${DATABASE_HOST}`), expanded on the server.
- **Configuration contracts.** Declare which keys a project needs, which are
  sensitive, and what type each is, then validate every environment against
  that contract. Edit a contract in the dashboard or keep it as a schema file
  in your repository.
- **Encryption with a real boundary.** Secret values live in the server,
  `varlatchd`, with envelope encryption: an installation root key wraps a key
  per organization, which wraps a key per value version. The database alone,
  or a backup alone, yields no plaintext.
- **Passkey sign-in.** People sign in with passkeys, so there are no passwords
  to store or leak. Machines use scoped service credentials, or OIDC from CI
  such as GitHub Actions, with no stored secret at all.
- **Access control.** Default-deny grants, custom roles, groups, and teams,
  and restrictive requirements. A requirement can make an environment
  retrievable only from specific machines on your Tailscale network, checked
  by Tailscale identity rather than by IP address.
- **Safe for AI agents.** Using a secret and revealing it are separate
  permissions. `varlatch run --agent-safe` gives an agent placeholders instead
  of secrets, and a local broker substitutes the real values only in requests
  to destinations you allow, at the headers or fields you name. As a second
  line of defense it also masks a secret the destination echoes back, in the
  [forms it recognizes](docs/reference/agent-safe-runs.md). Every use is
  authorized and audited. An MCP
  server, `varlatch mcp`, lets MCP hosts inspect configuration metadata; it
  never returns or writes a Secret's value.
- **A complete audit log.** Every security-relevant action is recorded
  synchronously in an append-only log, exportable as NDJSON and deliverable to
  signed webhooks.
- **Rotation without downtime.** A rotated secret keeps its previous value
  available for a grace period, so running services move over before the old
  credential is revoked.
- **Sync to other platforms.** Push an environment's configuration to GitHub
  Actions, Coolify, or Convex. Every push is authorized and audited.
- **Operations built in.** One program, with its own database and dashboard.
  `varlatch setup` installs it as a service, with its own HTTPS certificate,
  behind your proxy, or over your tailnet only. Backups are encrypted and
  verified, never pause the service, and restore onto a fresh host. `varlatch
  doctor` checks an installation's health, and `varlatch upgrade` takes an
  encrypted snapshot before changing anything.
- **No artificial limits.** Unlimited projects, environments, users, and
  machines.

<p align="center">
  <img src="docs/assets/readme/agent-safe-run.webp" alt="A terminal running varlatch run with --agent-safe: the agent's environment holds a placeholder for STRIPE_SECRET_KEY, and DATABASE_URL is left out">
</p>

In an agent-safe run, the agent sees a placeholder instead of the Stripe key.
The local Broker puts the real key into the `Authorization` header of requests
to `api.stripe.com` only, and `DATABASE_URL` never reaches the agent at all.
[Agent-safe runs](docs/reference/agent-safe-runs.md) explains the details.

## A look around

<table>
  <tr>
    <td width="50%"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/audit-dark.webp"><img src="docs/assets/readme/audit-light.webp" alt="The audit log: a live list of who read, changed, or was denied what"></picture><br>
      <sub><b>Audit log.</b> Every security-relevant action, live, filterable, and exportable as NDJSON.</sub></td>
    <td width="50%"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/access-dark.webp"><img src="docs/assets/readme/access-light.webp" alt="The Access page: how access works, explained, above the list of people"></picture><br>
      <sub><b>Access.</b> Default-deny: people, machines, roles, teams, and grants.</sub></td>
  </tr>
  <tr>
    <td width="50%"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/contract-dark.webp"><img src="docs/assets/readme/contract-light.webp" alt="A project's contract: each item with its type, whether it is required, and whether it is secret"></picture><br>
      <sub><b>Contract.</b> Which items a project needs, of what type, and which are secret.</sub></td>
    <td width="50%"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/environment-dark.webp"><img src="docs/assets/readme/environment-light.webp" alt="One environment's values, with secrets masked until revealed"></picture><br>
      <sub><b>Environment.</b> Secrets stay masked; revealing one is recorded in the audit log.</sub></td>
  </tr>
</table>

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/architecture-dark.svg">
    <img src="docs/assets/readme/architecture-light.svg" width="820" alt="Architecture: untrusted clients (browser, CLI, CI, workloads, AI agents) authenticate end to end, over the public address or your tailnet, with varlatchd, the one program that is the Secret Plane and security authority. It alone writes its SQLite file, in which secret values and their keys are only ciphertext, and reads the Root KEK and the backup key from files kept apart">
  </picture>
</p>

- **`varlatchd` is the security authority.** It owns everything that feeds an
  authorization decision, and it is all there is to run: the API, the
  dashboard's files, HTTPS certificates, its tailnet node, and backups are one
  program. Every principal authenticates to it end to end.
- **The dashboard has no authority of its own.** It acts as the signed-in
  person, through the same API. Its live updates say that something changed,
  never what, and it reads the rest from the API.
- **One public API.** `varlatchd` serves `/v1`: OpenAPI-first, bearer tokens
  only, with capability discovery so clients and servers of different
  versions work together.
- **Authorization is simple on purpose.** Grants only ever add access, and
  requirements only restrict it. There are no deny rules and no policy
  language to get wrong.
- **One SQLite file, one writer.** Every write goes through one queue and is
  durable before it is answered. Every change of a value, a
  contract or a grant commits with its audit event, in the same transaction. The database refuses to change or remove an audit event.

This is Varlatch from 0.50, a prerelease now. 0.23.0 runs the same API on
PostgreSQL and a self-hosted Convex backend:
[its README](https://github.com/varlatch/varlatch/tree/v0.23.0#how-it-works).

## Getting started

[Getting started](docs/getting-started.md) sends you to the short path for
where you are: [joining a team](docs/join-a-team.md) you were invited to,
[setting up a project](docs/set-up-a-project.md), or
[running an installation](docs/run-an-installation.md).

### Run your own installation

Varlatch runs on any Linux host, amd64 or arm64, and on Coolify. The current
release, 0.23.0, runs with Docker Compose: follow
[its documentation](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/run-an-installation.md). From
0.50, a prerelease now, it is one program with its own database:
[Run an installation](docs/run-an-installation.md).

### Use the CLI

The CLI is one file attached to every release. 0.23.0's needs Node.js
([install it](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/reference/install-the-cli.md)); from
0.50 it needs nothing else: [Install the CLI](docs/reference/install-the-cli.md).

```sh
varlatch login --server https://varlatch.example.com
varlatch init --org acme --project api
varlatch run -- npm run dev
```

`varlatch run` passes the environment's values to your command directly, so
no file of secrets lands on disk. `varlatch types --out src/config.ts`
generates typed access to them for a TypeScript application, and
`varlatch types --out app/varlatch_config.py` for a Python one.

`varlatch run` forwards SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, and SIGUSR2
to your command (only the first two on Windows), so a service manager can stop
or reload a service through it, and it exits with your command's status: 128
plus the signal's number when a signal ended it, 130 for Ctrl-C. A signal sent
to the whole process group, such as Ctrl-C in a terminal, reaches your command
twice: from the terminal and forwarded.

### Develop Varlatch

The server and the CLI are in [`go/`](go/README.md), and need Go 1.27. The
dashboard, which `varlatchd` embeds, needs Node.js 26 and pnpm:

```sh
pnpm install && pnpm build
cd go
go generate ./server/web    # build the dashboard into varlatchd
go vet ./... && go test ./...
go build -o ../.dev/ ./cmd/varlatchd ./cmd/varlatch
```

To run that `varlatchd` on Linux, from the root of the checkout (`.dev/` is
not committed; `varlatchd` refuses a data directory below one its group or
others can write to):

```sh
install -d -m 700 .dev .dev/data
(umask 077; head -c 32 /dev/urandom | base64 > .dev/root-kek)
printf '%s\n' 'public_url = http://localhost:8686' \
  "data_dir = $PWD/.dev/data" "root_kek_file = $PWD/.dev/root-kek" > .dev/varlatchd.conf
.dev/varlatchd serve --config .dev/varlatchd.conf
```

In another terminal, `.dev/varlatchd admin bootstrap --config .dev/varlatchd.conf`
prints a one-time link that creates the first administrator's passkey.

`pnpm test` and `pnpm typecheck` check the TypeScript packages. `pnpm dev:up`
(Docker needed) runs the stack of 0.23.0, with PostgreSQL and Convex and
synthetic data; `pnpm dev:down` stops it and `pnpm dev:reset` deletes it.

## Documentation

The same documentation, searchable, is at
[docs.varlatch.com](https://docs.varlatch.com).

- [`docs/getting-started.md`](docs/getting-started.md): where to start,
  whether you were invited, are setting up a project, or run the
  installation
- [`CHANGELOG.md`](CHANGELOG.md): what changed in each release, and how to
  upgrade
- [`CONTEXT.md`](CONTEXT.md): the vocabulary, from planes and identities to
  grants and contracts
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md): what Varlatch guarantees,
  each guarantee mapped to a test, and what it explicitly does not
- [`docs/self-hosting.md`](docs/self-hosting.md): operating an installation
  from 0.50; [`infra/compose/README.md`](infra/compose/README.md): 0.23.0 and
  earlier, with Docker Compose
- [`docs/self-hosting/requirements.md`](docs/self-hosting/requirements.md):
  what a host needs, with measured memory, processor, and disk use
- [`docs/self-hosting/configuration.md`](docs/self-hosting/configuration.md):
  every setting of an installation
- [`docs/operations/backup.md`](docs/operations/backup.md): backups and
  recovery
- [`docs/operations/upgrade.md`](docs/operations/upgrade.md): upgrading, from
  0.50
- [`docs/operations/verify-release.md`](docs/operations/verify-release.md):
  verifying a release's signatures and provenance
- [`docs/operations/migrate-to-0.50.md`](docs/operations/migrate-to-0.50.md):
  migrating an installation to Varlatch 0.50
- [`docs/reference/env-schema.md`](docs/reference/env-schema.md): the
  `.env.schema` contract file format
- [`docs/reference/agent-safe-runs.md`](docs/reference/agent-safe-runs.md):
  running an agent with placeholders, and where the broker substitutes
- [`docs/reference/assisted-mode.md`](docs/reference/assisted-mode.md): a
  coding agent driving the CLI with your credential, without reading Secrets
- [`docs/reference/coding-agents.md`](docs/reference/coding-agents.md): the
  Varlatch skill and agent files, `varlatch agents install`
- [`docs/reference/import.md`](docs/reference/import.md): moving a `.env`
  file into Varlatch with `varlatch import`
- [`docs/reference/scripting.md`](docs/reference/scripting.md): JSON output,
  exit statuses, and help for scripts, CI, and agents
- [`docs/reference/mcp.md`](docs/reference/mcp.md): the MCP server,
  `varlatch mcp`
- [`docs/reference/type-generation.md`](docs/reference/type-generation.md):
  typed configuration for TypeScript and Python with `varlatch types`

## Security, support, and contributing

Report vulnerabilities privately, as [`SECURITY.md`](SECURITY.md) describes,
never as a public issue. Varlatch comes without support commitments. Fixes,
security fixes included, go into the latest release only, so upgrade with
`varlatch upgrade` to get them. Before 1.0, a minor release may change the
`/v1` API, the CLI, configuration, or the database schema; the changelog says
what to do.

Outside contributions are not accepted yet, but issues are welcome.
[`CONTRIBUTING.md`](CONTRIBUTING.md) explains.

## No warranty

Varlatch is provided "as is", without warranty of any kind, and Robotsson is
not liable for damage or loss from using it, to the extent the law allows.
The warranty and liability sections of the licenses are the binding terms:
sections 15 and 16 of the [AGPL-3.0](LICENSES/AGPL-3.0-or-later.txt) and
sections 7 and 8 of the [Apache-2.0](LICENSES/Apache-2.0.txt).

You run your installation and are responsible for it. Keep your Root KEK safe
and your backups tested: without them, encrypted values cannot be recovered.

## License

Copyright © 2026 Robotsson. Varlatch is open source, licensed by directory
(see [`LICENSE`](LICENSE)):

- **AGPL-3.0-or-later:** the server (`go/server`, `go/cmd/varlatchd`, and
  0.23.0's, `services/varlatchd`), the dashboard (`apps/web`), and 0.23.0's
  dashboard backend functions (`convex/`).
- **Apache-2.0:** everything else, including the CLI, the SDK and other
  packages, and the deployment files.

The Convex backend that 0.23.0 and earlier run by default is source-available,
not open source; from 0.50, Varlatch runs none. Its license, FSL-1.1-Apache-2.0, permits internal use but not offering
it to others as a competing commercial service, and each version becomes
Apache-2.0 two years after its release. Running Varlatch for your own
organization is internal use. [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)
lists every third-party component of a release with its license.
