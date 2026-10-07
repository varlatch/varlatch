# Configuration reference

This page lists every setting you can change on an installation that runs
the canonical Docker Compose deployment. Almost all of them are variables
in `.env`, next to `docker-compose.yml`, and `varlatch setup` writes that
file for you. The [compose guide](../../infra/compose/README.md#first-install)
covers setup itself, and [Host requirements](requirements.md) what the host
needs.

On Coolify, these variables are the resource's environment variables, and
Coolify passes every one of them to every service. Keep secrets in files
there, as [Deploying on Coolify](../../infra/coolify/README.md#setup)
describes.

## How the configuration is applied

Docker Compose reads `.env` from the directory it runs in and substitutes
the values into the Compose files. A service sees a value only where a
Compose file passes it on, so a variable that no Compose file names has no
effect. `docker compose config` shows the result. It also prints every
secret that is set as a variable, so do not paste its output anywhere.

After you change `.env`, apply it in the installation's directory:

```sh
docker compose up -d
```

Compose recreates every service whose configuration changed. `docker
compose restart` is not enough: it restarts the containers with the
configuration they were created with.

Some values are used only once. The database passwords, for example, take
effect when PostgreSQL first creates its data directory:
[Keys and passwords](#keys-and-passwords) says which.

### The managed `.env`

`varlatch setup` writes `.env` on every run, from
[`varlatch-install.json`](#varlatch-installjson), with mode 0600. It holds
addresses, ports, and the paths of the secret files, never a secret value.
Its last managed line is:

```
# --- your additions below this line are kept by setup ---
```

Put the settings you add below that line. Setup keeps them on every rerun
and rewrites everything above it. If a variable appears twice, Compose uses
the later line.

Setup refuses to take over a `.env` it did not write. An installation
configured by hand moves to the managed file with
[`varlatch adopt`](../../infra/compose/README.md#existing-installations-varlatch-adopt).

For the public ingress at `https://vault.example.com`, setup writes this
(comments left out):

```
VARLATCH_PUBLIC_URL=https://vault.example.com
CONVEX_CLOUD_ORIGIN=https://vault.example.com/convex
CONVEX_SITE_ORIGIN=https://vault.example.com/convex
VARLATCH_JWKS_URL=http://varlatchd:8686/.well-known/jwks.json
VARLATCH_CONVEX_URL=http://convex-backend:3210
BIND_ADDRESS=127.0.0.1
VARLATCH_WEB_PORT=8787
VARLATCHD_PORT=0
CONVEX_PORT=0
VARLATCH_KEK_HOST_PATH=./secrets/varlatch-kek
POSTGRES_SUPERUSER_PASSWORD_HOST_PATH=./secrets/postgres-superuser-password
VARLATCH_MIGRATE_PASSWORD_HOST_PATH=./secrets/varlatch-migrate-password
VARLATCH_RUNTIME_PASSWORD_HOST_PATH=./secrets/varlatch-runtime-password
CONVEX_DB_PASSWORD_HOST_PATH=./secrets/convex-db-password
CONVEX_INSTANCE_SECRET_HOST_PATH=./secrets/convex-instance-secret
COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml
VARLATCH_PUBLIC_HOST=vault.example.com
# --- your additions below this line are kept by setup ---
```

### Files you do not edit

`docker-compose.yml`, the overlays (`docker-compose.caddy.yml`,
`docker-compose.tailscale.yml`, `docker-compose.tailnet-https.yml`),
`Caddyfile`, `tailscale-serve.json`, and `convex-supervisor.cjs` are release
files. `varlatch upgrade` replaces them and keeps the previous ones as
`*.pre-<version>`. Keep your changes in `.env`.

For changes that `.env` cannot express, add a `docker-compose.override.yml`
next to `docker-compose.yml`: upgrades never touch it. Compose reads that
file by itself only while `COMPOSE_FILE` is not set, which is the case with
the external ingress. With the public or tailnet ingress, setup lists it
last in `COMPOSE_FILE` when it exists: after you create or delete the file,
run `varlatch setup` again. `varlatch doctor` warns when the file exists but
is not in effect. Do not add a `COMPOSE_FILE` line of your own below the
keep marker: it would replace the list setup writes, and keep an outdated
one when a later setup run changes it.

## `varlatch-install.json`

Setup records the installation's configuration in `varlatch-install.json`
and derives `.env` from it. Its fields:

| Field | What it is | Becomes |
|---|---|---|
| `publicUrl` | the public URL | `VARLATCH_PUBLIC_URL`, and the Convex origins under it |
| `ingress` | `public`, `tailnet`, or `external` (absent in older files, meaning `external`) | `COMPOSE_FILE` and the ingress variables |
| `tailnetMachine` | the Tailscale machine name asked for | `VARLATCH_TAILNET_MACHINE` |
| `tailnetName` | the tailnet's MagicDNS suffix, read from the node | `VARLATCH_TAILNET_NAME` |
| `webPort` | the dashboard's host port | `VARLATCH_WEB_PORT` |
| `bindAddress` | the host address of the published ports | `BIND_ADDRESS` |
| `convexOrigin` | the browser-facing Convex origin, when it is not `<publicUrl>/convex` (adopted installations only) | `CONVEX_CLOUD_ORIGIN` and `CONVEX_SITE_ORIGIN` |
| `secretPaths` | where an adopted installation keeps its secret files, by path variable | the `*_HOST_PATH` variables |

To change `webPort` or `bindAddress`, edit the file and run `varlatch setup`
again. Leave `publicUrl`, `ingress`, `tailnetMachine`, and `tailnetName`
alone: they decide the address passkeys are registered for. To give the
installation another address, use `varlatch move`:
[Moving an installation to another address](../operations/move-installation.md).
Setup refuses a `--public-url` or `--ingress` that differs from the
recorded one, and a `publicUrl` edited into the file.

## All variables

| Variable | Section | Written by setup | Holds a secret |
|---|---|---|---|
| `VARLATCH_PUBLIC_URL` | [Public address](#public-address) | yes | no |
| `CONVEX_CLOUD_ORIGIN` | [Public address](#public-address) | yes | no |
| `CONVEX_SITE_ORIGIN` | [Public address](#public-address) | yes | no |
| `COMPOSE_FILE` | [Ingress](#ingress) | public and tailnet ingress | no |
| `VARLATCH_PUBLIC_HOST` | [Ingress](#ingress) | public ingress | no |
| `VARLATCH_ACME_CA` | [Ingress](#ingress) | no | no |
| `VARLATCH_HTTP_PORT`, `VARLATCH_HTTPS_PORT` | [Ingress](#ingress) | no | no |
| `BIND_ADDRESS` | [Host ports](#host-ports) | yes | no |
| `VARLATCH_WEB_PORT` | [Host ports](#host-ports) | yes | no |
| `VARLATCHD_PORT`, `CONVEX_PORT` | [Host ports](#host-ports) | yes | no |
| `VARLATCH_JWKS_URL` | [Internal addresses](#internal-addresses) | yes | no |
| `VARLATCH_CONVEX_URL` | [Internal addresses](#internal-addresses) | yes | no |
| `VARLATCH_KEK_HOST_PATH` and the other `*_HOST_PATH` variables | [Keys and passwords](#keys-and-passwords) | yes | a path to one |
| `POSTGRES_SUPERUSER_PASSWORD`, `VARLATCH_MIGRATE_PASSWORD`, `VARLATCH_RUNTIME_PASSWORD`, `CONVEX_DB_PASSWORD`, `CONVEX_INSTANCE_SECRET` | [Keys and passwords](#keys-and-passwords) | no | yes |
| `CONVEX_ADMIN_KEY` | [Keys and passwords](#keys-and-passwords) | no | yes |
| `TS_AUTHKEY_HOST_PATH` | [Tailscale](#tailscale) | tailnet ingress | a path to one |
| `TS_AUTHKEY` | [Tailscale](#tailscale) | no | yes |
| `VARLATCH_TAILNET_NAME` | [Tailscale](#tailscale) | tailnet ingress | no |
| `VARLATCH_TAILNET_MACHINE` | [Tailscale](#tailscale) | tailnet ingress | no |
| `VARLATCH_TRUSTED_PROXIES` | [Client addresses](#client-addresses) | no | no |
| `VARLATCH_SYNC`, `VARLATCH_SYNC_ADAPTERS` | [Sync Targets](#sync-targets) | no | no |

A default below is what the Compose files use when the variable is unset
or empty.

## Public address

### `VARLATCH_PUBLIC_URL`

- **Read by:** `varlatchd`, and `convex-deploy`, which gives it to Convex as
  `VARLATCH_ISSUER`.
- **Default:** none. Compose refuses to start without it.
- **Setup:** writes the `--public-url` you give, or with the tailnet
  ingress, the address the node reports once it has joined.

The address people open in their browser. Passkeys are registered for it,
it is the issuer of the tokens varlatchd signs, and enrollment links start
with it. It must be exactly the URL users visit: an origin such as
`https://vault.example.com`, with no path. Browsers only allow passkeys on
HTTPS; `http://localhost` works for local testing. varlatchd does not start
with a value that is not a URL.

When to change it: only with `varlatch move`. Every passkey is registered
for this address, so a move is a re-enrollment event:
[Moving an installation to another address](../operations/move-installation.md).
When you restore onto a new host, set it to the original installation's
URL, even though the new host does not serve that address, and move
afterwards if you need a new one:
[Restore on a fresh host](../operations/backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore).

### `CONVEX_CLOUD_ORIGIN`

- **Read by:** `convex-backend`, and `varlatch-web`, which serves it to
  browsers in `/varlatch-config.js` when its container starts.
- **Default:** `http://127.0.0.1:3210` for `convex-backend`. `varlatch-web`
  gets no value, and browsers then try `http://localhost:3210`.
- **Setup:** writes `<public URL>/convex`, or an adopted installation's
  separate Convex origin.

Where browsers open the dashboard's live-update connection. With one public
origin, `varlatch-web` forwards `/convex/` to `convex-backend`, WebSocket
included, so Convex needs no public route of its own. An installation that
gives browsers a separate Convex origin, such as
`https://convex.example.com`, routes that origin to `convex-backend` on
port 3210.

When to change it: to move an existing installation from a separate Convex
origin to `<public URL>/convex`. Remove the old route afterwards.
`varlatch doctor` fails when browsers cannot use the value: a loopback
address behind a dashboard on a public address, or plain HTTP behind an
HTTPS dashboard. While Convex cannot be reached, the dashboard keeps working
without live updates.

### `CONVEX_SITE_ORIGIN`

- **Read by:** `convex-backend`.
- **Default:** `http://127.0.0.1:3211`.
- **Setup:** writes the same value as `CONVEX_CLOUD_ORIGIN`.

Convex's origin for HTTP actions. Varlatch's functions define none, and the
Compose file publishes no port for them. Keep it equal to
`CONVEX_CLOUD_ORIGIN`.

## Ingress

The ingress overlays put a TLS proxy in front of the dashboard: Caddy for
the public ingress, the Tailscale sidecar for the tailnet ingress. With the
external ingress, your own proxy does this instead.
[Host requirements](requirements.md#the-address) compares the three.

### `COMPOSE_FILE`

- **Read by:** Docker Compose itself, and so by every `varlatch` command
  that runs `docker compose` in the directory.
- **Default:** not set. Compose reads `docker-compose.yml`, and
  `docker-compose.override.yml` when it exists.
- **Setup:** writes
  `docker-compose.yml:docker-compose.caddy.yml` for the public ingress and
  `docker-compose.yml:docker-compose.tailscale.yml:docker-compose.tailnet-https.yml`
  for the tailnet ingress, followed by `docker-compose.override.yml` when
  that file exists. It writes nothing for the external ingress.

The Compose files that make up the installation, separated by colons. When
it is set, Compose reads only the files it lists.

When to change it: not for the ingress setup chose. To give varlatchd its
tailnet listener, for Tailnet Requirements, an installation adds
`docker-compose.tailscale.yml`: see
[Optional Tailscale integration](../../infra/compose/README.md#optional-tailscale-integration).

### `VARLATCH_PUBLIC_HOST`

- **Read by:** `caddy`, as the site address in the `Caddyfile`.
- **Default:** none. Compose refuses to start the Caddy overlay without it.
- **Setup:** writes the host name of the public URL, with the public
  ingress.

The name Caddy serves and obtains a certificate for. It is always the host
of `VARLATCH_PUBLIC_URL`: never change it on its own.

### `VARLATCH_ACME_CA`

- **Read by:** `caddy`.
- **Default:** `https://acme-v02.api.letsencrypt.org/directory`, Let's
  Encrypt.
- **Setup:** does not write it.

The ACME directory Caddy obtains certificates from. Change it to use
another ACME certificate authority. Varlatch's own tests point it at a local
ACME server.

### `VARLATCH_HTTP_PORT` and `VARLATCH_HTTPS_PORT`

- **Read by:** Docker Compose, for the ports `caddy` publishes.
- **Default:** `80` and `443` (443 for both TCP and UDP).
- **Setup:** does not write them.

The host ports Caddy listens on, on every interface. Change them only when
something in front of the host forwards the public ports 80 and 443 to
other ports: certificate validation arrives on ports 80 and 443, and the
public URL cannot carry a port.

## Host ports

With one public origin, only the ingress needs to be reachable from outside
the host. The other ports are published on loopback, for your own proxy and
for local checks.

### `BIND_ADDRESS`

- **Read by:** Docker Compose, as the host address of the ports published
  for `varlatch-web`, `varlatchd`, and `convex-backend` (with the Tailscale
  overlay, the sidecar's port instead of varlatchd's). Caddy's ports do not
  use it.
- **Default:** `127.0.0.1`.
- **Setup:** writes `127.0.0.1`.

Loopback keeps the containers' ports off the network, so the ingress is the
only way in. Change it rarely: `0.0.0.0` publishes all of these ports on
every interface, varlatchd's and Convex's included. A browser cannot sign
in at a plain `http://<host>:8787` address anyway, since passkeys need
HTTPS. For an installation on a LAN, use the external ingress with a TLS
proxy.

### `VARLATCH_WEB_PORT`

- **Read by:** Docker Compose, for the port `varlatch-web` publishes.
- **Default:** `8787`.
- **Setup:** writes `--port` (default 8787), recorded as `webPort`.

The dashboard's host port. With the external ingress, your proxy forwards
to it. The dashboard also answers `/readyz` here, from varlatchd. Change it
when 8787 is taken on the host: on a managed installation, change `webPort`
in `varlatch-install.json` and run setup again.

### `VARLATCHD_PORT` and `CONVEX_PORT`

- **Read by:** Docker Compose, for the ports `varlatchd` and
  `convex-backend` publish. With the Tailscale overlay, the sidecar
  publishes `VARLATCHD_PORT` instead.
- **Default:** `8686` and `3210`.
- **Setup:** writes `0` for both, unless the installation keeps a separate
  Convex origin. Then it writes neither, and your own lines stay.

`0` lets Docker choose a free loopback port. Nothing needs to reach
varlatchd or Convex directly, because the dashboard serves varlatchd's API
and Convex at the public URL. Never route a public domain at varlatchd's
port: passkey sign-in works only at the public URL. An installation that
keeps a separate Convex origin forwards that origin to `CONVEX_PORT`.
Otherwise, leave both as setup writes them.

## Internal addresses

### `VARLATCH_JWKS_URL`

- **Read by:** `convex-deploy`, which sets it in Convex's configuration.
- **Default:** `http://varlatchd:8686/.well-known/jwks.json`.
- **Setup:** writes the default.

Where Convex fetches the public keys that verify varlatchd's tokens, over
the Compose network. Never change it on a new installation. Installations
deployed before 0.10.0 may still name `http://tailscale:8686/...`, and
`varlatch adopt` moves them to the fixed name. Archives made with the old
name still restore: the Compose file gives varlatchd the alias `tailscale`.

### `VARLATCH_CONVEX_URL`

- **Read by:** `varlatchd`.
- **Default:** `http://convex-backend:3210`.
- **Setup:** writes the default.

Where varlatchd publishes the dashboard's read models (Mirrors) and reaches
Convex during backup and restore. Never change it.

## Keys and passwords

Every key and password of an installation is a file. Setup generates each
one, except the Tailscale auth key, which you give it. The Compose files
mount each file only into the services that need it, and `.env` holds only
its path. Keep secrets out of `.env`.

### Secret files

| Path variable | File setup creates | Mounted into | Holds |
|---|---|---|---|
| `VARLATCH_KEK_HOST_PATH` | `secrets/varlatch-kek` | `varlatchd` | the Root KEK |
| `POSTGRES_SUPERUSER_PASSWORD_HOST_PATH` | `secrets/postgres-superuser-password` | `postgres` | the PostgreSQL superuser's password |
| `VARLATCH_MIGRATE_PASSWORD_HOST_PATH` | `secrets/varlatch-migrate-password` | `postgres`, `varlatch-migrate` | the password of the role that applies migrations |
| `VARLATCH_RUNTIME_PASSWORD_HOST_PATH` | `secrets/varlatch-runtime-password` | `postgres`, `varlatchd` | the password of varlatchd's runtime role |
| `CONVEX_DB_PASSWORD_HOST_PATH` | `secrets/convex-db-password` | `postgres`, `convex-backend` | the password of Convex's own role |
| `CONVEX_INSTANCE_SECRET_HOST_PATH` | `secrets/convex-instance-secret` | `convex-backend`, `convex-deploy` | the Convex instance secret |
| `TS_AUTHKEY_HOST_PATH` | `secrets/tailscale-authkey`, from the key you give | `tailscale` | the Tailscale auth key ([Tailscale](#tailscale)) |

- **Default:** `./secrets/varlatch-kek` for the Root KEK. For the others,
  `/dev/null`: an empty file, which the services ignore.
- **Setup:** writes every path, relative to the installation's directory
  (the Tailscale one only with the tailnet ingress). For a new installation
  it generates the files as random hex: 32 bytes for the Root KEK and the
  Convex instance secret, 24 bytes for each password. It never generates
  one for an installation that already has a database: it stops instead
  and asks you to restore the missing file.

Setup creates `secrets/` with mode 0700, and the files containers read
with mode 0644: the containers' users must read them, and the directory
keeps everyone else out. If you place the files yourself, do the same. On
a host that redeploys from a fresh checkout, such as Coolify, keep them
outside the checkout, for example in `/data/varlatch/secrets`.

### Secret variables

Each password and secret can also be given as a variable of the same name:
`POSTGRES_SUPERUSER_PASSWORD`, `VARLATCH_MIGRATE_PASSWORD`,
`VARLATCH_RUNTIME_PASSWORD`, `CONVEX_DB_PASSWORD`, `CONVEX_INSTANCE_SECRET`,
and `TS_AUTHKEY`. They are empty by default, and setup never writes them. A
variable that is set wins over its file.

They exist for installations configured by hand, and `varlatch adopt` moves
their values into files. Prefer files: a variable becomes part of the
container's configuration, and on Coolify it reaches every service,
`varlatchd` included.

The Root KEK has no variable in the Compose files. varlatchd would also
accept it as `VARLATCH_KEK`, but never put it there: the Root KEK belongs in
a file, with copies off the host.

### What each one is for

- **The Root KEK** is the root of the encryption hierarchy: 32 bytes, as 64
  hex characters or base64. At startup varlatchd checks it against the
  installation's canary and refuses to start with any other key. Never
  replace the file, and keep copies off the host, as
  [The root KEK is your responsibility](../../infra/compose/README.md#the-root-kek-is-your-responsibility)
  describes.
- **The database passwords** are used when PostgreSQL first creates its
  data directory: `postgres-init/` then creates a role for migrations, a
  role for varlatchd, and a role for Convex, which has no access to
  varlatchd's database. Changing a file later does not change the password
  in the database; that also needs `ALTER ROLE`.
- **The Convex instance secret** is required: `convex-backend` refuses to
  start without one. `convex-deploy` derives the Convex admin key from it
  inside its own container, so there is no admin key to store.
- **The Backup Encryption Key** is `secrets/backup-key`, mode 0600. Setup
  generates it for a new installation, no container mounts it, and the host
  CLI reads it with `--bek-file`. Keep a copy off the host, apart from the
  Root KEK copy:
  [Keys and recovery inputs](../operations/backup.md#keys-and-recovery-inputs).

### `CONVEX_ADMIN_KEY`

- **Read by:** `convex-deploy`.
- **Default:** empty.
- **Setup:** does not write it. It holds a secret.

Leave it empty: `convex-deploy` derives the key. Installations that still
set it keep working, and `varlatch adopt` removes it once the derived key
has worked. After a restore onto a fresh Convex instance secret, an
installation that still sets it must generate a new one.

## Tailscale

These variables belong to `docker-compose.tailscale.yml`, which the tailnet
ingress uses, and which also gives varlatchd its tailnet listener.

### `TS_AUTHKEY_HOST_PATH` and `TS_AUTHKEY`

- **Read by:** `tailscale`, the sidecar.
- **Default:** `/dev/null` and empty.
- **Setup:** with the tailnet ingress, asks for the key (or reads
  `--tailscale-auth-key-file`), stores it in `secrets/tailscale-authkey`
  with mode 0600, and writes that path. It holds a secret.

The auth key (`tskey-...`) the node joins your tailnet with. Only a node
that has not joined yet needs it: afterwards, its identity lives in the
`tailscale-state` volume. The key must not be expired or used up. You can
tag the node, for example `tag:varlatch`.

### `VARLATCH_TAILNET_NAME`

- **Read by:** `varlatchd`, as `VARLATCH_TAILSCALE_TAILNET`.
- **Default:** none. Compose refuses to start the Tailscale overlay without
  it.
- **Setup:** with the tailnet ingress, writes `pending.invalid` until the
  node has joined, then the tailnet's MagicDNS suffix the node reports.

Your tailnet, for example `example.ts.net`. varlatchd's tailnet listener
identifies each caller with Tailscale's WhoIs and accepts only callers from
this tailnet. Set it yourself only when you add the overlay by hand.

### `VARLATCH_TAILNET_MACHINE`

- **Read by:** Docker Compose, as the sidecar's host name.
- **Default:** `varlatch`.
- **Setup:** with the tailnet ingress, writes `--tailnet-machine` (default
  `varlatch`).

The machine name the node asks for. The dashboard is then at
`https://<name>.<tailnet>.ts.net`. When the name is taken, Tailscale adds a
suffix, and setup uses the name the node actually got. Use lowercase
letters, digits, and hyphens, at most 63 characters. The certificate is
published in Certificate Transparency logs, so keep the name
non-sensitive.

Choose it before the first run. Renaming the machine or the tailnet later
changes the address, and everyone registers their passkey again. Setup
stops when it sees the name has changed.

## Client addresses

### `VARLATCH_TRUSTED_PROXIES`

- **Read by:** `varlatchd`.
- **Default:** depends on the Compose files:

  | Files | Default |
  |---|---|
  | `docker-compose.yml` | `varlatch-web` |
  | with `docker-compose.caddy.yml` | `varlatch-web,caddy` |
  | with `docker-compose.tailnet-https.yml` | `varlatch-web,tailscale` |
  | `docker-compose.coolify-tailscale.yml` | `varlatch-web,coolify-proxy` |

- **Setup:** does not write it.

The proxies whose `X-Forwarded-For` header varlatchd believes, so that its
per-client limits and the device sign-in confirmation see each caller's own
address. Entries are separated by commas: Compose service or container
names, IP addresses, and CIDR ranges.

Change it when your own reverse proxy sits in front of the dashboard, or
when varlatchd logs that a proxy name does not resolve. Your value replaces
the default, so keep `varlatch-web` in the list, and `caddy` or `tailscale`
where the ingress adds one. An entry that is not an IP address, a CIDR
range, or a host name stops varlatchd from starting.
[Client addresses behind proxies](../../infra/compose/README.md#client-addresses-behind-proxies)
explains how varlatchd reads the header, and which ranges never to list.

## Sync Targets

### `VARLATCH_SYNC`

- **Read by:** `varlatchd`.
- **Default:** `on`.
- **Setup:** does not write it.

With `on`, authorized users may add Sync Targets, which push an
environment's values to GitHub Actions, Coolify, or Convex. With `off`,
varlatchd delivers nothing for the whole installation, and the dashboard
points users at the client-side `varlatch sync push` instead. Any other
value stops varlatchd from starting. Set `off` on networks the installation
must not reach out from, or when your policy forbids it.

### `VARLATCH_SYNC_ADAPTERS`

- **Read by:** `varlatchd`.
- **Default:** empty: all built-in adapters, `github-actions`, `coolify`,
  and `convex`.
- **Setup:** does not write it.

A comma-separated list of the platforms Sync Targets may use. varlatchd
refuses to connect another platform and delivers only through the listed
adapters. Set it to allow only the platforms you use.

## Logs

There are no logging settings. Every service logs to standard output:
`docker compose logs <service>` shows it. At startup, varlatchd logs the
address each trusted proxy name resolves to, whether Sync Targets are
enabled, and where it publishes Mirrors.

## Backups

No variable in `.env` configures backups. The host CLI runs them, as
[Installation backup and recovery](../operations/backup.md) describes, with
these settings:

| Setting | Where | Default |
|---|---|---|
| Backup Encryption Key | `--bek-file` (setup generates `secrets/backup-key`), or `--bek-passphrase-file` | none |
| Destinations | `backup-destinations.json` in the installation's directory, or `--destinations-file` | none: archives stay on the host |
| Archive path | `--out` | `backups/<archive-id>.vltbak` in the installation's directory |
| Scratch space | `--scratch-dir` | the system's temporary directory |
| Capture deadline | `--timeout-seconds`, 1 to 86400 | 300 seconds |

Backup status, the backup history, and the restore gate live on the
`varlatch-state` volume: keep it with the installation. The reference
systemd timer in [`infra/host-backup`](../../infra/host-backup/README.md)
keeps its own settings in `/etc/varlatch-backup/config.env`: `COMPOSE_DIR`,
`COMPOSE_FILE`, `DESTINATION` (default `offsite`), `LOCAL_KEEP` (default 7),
`CLI`, and `STATUS_FILE`.

## Fixed settings

The services also read variables that the Compose files set to fixed
values. They appear in `docker compose config`, and they are part of the
deployment, not settings: leave them as they are.

| Service | Variable | Value |
|---|---|---|
| `varlatchd` | `VARLATCH_STATE_DIR` | `/var/lib/varlatch`, the `varlatch-state` volume |
| `varlatchd` | `VARLATCH_DATABASE_URL`, `VARLATCH_DATABASE_PASSWORD_FILE` | the runtime role on `postgres:5432/varlatch`, password from `/run/secrets/varlatch-runtime-password` |
| `varlatchd` | `VARLATCH_KEK_FILE` | `/run/secrets/varlatch-kek` |
| `varlatchd` | `VARLATCH_PORT` | `8686` |
| `varlatchd`, with the Tailscale overlay | `VARLATCH_TAILSCALE_SOCKET`, `VARLATCH_TAILNET_PORT` | `/var/run/tailscale/tailscaled.sock`, `8687` |
| `varlatch-migrate` | `VARLATCH_DATABASE_URL`, `VARLATCH_DATABASE_PASSWORD_FILE` | the migration role, password from `/run/secrets/varlatch-migrate-password` |
| `convex-backend` | `INSTANCE_NAME` | `convex-self-hosted` |
| `convex-backend` | `POSTGRES_URL`, `DO_NOT_REQUIRE_SSL` | Convex's role on `postgres:5432`, without TLS inside the Compose network |
| `convex-backend` | `DISABLE_BEACON` | `1`: no usage beacon |
| `convex-deploy` | `CONVEX_SELF_HOSTED_URL` | `http://convex-backend:3210` |
| `tailscale` | `TS_USERSPACE`, `TS_STATE_DIR`, `TS_SOCKET`, `TS_ENABLE_HEALTH_CHECK`, `TS_LOCAL_ADDR_PORT`, `TS_SERVE_CONFIG` | userspace networking, the state and socket volumes, the health check, and with the tailnet ingress, `tailscale-serve.json` |

Three of them carry more weight than they seem to:

- `INSTANCE_NAME` names Convex's database (`convex_self_hosted`, which
  `postgres-init/` creates) and is part of the admin key `convex-deploy`
  derives.
- The Convex supervisor refuses to start when `DATA_DIR` or `STORAGE_DIR`
  point elsewhere, or when any `S3_STORAGE_` variable is set: installation
  backups need Convex's local storage layout.
- varlatchd also accepts `VARLATCH_KEK` and `VARLATCH_TAILNET_BIND`, but the
  Compose files pass neither, and you should not add them.

## Operator CLI environment

The host CLI reads a few variables of its own:

| Variable | Used by | Purpose |
|---|---|---|
| `GITHUB_TOKEN` or `GH_TOKEN` | `varlatch upgrade`, `varlatch self-update` | a GitHub token for reading releases, needed only when they come from a private repository |
| `VARLATCH_RELEASE_REPO` | `varlatch upgrade`, `varlatch self-update` | the repository releases come from; default `varlatch/varlatch`; `--repo` overrides it |
| `COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`, `COMPOSE_ENV_FILES` | `varlatch doctor` and the other host commands, through `docker compose` | for a project started with other files or another project name: [Health check](../../infra/compose/README.md#health-check-read-only) |
| `VARLATCH_KEK_PASSPHRASE` | `admin kek export` and `admin kek restore`, inside `varlatchd` | the escrow passphrase, for non-interactive use; `--passphrase-file` is the alternative |
