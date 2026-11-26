# Migrating an installation to Varlatch 0.50

Varlatch 0.50 is a new server: one `varlatchd` binary with its own
database, in place of the Compose installation's services (the TypeScript
server, PostgreSQL and Convex). `varlatch migrate` moves an installation
from the last TypeScript release to it. It keeps the installation's
identity, its address and its keys, and every person, Organization,
Project, value, grant, credential and audit event, checked on both sides
before the new server opens.

## What people notice

- **They sign in again, with the same passkey.** Every browser session ends
  at the migration. Passkeys keep working: the address stays the same, and
  a passkey belongs to its address. Nobody enrolls a new one.
- **CLIs and applications keep working.** CLI sign-ins, device sign-ins,
  machine, agent and OIDC credentials are carried over with their expiry,
  revocations and use limits. A CLI keeps its server address, so released
  CLIs and the new one go on working without a new `varlatch login`.
- **A short downtime.** From the barrier to the open, the installation
  answers `503` with `Retry-After: 5`: fetching values, OIDC
  exchanges, sign-ins and device sign-ins wait, and a CLI polling a device
  sign-in continues against the new server at the same address.
  Applications that already hold their values keep running. Do not
  schedule CI deploys during the window. The dry run measures how long it
  will be (see [The dry run](#the-dry-run)).
- **Unfinished sign-ins are retried.** A passkey ceremony or sign-in that
  was in flight at the barrier is not carried over: it fails and is
  started again.
- **Open dashboard tabs need a hard reload.** A tab that stayed open across
  the migration is still running the 0.23.0 dashboard in memory and cannot
  switch itself to 0.50. Reload it with `Ctrl+Shift+R` (`Cmd+Shift+R` on a
  Mac) and sign in again with the same passkey. A browser that opens a
  bookmarked address from its cache of 0.23.0 has its cache cleared on the
  old page's first call, so a plain reload or the next address opens the
  0.50 dashboard. The same hard reload applies to open tabs after a
  rollback to 0.23.0.

Sync Targets, webhooks and audit export are drained at the barrier and
resume on the new server from where they stopped: nothing already
delivered is sent again, and a failed delivery is retried under the same
rules.

## Before you start

### What 0.23.0 says about 0.50

Once 0.50.0 is the latest release, 0.23.0 and earlier notice it, but look in it
for files that a 0.50 release does not have. Nothing is changed or installed,
and the words mislead:

- **The CLI's `varlatch self-update`** refuses: `Release 0.50.0 has no
  varlatch-cli-0.50.0.cjs with SHA256SUMS; releases before 0.9.0 predate the
  single-file CLI.` Its `--check` names 0.50.0. Install the new CLI with
  `install.sh` or `install.ps1`, which replace the old one, or with
  `brew upgrade varlatch` where Homebrew installed it: [Install the
  CLI](../reference/install-the-cli.md). Either CLI works with either server,
  so people can do that before or after the migration. The desktop apps
  that offer `varlatch self-update` mean the same.
- **The dashboard's Release page** shows `varlatch upgrade 0.50.0`, for the
  host. That command refuses too: `Release v0.50.0 has no varlatch-release.json
  asset`, and that it "predates the release-set tooling". `varlatch upgrade
  --check` ends the same way, with exit status 1, after it has recorded the
  release for the dashboard; the host backup's nightly check logs it and goes
  on. Follow this guide instead: 0.50 is not an upgrade of a Compose
  installation.

On the installation's host, keep the 0.23.0 CLI: its host commands are the
Compose installation's (below).

### Upgrade to the last TypeScript release first

`varlatch migrate` takes exactly one source: a Compose installation of the
last TypeScript release, **0.23.0**, running its published image,
`ghcr.io/varlatch/varlatchd`, checked by its registry digest. Upgrade to it
first, the usual way
([Upgrade](../../infra/compose/README.md#upgrade-backup-gated-forward-only)),
and let it run.

- A source on another release is refused: `the source runs <release>; a
  migration starts from the last TypeScript release, 0.23.0, only: upgrade
  it first`.
- An image built locally, or pulled under another repository's name, is
  refused, naming both images: `the source's image is repository
  <repository>, digest <digest>, not the published 0.23.0 image: repository
  ghcr.io/varlatch/varlatchd, digest sha256:6d9b9a67...`.
- Its exposure backfill must have finished, and no key rotation may be in
  progress. The TypeScript release's export refuses either: `the exposure
  backfill has not finished: let varlatchd run until it has (it runs in
  the background), then export again`, or `a Root KEK rotation is in
  progress (<state>): finish it, then export again`.

### What you need

On the installation's Linux host, as root (`varlatch migrate` runs on
Linux only; on any other OS it refuses at once: `varlatch migrate runs on
the Linux host of the installation it migrates`):

- **The Go CLI**, `varlatch` 0.50 or later, and `varlatchd` of the release
  you migrate to. `varlatch migrate` drives both installations as
  programs: it opens neither database itself.
- **The TypeScript CLI** of 0.23.0, as `varlatch-ts` on the `PATH` (or name
  it with `--ts-cli`). The preflight makes its backup with it.
- **The stock layout of the server's state.** `varlatchd`'s `/var/lib/varlatch`
  is on a named volume of its own, the whole of it, as the stock and Coolify
  Compose files have it (`varlatch-state`). The marks the migration leaves
  the old server behind are in it, so a bind mount, a part of a volume, or
  something mounted inside it is refused in the preflight, before the backup
  and the barrier.
- **Docker Compose 2.32.0 or later** (`docker compose version`). An earlier
  one does not make PostgreSQL's container again when a rollback gives it a
  fresh volume, so `varlatch migrate` and `varlatch migrate --rollback`
  refuse it before anything is done: `Docker Compose <version> is too old:
  varlatch migrate needs 2.32.0 or later`. An undo (`--resume`, `--abort`)
  works with an earlier one too.
- **No certificate authority the old server alone trusts.** A server whose
  `varlatchd` has `NODE_EXTRA_CA_CERTS` trusts the authorities in that file
  beside its own. The new server does not read that variable: it trusts the
  system's, or the file `SSL_CERT_FILE` names in the place of the system's,
  which must then hold the system's authorities and yours. The preflight, a
  dry run's too, says so with `Warning: the source's varlatchd trusts
  certificate authorities of its own (NODE_EXTRA_CA_CERTS="<file>", ...)` and
  goes on; it does not read the file. Give the new server the authority
  before the migration, or its connections to the webhooks, platforms, OIDC
  issuers and backup destinations that need it fail:
  - **A host install:** add it to the host's trust store (on Debian and
    Ubuntu, `update-ca-certificates`), or set `SSL_CERT_FILE` with `systemctl
    edit varlatchd` (`[Service]`, `Environment=SSL_CERT_FILE=<file>`; a file
    the service may read, not under `/home`).
  - **The image:** mount a file with both, and set `SSL_CERT_FILE` to it in
    the service's environment (the image sets it to its own).
- **The Backup Encryption Key** (`--bek-file`) and, when the Root KEK is not
  where the installation's `.env` says, its file (`--kek-file`). The new
  server uses the same two keys, so every archive, old and new, opens with
  them. No key is rotated, and no new key ceremony is needed.
- **A backup destination** (`--backup-destination`, as configured, or from
  `--destinations-file`) and its **read credentials**
  (`--read-credentials-file`): the preflight uploads a fresh backup, then
  downloads it and verifies it, as
  [0.23.0's runbook](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/operations/backup.md#create-and-verify) describes.
- **The target**, in one of two shapes:
  - **A host install** (`--config /etc/varlatch/varlatchd.conf`, and
    `--unit` when its systemd unit is not `varlatchd`). There is no need to
    run `varlatch setup` first. When the configuration is not there,
    `varlatch migrate` makes the host install with setup's own steps: the
    `varlatch` system user, the data directory, `/etc/varlatch`, the
    configuration, and the unit, enabled but not started.
    - **The configuration's answers** come from the source: its public URL
      and its ingress (for your own proxy, the dashboard's address the
      proxy targets). Give what the source cannot say: `--acme-email`, the
      certificate account's address for public ingress; `--listen`, the
      plain listener (Coolify's, or another address than the
      dashboard's); and `--accept-existing-user` to use a `varlatch` user
      that already exists.
    - **No keys are generated:** the target's Root KEK and Backup
      Encryption Key are the source's, copied into its key files.
    - **An undo removes what it made.** Each item is recorded in the
      journal before it is made, so an undo before the switch removes
      exactly those items, never what was already there. If removing them
      keeps failing, remove what is left by hand (`--status` names each
      item), then clear the record with `varlatch migrate --abort
      --forget-target`.
    - **A host install you prepared yourself** is used as it is, as long
      as its data directory is empty and it has not been started.
    - **A source that serves a tailnet address needs a prepared target.**
      The host install migrate makes is never on a tailnet, so migrate
      refuses before anything is made or backed up: `the source serves a
      tailnet address (its Tailscale sidecar), and the target migrate
      makes at /etc/varlatch/varlatchd.conf is never on a tailnet: write
      /etc/varlatch/varlatchd.conf with tailnet = on and the tailnet
      settings first (a prepared target, which migrate uses as it is),
      then run varlatch migrate again; nothing was done`.
  - **The 0.50 image** (`--to-data`, `--to-keys`, `--to-config`,
    `--to-image` and `--to-service`), its service created in setup mode
    with nothing listening, and its data directory, keys directory and
    configuration as bind paths on this host. See
    [The image target](#the-image-target).

  The target's `public_url` must be the source's `VARLATCH_PUBLIC_URL`,
  scheme, host and port alike: passkeys belong to that address. A
  migration onto another address is refused; move afterwards with
  [`varlatch move`](move-installation.md).

  **The outbound allow list carries over.** The private destinations the
  source may reach (its `VARLATCH_OUTBOUND_ALLOW`: Coolify, Convex,
  webhooks, OIDC issuers or the audit export on a private address) are the
  0.50 server's `outbound_allow`, with the same entries. migrate reads the
  list from the running `varlatchd` container. When it is not running, it
  reads `docker compose config` instead, and says so: `The source's
  varlatchd is not running: its outbound allow list
  (VARLATCH_OUTBOUND_ALLOW) is read from docker compose config, not from
  its container.`

  - **A host install migrate makes** gets the list as `outbound_allow`.
  - **A target you prepared** (a host install, or the 0.50 image's
    `--to-config` file) keeps its own configuration. If it sets no
    `outbound_allow` while the source allows private destinations, migrate
    refuses before anything is done:

    ```text
    preflight: the source allows private destinations (VARLATCH_OUTBOUND_ALLOW=<list>), and the target's configuration <file> sets no outbound_allow, so the Go installation would refuse them all: add the line outbound_allow = <list> to it; nothing was done
    ```

    If its `outbound_allow` lacks some of the source's entries, migrate goes
    on and warns, since a wider entry of its own may cover them:

    ```text
    Warning: the target's outbound_allow (<target's list>) lacks entries the source allows (<missing entries>): unless its own entries cover them, the Go installation refuses those destinations; the source's list is VARLATCH_OUTBOUND_ALLOW=<list>.
    ```

  After the migration, check it on the 0.50 server: `varlatchd admin
  outbound check --config /etc/varlatch/varlatchd.conf` (for the image, in
  its container). It lists every configured destination, GitHub Sync
  Targets' connections at `https://api.github.com` included. It exits 0
  when every destination is allowed, 1 when one is refused, and 2 when
  none is refused but a name did not resolve. For a refused one it names
  the `outbound_allow` line to set in that file, and how to restart
  `varlatchd` after it.

Run `varlatch migrate` from the Compose directory of the installation, or
name that directory with `--from`. `varlatch migrate --help` lists every
option.

## The dry run

Run the migration with `--dry-run` first, on the running installation:

```sh
sudo varlatch migrate --dry-run --ingress public \
  --config /etc/varlatch/varlatchd.conf \
  --bek-file /path/to/backup-key \
  --backup-destination offsite --read-credentials-file /path/to/read.json
```

It runs the preflight (the source's release, the fresh backup, the keys
copied into the target's key files and checked), then makes a full copy
from a snapshot of the running installation, imports it into a scratch
directory and runs every check against it. Nothing is closed, and nobody
notices. It stops there.

Its report:

```text
Dry run: 41 tables, 182340 rows; checks passed true.
Projected downtime 3m30s fits the budget of 10m0s, with headroom 30s: drain up to 1m0s, export 25s, import 20s, checks 15s, address transfer 1m0s (estimated for public ingress, the target's restart included; included in the projection).
```

A dry run does not move the address, so its transfer time is the
ingress's estimate, and the report says so in the parenthesis. A
migration that measured its transfer reports the time alone.

- **Checks passed** must be `true`. The checks compare both sides without
  showing any secret: every row, every encrypted item (by keyed digests,
  under a key made for the run and then discarded), every access decision
  the old server makes, and the audit log. A failed check names its class.
- **Projected downtime** is the drain, the final copy and checks (measured
  on the same data), headroom on that copy work (a quarter of export, import
  and checks, at least 30 seconds, for run-to-run variance) and the address
  transfer (estimated by the ingress: about a minute for a certificate or a
  Coolify domain move, seconds for your own proxy). The migration refuses to
  start its barrier when the projection exceeds `--max-downtime` (10 minutes
  by default).
- **Drain** is bounded by `--drain` (60 seconds by default): in-flight
  requests (an upload still arriving included), Sync Target pushes,
  webhook deliveries and audit export batches finish within it, and
  nothing new starts.

`varlatch migrate --status` shows where a migration stands, from the
Compose directory (or with `--from`). Add `--json` for the full report.

A dry run that fails before the barrier records itself as stopped in
`migration.json`, so once you fix the problem, running `varlatch migrate`
starts it again without needing `--abort`. (A run killed mid-dry-run stays
interrupted; use `--resume` or `--abort`.)

## The migration

The same command without `--dry-run`:

```sh
sudo varlatch migrate --ingress public \
  --config /etc/varlatch/varlatchd.conf \
  --bek-file /path/to/backup-key \
  --backup-destination offsite --read-credentials-file /path/to/read.json
```

It runs these phases, each written to a journal (`migration.json`, in the
Compose directory and in the target's data directory) before it starts:

1. **Preflight**, as in the dry run, with a new backup.
2. **The dry run**, again, against the budget.
3. **The barrier**: the TypeScript server stops taking requests, drains,
   and freezes its state. This is where the downtime starts.
4. **The final copy**: exported at the frozen point, imported into the
   target, and checked. Browser sessions end here.
5. **The address transfer** (see [The address transfer](#the-address-transfer)).
6. **The switch**: the TypeScript installation is marked migrated out. It
   no longer starts writable, and answers `503` to every request, reads
   included, so no application reads a stale value from it.
7. **Open**: the new server serves the installation at its address.

The journal holds no key and no value. The new server does not start on a
data directory whose journal is not open, and the old one refuses to start
writable once its journal says switched.

> **Do not recreate or redeploy the old TypeScript application after the
> switch.** When containers are recreated (Coolify **Redeploy**,
> `docker compose up -d --force-recreate`, `docker compose down` then
> `up`, or a reboot that recreates containers) or when `varlatchd` is
> already stopped, Compose re-runs the one-off `varlatch-migrate` service,
> which refuses behind the migrated-out gate, so the old `varlatchd` does
> not start and stops answering its migrated-out `503`. On a still-running
> old installation, a plain `docker compose up -d` re-runs and fails
> `varlatch-migrate` while leaving the running `varlatchd` answering `503`.
> A plain `docker compose restart` is fine too (it does not recreate
> `varlatchd` or re-check its dependency; the re-run one-off simply
> refuses again), and `varlatch migrate` uses `--no-deps` for its own
> restarts.

### Interrupted

A migration can be interrupted anywhere: a lost connection, a reboot, a
failed check. `varlatch migrate --resume`, with the same options, goes on
from the journal and never guesses:

| Interrupted | Where it stands | `--resume` |
| --- | --- | --- |
| Before the barrier | The old installation runs, unchanged | Starts again from the preflight |
| From the barrier to the transfer | Closed behind the barrier | Undoes it: the barrier lifted, the old installation reopened unchanged, the target's database discarded |
| During the address transfer | Closed, the new server isolated behind its gate | Checks the address again (or your step, on Coolify); if it does not answer from the new server, gives it back and undoes |
| After the switch | The new server serves, or is about to; the old one refuses writes | Finishes the open |

Any failure from the barrier to the switch undoes the migration, in
reverse order:

1. The tailnet name goes back to the old node, when it moved.
2. The new server stops.
3. The barrier is lifted.
4. The address goes back: the old ingress (Caddy or the dashboard) starts
   again. It is recreated when its container does not serve, for example
   one that a failed start left without a network. On Coolify too: the
   dashboard's container still routes the domain.
5. The undo reports the old installation reopened only once it answers at
   its address, as itself, within `--transfer-timeout`. If it does not,
   the undo stays resumable: `--resume` (or `--abort`) starts the ingress
   again and checks again.

While the new server may still serve the address (it did not stop, or its
service is yours to stop), the old ingress is not started and the new
server's database is kept; `--resume` goes on once it is stopped. If the
tailnet's control plane cannot be reached during an undo, the address does
not move back either, and both installations stay closed until `--resume`
finishes it.

After the switch it goes forward: `--resume` finishes the open. `varlatch
migrate --abort` undoes a migration that has not switched yet, in the same
order.

**Ctrl-C or a kill ends `varlatch migrate` at once**, wherever it is: it
undoes nothing as it goes. The journal says where it stands, and
`--resume` or `--abort` goes on from there. Let an undo that is still
saying its steps finish.

### What you see printed

`varlatch migrate` writes what it does on stderr, one line at a time. Each
step of an undo and of a rollback, the final copy's export, import and
checks, `--finish`'s archive, each wait for an address to answer, and each
step that moves the tailnet name or starts or stops the sidecar says when it
starts, every 15 seconds while it lasts, and when it ends:

```text
Step: waiting for https://vault.example.com to answer from the TypeScript release (about 3m0s at most).
Still going after 15s: waiting for https://vault.example.com to answer from the TypeScript release (about 3m0s at most).
Done in 22s: waiting for https://vault.example.com to answer from the TypeScript release (about 3m0s at most).
```

No step waits for its reader. When nobody reads them, these lines are left
out, and the command's other lines wait, at its end five seconds at the
most. A migration whose output goes to a pipe that is closed goes on to its
end, with the same exit status. A terminal that closes ends it, as Ctrl-C
does: run it in `tmux` or `screen` over a connection that may drop.

- `Failed after` is a step that did not succeed. An undo goes on past some
  and makes up for them later. When one matters, why, and what to do, is in
  the last line of the command.
- `Left to you after` is a step that is yours; the line beside it says
  what to do.
- `Still going` says that `varlatch migrate` waits, and for what. A step
  that names a limit (`about ... at most`) ends by itself, ten seconds or so
  after it at the latest; one that runs a command,
  as a service's stop, lasts as long as that command.
- An undo of the address transfer can take minutes: a service may take its
  time to stop, the address has up to `--transfer-timeout` (3 minutes by
  default) to answer, and the tailnet name moves back first.
- With `--json` these lines are left out, and the journal is printed as
  JSON on stdout at the end. The other messages, what is left to you among
  them, still go to stderr.

## The address transfer

The address moves before the switch, so an undo still reopens the old
installation. The new server starts isolated behind the migration's gate,
answering only `GET /v1/meta`. The migration then checks, through the
public URL, that `/v1/meta` answers with the migrated installation's id
and the new release, within `--transfer-timeout` (3 minutes by default).
If it does not, the address goes back and the migration is undone.

`--ingress` names the source's ingress:

- **`public`**: the installation's own Caddy. Caddy stops; the new server
  starts on ports 80 and 443 and gets its certificate for the same name.
  The target's configuration needs `listen_https`.
- **`proxy`**: your own reverse proxy. The dashboard stops, freeing its
  port; the new server starts on it, so the proxy needs no change. The
  target's `listen` must be the dashboard's address
  (`BIND_ADDRESS:VARLATCH_WEB_PORT`).
- **`coolify`**: Coolify routes the domain by application, so you move it.
  See below.

### On Coolify

`varlatch migrate` does not change anything in Coolify: you make each step
it asks for, then run it again with `--resume`.

`--from` is the directory Coolify deploys the TypeScript application from,
`/data/coolify/applications/<uuid>`. It can hold several Compose files:
Coolify's own `docker-compose.yaml`, and, with **Preserve Repository** on,
the repository's `docker-compose.yml`, which names another project. Plain
`docker compose` there can read the wrong one, so `varlatch migrate` takes
the project from the labels of the application's containers
(`com.docker.compose.project`, its `config_files` and its `working_dir`),
names it in every `docker compose` command, and keeps it in the journal. It
refuses, naming both, when:

- the directory holds the containers of two projects, or another
  directory's container, anywhere on the host, is of the same project (also
  when `--from` has no containers of its own);
- a container of the project was made from another list of files, or the
  same files in another order (a file added to `COMPOSE_FILE` later leaves
  the containers it did not change on the old list: make them again with
  `docker compose up -d --force-recreate`, in a maintenance moment, first);
- a file the labels name is not there;
- `COMPOSE_FILE` or `COMPOSE_PROJECT_NAME`, in your shell or in `.env`,
  names another, or your shell's `COMPOSE_PATH_SEPARATOR` is not the one
  `.env` is read with;
- `--resume`, `--abort`, `--rollback` or `--finish` finds the installation
  started another way than the journal records.

It reads the containers again before every command that changes something,
so an installation that changed meanwhile is left as it is. Before the
barrier, `--abort` ends such a migration, and a new one takes the
installation as it is.

If it says that `.env` names other files than the containers were made
from, set `COMPOSE_FILE` in `.env` to the files it prints: that makes no
container again. `docker compose up -d` does, with whatever files it reads.

With no containers, it takes the directory's only Compose file (and its
override), and refuses several unless `COMPOSE_FILE` names them.

1. Create the 0.50 application in Coolify as a **Docker Compose** resource
   pointing at `infra/coolify/varlatchd.compose.yml` (see
   [its Coolify setup](../../infra/coolify/README.md#single-container-go-service-050)
   and [The image target](#the-image-target)),
   with `VARLATCH_VARLATCHD_DIGEST` set to the release's verified digest,
   in setup mode with nothing listening (do not click **Deploy** yet):
   - create the host configuration file (`/srv/varlatch/varlatchd.conf`) as
     a regular file before clicking **Deploy**, otherwise Docker creates an
     empty directory there and `varlatchd` fails with `EISDIR`;
   - use the default paths: Coolify mounts `/srv/varlatch/data`,
     `/srv/varlatch/keys` and `/srv/varlatch/varlatchd.conf` whatever
     `VARLATCH_DATA_DIR`, `VARLATCH_KEYS_DIR` and `VARLATCH_CONFIG_FILE` are
     set to;
   - set `listen = 0.0.0.0:8686` and `trusted_proxies = coolify-proxy` in
     `varlatchd.conf`, and leave `listen_https` unset (Coolify's proxy
     terminates TLS; setting `listen_https` with `listen = 0.0.0.0:8686`
     makes `varlatchd` refuse to start with exit `78` and crash-loop).
2. Run the migration with `--ingress coolify` and the image target's
   options. After the final copy it stops the TypeScript dashboard's
   container (`varlatch-web`), then stops itself (exit status 75) and says,
   step by step, what to do. Keep this order:
   1. Move the domain: in Coolify, remove the installation's domain from the
      TypeScript application and set it on the 0.50 application's
      `varlatchd` service, port `8686`. **Save** only. Do not **Deploy**,
      **Restart** or **Stop** the TypeScript application: its containers are
      the way back.
   2. Start the 0.50 service: **Deploy** it. It starts isolated behind the
      migration's gate, with the domain in its labels.
3. Check by hand that `https://<domain>/v1/meta` answers, then run
   `varlatch migrate --resume` with the same options. It checks `/v1/meta`
   through the public URL, then switches and opens.

If the check fails, `--resume` checks again once you have fixed the
domain. `--abort` undoes the migration: once the 0.50 service is stopped
(when asked), it starts the TypeScript dashboard again and waits until the
old installation answers at its address; then set the domain back in
Coolify (**Save** only).

#### How Coolify routes a domain

Measured on Coolify 4.7.6 with its Traefik proxy (3.6), on throwaway
applications:

| What you do | What happens |
| --- | --- |
| Change an application's domain, without a deploy | Nothing on the host changes: containers, labels and files stay as they are, and the old container goes on serving the domain. Setting it on a second application is refused until you remove it from the first (or force it) |
| **Deploy** only the second application | Both containers carry a router for the domain. The proxy picks either one, and picks again each time a labelled container on the host starts or stops |
| Stop the old application's routed container (`docker compose stop varlatch-web`) | The new one serves, always. Starting it again (`up -d --no-deps varlatch-web`) brings the same router back |
| **Restart** or **Deploy** a Compose application, also with nothing changed | Every container is made again, from Coolify's own Compose file, and `.env` is written again without lines of yours (`COMPOSE_FILE` among them). Other files in the directory stay |
| **Stop** an application | Its containers and networks are removed; its volumes stay |
| A route of your own in the proxy's dynamic configuration, with a higher priority | It wins over both containers at once, and needs no deploy of either |

With Coolify's other proxy (Caddy), this is not tested: check the domain
move and the way back on throwaway applications first.

### The tailnet

When the installation serves its tailnet address, the migration hands the
tailnet name over to a new node, by rename, in the same transfer:

- Before the barrier, the new server's node joins under a temporary name
  (`<name>-vl-<op>-n`, where `<op>` is the handoff's 10-character
  operation id) and, on Tailscale, gets a certificate for it, which proves
  issuance works now. The handoff checks the issuance count against Let's
  Encrypt's limit of five per exact name per week, and renews the old
  node's certificate first if it would expire within the rollback window
  and seven days.
- Under the barrier, the old sidecar stops without logging out (its state
  is kept for the rollback window), then the old node is renamed to
  `<name>-vl-<op>-o` and the new node to `<name>`, back to back, each read
  back from the control plane. On Tailscale, the new node then obtains the
  certificate for `<name>`. Everything from stopping the old sidecar to
  the final check runs within one 180-second deadline.
- Tailscale does not make a name free again the moment a node lets go of
  it. A rename to it a second later is accepted, but the node gets
  `<name>-1`, although no other device lists `<name>`. When a rename reads
  back as the wanted name with such a number added, and no other device
  holds the name, the handoff waits and renames again (after 1, 2, 3, then
  every 5 seconds, for up to 45 seconds, always within the deadline),
  printing `Waiting for the tailnet to release the name <name>`. A name
  another device holds, or any other name read back, still fails at once.
  Headscale frees a name at once, so nothing waits there.
- The transfer counts only once `<name>`, resolved from a client node,
  reaches the new node. Any failure before the new node opens renames both
  nodes back (each read back, with the same wait for the name) and reopens
  the old node. The rollback's handoff waits the same way.

With both a public (or Coolify) address and the tailnet address, the order
is fixed: the domain first, checked through the public URL; then the
tailnet name, checked from a client node; then both together. A failure
undoes them in reverse order: the tailnet name goes back first, then the
address.

#### The tailnet authority

The rename needs authority over the tailnet, for the migration only. Both
are given in files, never on the command line:

- **The OAuth client** (`--tailscale-oauth-client-file <file>`): a
  Tailscale OAuth client with the **`devices:core`** scope and no other,
  generated in the Tailscale admin console, in a file holding
  `{"clientId": "...", "clientSecret": "..."}`. The migration refuses a
  client with any other scope. Each operation exchanges the client for a
  token of its own, and no token is kept.
- **The new node's auth key** (`--tailnet-auth-key-file <file>`): an auth
  key with the node's tags, which the migration gives to the 0.50
  server.

Give both again with `--resume`, `--abort` and `--rollback`: a migration
whose tailnet name is moving is refused without them, and changes
nothing. Revoke the client once the migration has opened; a rollback
needs one again, so create a new one then.

If the old node's certificate cannot be renewed to last through the
rollback window, the migration stops before the barrier.
`--accept-rollback-certificate` goes on: a rollback after that
certificate ends then needs a new one, about 40 s of downtime.

Two things on the tailnet itself:

- **The auth key must be reusable.** The new node joins with it, and the
  final check joins a short-lived probe node with it too, so a single-use
  key would be spent before the check.
- **The tailnet's access rules must let the node's tags see each other.**
  The final check looks for the name from a probe node with the new
  node's tags. If the rules hide the node from it, the check cannot prove
  the name reaches the new node, so the transfer is undone; the message
  names the tags.

##### On a self-hosted control server (Headscale)

The name moves the same way on Headscale, with Headscale's authority in
place of the OAuth client. Headscale issues no certificates, so there are
no certificate steps either:

- **Both nodes on the same control server.** The source's `tailscale`
  sidecar logs in to it with `--login-server=https://<its IP
  address>[:port]` in its `TS_EXTRA_ARGS` (an override of your Compose
  installation's). The target's configuration names the same server the
  same way, as `tailnet_control_url`. migrate compares the two and refuses
  a difference before anything is done.
- **The authority**, one of:
  - **Headscale's API:** `--headscale-url https://<its IP
    address>[:port]` with `--headscale-api-key-file <file>`, a key from
    `headscale apikeys create --expiration 1h`. Every Headscale API key is
    a full administrator, so migrate refuses one that never expires or
    that expires more than an hour from now. Each run expires its own key
    when it ends, so give every run (`--resume`, `--abort`,
    `--rollback`) a new one. A run that is killed cannot expire its key.
    The next run names it, and you expire it with `headscale apikeys
    expire --prefix <prefix>`:

    ```text
    varlatch migrate: an earlier run opened the Headscale API key <prefix> at <time> and did not close it (it was stopped): the key stays live until it expires, up to an hour after it was made. Expire it now: headscale apikeys expire --prefix <prefix>
    ```

  - **Headscale's CLI**, when migrate runs on the control server's host:
    `--headscale-cli <absolute path to headscale>`, with no key at all.
- **The new node's auth key** (`--tailnet-auth-key-file <file>`): a
  reusable pre-auth key tagged with the node's tags (`headscale
  preauthkeys create --reusable --tags <tags>`). Headscale gives a node its
  pre-auth key's tags, so they must be the configuration's `tailnet_tags`.
  Until they are, the node's tailnet access stays closed, and its tailnet
  status says `TAGS_DIFFER`, naming both sets.
- **No HTTPS.** A source that serves the tailnet browser endpoint over
  HTTPS (the sidecar's `TS_SERVE_CONFIG`) is refused: remove the HTTPS
  overlay first. A target configuration that sets `tailnet_https_port` is
  refused too: leave it unset.

The authority must match the control server. Tailscale's OAuth client on a
self-hosted server, or Headscale's authority on Tailscale's, is refused
before anything is done, naming the one to give. A run that resumes a
handoff must give the authority it was planned with: its node ids are
that server's.

## The image target

To migrate into the 0.50 image (with Docker Compose or Coolify) instead of
a host install, give the image's service in place of `--config`:

```sh
sudo varlatch migrate --ingress coolify \
  --to-data /srv/varlatch/data --to-keys /srv/varlatch/keys \
  --to-config /srv/varlatch/varlatchd.conf \
  --to-image ghcr.io/varlatch/varlatchd:0.50.0@sha256:<digest> \
  --to-service varlatchd \
  --bek-file /path/to/backup-key \
  --backup-destination offsite --read-credentials-file /path/to/read.json
```

- The service is created beforehand in setup mode, with nothing listening.
  Its data directory, keys directory and configuration are bind paths on
  this host, owned by the image's user (`65532:65532`) and not writable by
  others. The migration says the `chown` and `chmod` to run when they are
  not. Its `varlatchd` runs as that user with a temporary directory and a
  home of its own, which the migration makes under its own `TMPDIR` and
  checks at once: when that user cannot write there (a `TMPDIR` closed to
  other users), it refuses before anything is done. On Coolify,
  `infra/coolify/varlatchd.compose.yml`'s default bind
  paths and service name match `--to-data /srv/varlatch/data`,
  `--to-keys /srv/varlatch/keys`, `--to-config /srv/varlatch/varlatchd.conf`
  and `--to-service varlatchd`, and its `VARLATCH_VARLATCHD_DIGEST`
  variable pins the digest matching `--to-image`.
- `--to-image` is pinned by its digest, and its tag is the release of the
  `varlatchd` on this host, which fills the bind paths as the image's user.
  The release's `varlatchd-image.txt`, listed in its signed `SHA256SUMS`,
  holds that exact reference ([verifying a release](verify-release.md)).
  The migration does not run Docker against the service: that it runs this
  digest is yours to check.
- Starting and stopping the service are yours. The migration stops (exit
  status 75) at each step and says exactly what to run: in Coolify,
  **Deploy** or **Stop**; with Docker Compose, `docker compose up -d
  <service>` or `docker compose stop <service>`. Then run it again with
  `--resume`.
- With a tailnet address, an undo after the tailnet name moved first asks
  you to stop the 0.50 service (exit status 75): the name stays with the
  new node until you do. Then `--resume` (or `--abort`) gives the name
  back to the old node, then the address.

## The rollback window

For **30 days after the switch**, `varlatch migrate --rollback` returns the
installation to the last TypeScript release, with everything that changed
since. It works while every release the installation has run since is
reversible to 0.23.0: each 0.50 release says so in its `release.json`
(`reversibleTo`), and passes the migration's gate, forward and back,
before it is published. A
release that cannot keep the window says so instead
(`endsRollbackWindow`); every release says exactly one of the two, or it
is refused when it is built. `varlatch upgrade` asks before upgrading to a
release that ends the window:

> This release ends the migration's rollback window: after it, `varlatch
> migrate --rollback` can no longer return this installation to the
> TypeScript release (0.23.0). Its data stays; only the way back goes.

An upgrade has its own way back, `sudo varlatch upgrade --rollback`, to the
release it came from (0.50.0-rc.4 or later). It leaves this window as it is,
and says so: open, or ended by the upgrade, which going back does not undo.
It refuses while a migration or its rollback is under way, and for an upgrade
made before the migration.

### Roll back

From the Compose directory of the migration (or with `--from`), with the
new server running:

```sh
sudo varlatch migrate --rollback --config /etc/varlatch/varlatchd.conf
```

(or the image target's `--to-*` options). The new server keeps running
until the address moves back:

1. The new server takes a barrier and freezes its state; it keeps running,
   isolated. Open dashboards lose their live updates at once, show maintenance
   as soon as they ask the server for something, and come back by themselves.
   Other requests and deliveries finish within `--drain` (60 seconds by
   default). One that does not (a running backup, which takes several minutes
   for a large database; a large audit export or CLI download that a client
   reads slowly) undoes the rollback: the new server serves on and the message
   says so. Run it again once that has ended. The copy of the frozen state is
   made at full speed: nobody is served meanwhile.
2. Its state is exported for the TypeScript release, with the same two
   changes as the forward migration: browser sessions end, and the audit
   log records the migration.
3. The TypeScript release starts on a **fresh** database: new PostgreSQL
   and Convex volumes. The volumes from before the migration are kept as
   they are. Before PostgreSQL starts, its Compose configuration must name
   the new volumes, and before the import, the running container must be on
   its new one: otherwise the rollback refuses, naming both, and is undone.
   The same is checked again before the address moves, before the new
   server stops, before the rollback is recorded, and on each `--resume`
   until it is recorded in both journals.
4. The rebuilt database is checked against the new server's copy.
5. The address moves back: the new server stops serving it, and the
   TypeScript release and its ingress start on it.

   On Coolify, from here on, do not **Deploy** or **Redeploy** the
   TypeScript application: Coolify starts it from its own Compose file,
   which names the volumes from before the migration, without what was
   written since. It would answer as the same installation and release.
   Once `varlatch migrate --status` shows that a start of the rebuilt
   release was recorded, restarting its containers (`docker restart`) is
   fine. Before that, start none of them by hand: `--resume` starts them
   after it records the start.

   The address moves by the route you put in before (see
   [the way back on Coolify](#the-way-back-on-coolify)): the TypeScript
   release must answer `/v1/meta` through it, as this installation, before
   the new server stops. If the application was deployed again before that,
   `--resume` refuses, the new server goes on as it was, and it prints how
   to run the application on the new volumes again: the `COMPOSE_FILE` to
   set in `.env`, then the `docker compose` commands to run. Before the
   rollback has recorded a start of the rebuilt release, those keep
   `varlatchd` stopped: do not start it yourself, `--resume` starts it once
   the journal protects the new volumes.
6. Rolled back: the new server never starts on that data directory again.

Before step 5, an interruption, a failed check or `--abort` undoes the
rollback, and the new server goes on serving. In step 5, until the
rollback records that it starts the rebuilt TypeScript release (just
before it starts it), `--resume` goes on with the move, and a failed check
of the volumes (the application deployed again, for example) leaves the
rollback pending: repair it as `--resume` says and run `--resume` again,
or run `--abort`, which undoes it while nothing is recorded as started.
From that record on, the rebuilt release may have accepted writes that the new
server's copy does not have, so the rollback goes forward only: a failure,
including a failed start of the rebuilt release, stops with the rebuilt
volumes and journal phase kept so you can fix the cause and run `--resume`
again, and `--abort` refuses. `varlatch migrate --status` shows when the
start was recorded. A rollback begun by 0.50.0 and interrupted in step 5
counts as started too: finish it with the 0.50.1 CLI. People sign in again after a rollback too, with the
same passkey, and hard-reload any dashboard tab that stayed open
(`Ctrl+Shift+R`, `Cmd+Shift+R` on a Mac).

#### The way back on Coolify

On Coolify, `--rollback` begins nothing until the way back works, because a
domain set back in Coolify would need a deploy of the TypeScript
application:

1. The first `varlatch migrate --rollback` prints a small file and where to
   put it, `/data/coolify/proxy/dynamic/varlatch-rollback.yaml` on the host
   (or in Coolify: the server, **Proxy**, **Dynamic Configurations**), and
   stops (exit status 75). It routes the domain to the TypeScript
   dashboard's container, above the containers' own routers, and puts the
   migration's id on each answer (`X-Varlatch-Rollback`), so that
   `varlatch migrate` knows which router answered. The migration is still
   open.
2. Put the file there. From then on the domain does not lead to the new
   server. To change your mind, remove the file.
3. Run `varlatch migrate --rollback` again. The rollback begins here: it is
   recorded in the journal, and the TypeScript installation's services start
   behind its migrated-out gate (with the old Tailscale sidecar, when the
   migration stopped it: its node comes up under its temporary name), then
   its dashboard. The new server goes on as it was: its barrier waits until
   the domain reaches the TypeScript installation by the route. Its
   `/readyz` must answer there itself (a redirect to another address is not
   followed), with 503, not ready, in the state migrated-out. If it does
   not, or the run is interrupted, the rollback is undone (`--resume` or
   `--abort` does it after an interruption): the dashboard, the sidecar and
   the services this run started are stopped again, and no others.
4. The rollback runs to its end. With the image target it stops once (exit
   status 75) for you to stop the 0.50 service, when the domain already
   answers from the TypeScript release.
5. Afterwards: in Coolify, set the domain back on the TypeScript application
   (**Save** only, do not deploy), remove the file, and check that the
   domain still answers. The dashboard's container routes it itself, and the
   new server's is stopped.

An undone rollback stops the dashboard again. Remove the file then, and the
new server serves the domain as before: check it yourself, `varlatch
migrate` does not.

The old installation's containers and images may be gone by then (a prune).
`--rollback` pulls the images it needs before anything else, and makes the
containers again: the journal, the Compose files and the volumes the
migration recorded are enough. It refuses, before anything is done, when a
volume is not the recorded one.

The TypeScript installation's migrated-out gate is a file in its state
volume (`<project>_varlatch-state`, `maintenance.json`). A TypeScript server
that does not find it takes requests again, on the database from before the
migration. So the rollback on Coolify, and `--finish --delete-old-data`,
read it first, without starting anything: the volume must be the one the
migration recorded in its preflight, and the gate the migration's own, by its
id (a migration that an earlier 0.50 pre-release began recorded no volume:
then only the gate is checked). The server's container is made, its gate read
through its own mounts, and that very container started. Otherwise they
refuse, nothing is started, and the new server serves on. Do not start the
TypeScript installation then. Keep that volume during the rollback window, as
you keep its PostgreSQL and Convex volumes.

Finish an undo with the `varlatch` that began it: a rollback's undo that an
earlier 0.50 pre-release began can have left a gate this one does not know,
and refuses.

An undo of the rollback puts that gate back first, before it starts or
changes anything else, and lifts the new server's barrier last, only while
the gate is there: the two servers never both take requests, whoever starts
the old containers (Docker after a restart, or a Coolify deploy).

- **The gate cannot be put back, or held** (its volume is another project's,
  another operation's gate is in it, or the Compose files now give the server
  another volume, say): the undo stops. The new server stays behind its barrier, so the outage goes on
  and no data is lost. The message says what is not as it should be and what
  to do; then `--resume` or `--abort` tries again.
- **The gate is back, the rest is not** (a database volume is gone or still
  in use, say): the old server is held stopped behind its gate, the message
  says so, and the new server takes requests again. Do not start the old
  installation then. `varlatch migrate --resume` puts it back once the cause
  is gone, and until then neither `--rollback` nor `--finish` begins.

Coolify 4.7.6's own Docker cleanup leaves an
application's stopped containers, and the images they use; with **Delete
Unused Volumes** on, it would remove volumes no container uses, so leave
that off, and do not upgrade Coolify during the rollback window.

On a Tailscale topology (`varlatchd` with `network_mode: service:tailscale`):

- **After a migration that moved the tailnet name**, the rollback starts
  the old `tailscale` sidecar itself, which the migration stopped during
  the tailnet transfer. Its old node comes back under its temporary name. The name stays
  with the new server's node until the address moves back, then returns
  to the old node. An undo of the rollback stops the sidecar again. Give
  the tailnet authority again (see [The tailnet authority](#the-tailnet-authority)).
- **Otherwise** `varlatch migrate` never starts the old Tailscale node
  itself. If the old `tailscale` sidecar is stopped, `--rollback` refuses
  before anything and names the step: `docker compose up -d --no-deps
  tailscale`, then `varlatch migrate --rollback` again.

### Archives made during the window

The TypeScript release cannot read the 0.50 server's archives (format 3,
compressed).
The rollback's report lists every one made since the switch:

```text
2 Go archives were made since the switch; the TypeScript release cannot read them, so they restore through a Go varlatchd (setup --restore) or a later forward migration's installation only. migrate deletes none of them; their uploaded copies stay at Go's backup destination, and the local files follow Go's backup_keep (a later backup run, --finish --delete-old-data's final archive included, may remove the oldest):
  <archive id> (release 0.50.0, <created at>)
  <archive id> (release 0.50.0, <created at>)
```

`varlatch migrate` deletes none of them. The uploaded copies stay at the
0.50 server's backup destination. The local files follow its
`backup_keep`, so a later backup run may remove the oldest. Copy any you
want to keep somewhere else. Each can be restored only by a 0.50 server,
onto a fresh host:

```sh
sudo varlatch setup --restore <archive> \
  --root-kek-file /path/to/varlatch-kek --backup-key-file /path/to/backup-key
```

or by the installation a later forward migration makes.

**On a Tailscale tailnet, the restore takes the old installation's name
over.** Give `setup --restore` the tailnet ingress and an OAuth client, as
for the migration (see [The tailnet authority](#the-tailnet-authority);
both files by absolute path, the OAuth client a regular file, not a link,
of mode 0600, checked before anything is made):

```sh
sudo varlatch setup --restore <archive> \
  --root-kek-file /path/to/varlatch-kek --backup-key-file /path/to/backup-key \
  --ingress tailnet --tailnet-hostname <name> \
  --tailnet-auth-key-file /root/auth-key \
  --tailscale-oauth-client-file /root/oauth-client.json
```

It takes the name by rename, instead of waiting for the old node to be
deleted, before `varlatchd` first starts:

1. The restored node joins under a temporary name, `<name>-vl-<op>-n`,
   held: it serves nothing yet.
2. The old node must be dead: not connected to the tailnet, and last seen
   more than 5 minutes ago by the control plane's clock. A node with no
   last-seen time is refused too. This is checked again right before the
   rename. A node seen since may be the old installation still running,
   so its name is never taken; there is no override. Stop the old
   installation, wait, and run setup again (on Headscale, with a new API
   key: see below).
3. The old node is renamed `<name>-vl-<op>-o`, and the restored node
   takes the name. With tailnet HTTPS, the name's certificate is obtained
   (and counted against the name's issuances).
4. The name is checked to reach the restored node from another node of
   the tailnet. Then the hold is removed, and `varlatchd` listens once it
   starts.

Each step is journalled before it acts. Run the same command again after
an interruption: a cut-short rename is undone, then done again, and one
stopped after the rename is checked again and finished. The old node stays in the
tailnet under its `-o` name until you remove it in the admin console.

Without an authority file, setup takes no name over: it checks with a
probe node that the name is free, and while the old node still holds it,
it stops: `delete that node in the tailnet's admin console, then run
setup again; nothing has enrolled`.

**On a Headscale tailnet**, give `setup --restore` the control server and
Headscale's API key in place of the OAuth client (both files by absolute
path, the key's mode 0600):

```sh
sudo varlatch setup --restore <archive> \
  --root-kek-file /path/to/varlatch-kek --backup-key-file /path/to/backup-key \
  --ingress tailnet --tailnet-hostname <name> \
  --tailnet-control-url https://<its IP address>[:port] \
  --tailnet-auth-key-file /root/auth-key \
  --headscale-api-key-file /root/headscale-api-key
```

- **`--tailnet-control-url`** is the control server, https on its IP
  address, written as varlatchd and `varlatch migrate` write it (setup
  refuses another spelling, naming the canonical one). It goes into the
  new installation's configuration as `tailnet_control_url`. For now it
  goes with `--restore` only: `setup: --tailnet-control-url goes with
  --restore for now: setup does not yet set up a fresh installation on a
  self-hosted control server`.
- **`--headscale-api-key-file`** is a key from `headscale apikeys create
  --expiration 1h`, one line in a file of mode 0600, checked before
  anything is made. It goes with `--tailnet-control-url`, and the OAuth
  client goes without it: setup refuses either the other way round.
- **The auth key** is a reusable pre-auth key tagged with the node's tags,
  as for the migration.
- **A rerun takes the same authority, with a new key.** The answers are
  journalled in `/etc/varlatch/setup.json`, and a rerun naming another
  control server is refused. Every takeover expires its API key when it
  ends, refusals included, so a rerun that still has the takeover to do
  needs a new key (`headscale apikeys create --expiration 1h`, in the same
  file): the old one is refused with `the API key has expired`. A rerun
  reads where the takeover got to from the node's own state, and finishes
  it or leaves it done.

The takeover setup runs (`varlatchd admin tailnet take-name
--headscale-url <the URL> --headscale-api-key-file <file>`) follows the
same rules as the migration's handoff:

- **The URL is the configuration's `tailnet_control_url`.** Another one
  is refused: `--headscale-url (<url>) does not match tailnet_control_url
  (<url>): the API authority must be the installation's own control
  server; nothing was done`. The OAuth client on a self-hosted server is
  refused too, naming the options to give instead.
- **Not the CLI.** `--headscale-cli` is refused for the takeover: the
  CLI's listing has no HTTP `Date`, by which the old node's last-seen time
  is judged.
- **The old node must be dead** by Headscale's own listing (its `Date`,
  and the node's online state and last-seen time): offline, and last seen
  more than 5 minutes ago, checked again right before the rename. A node
  with no last-seen time is refused, and so is a listing without a
  `Date`, or one more than an hour off this host's clock; nothing is
  renamed.
- **The key is expired when the takeover ends**, refusals included. When
  it cannot be (the
  control server unreachable, say), the warning names the command that
  expires it on the control server, `headscale apikeys expire --prefix
  <prefix>`.
- **A takeover under way finishes only where it began.** Its journal
  records the control server and the restored node's StableID (Headscale's
  node ids are small numbers another server or node can carry). A rerun
  against another `tailnet_control_url`, or on another node, is refused
  before anything is renamed: `the handoff under way (<operation>) began
  against <url>, not this tailnet_control_url (<url>): set
  tailnet_control_url back to finish it; nothing was done`.
- **A Headscale on a private address needs `outbound_allow`.** The
  takeover's calls go through the outbound policy; when it refuses them,
  the message names the line to add to `varlatchd.conf`.
- **No certificates** are asked for on Headscale.


### Finish

`varlatch migrate --finish` ends the window, after its 30 days or earlier
when you decide. **It cannot be undone**: from then on `--rollback`
refuses.

```sh
sudo varlatch migrate --finish --config /etc/varlatch/varlatchd.conf
```

(or the image target's `--to-*` options), from the Compose directory or
with `--from`.

**After a migration**, it removes the TypeScript installation's containers
and the old tailnet node's state and certificates (its Tailscale and Caddy
volumes). Its data volumes stay, unless you add `--delete-old-data`:

```sh
sudo varlatch migrate --finish --delete-old-data \
  --config /etc/varlatch/varlatchd.conf \
  --bek-file /path/to/backup-key \
  --backup-destination offsite --read-credentials-file /path/to/read.json
```

- First, a final archive of the whole old installation is made, uploaded
  to the destination, then downloaded back and verified. The backup
  options are this archive's. The TypeScript release takes a backup while
  it is marked migrated out (for this archive), never behind the
  transfer's barrier. Its stopped services are started for it only while
  that gate is in its state volume.
- Only once the journal records the verified archive are the old
  PostgreSQL and Convex volumes removed, with the TypeScript
  installation's `<project>_varlatch-state` volume. They are the volumes
  its containers were on when `--finish` began, recorded then: the Compose
  files must still name them before the archive, and each must be the same
  volume, of the installation's project and unused, right before it is
  removed. Otherwise nothing is removed.
- After that, the old data can be restored only through that final
  archive (with the [converter](#old-archives-the-converter)).

**After a rollback**, the TypeScript release runs again, and `--finish`
closes the window on the 0.50 side. Without `--delete-old-data`, the 0.50
server's copy is kept as it is. With it, a final archive of that copy is
made and verified (format 3, restorable with `setup --restore`). Then the
volumes from before the migration, unused since the rollback rebuilt the
database, are removed, and after them the copy is discarded. Before the
archive and again before the removal, the TypeScript release must run on
the rebuilt volumes, and each volume removed must be the one the journal
recorded when the rollback began, be the installation's project's, and be
mounted by no container. Otherwise nothing is removed and the copy is kept.

On Coolify, the removals after a migration are yours: `--finish` names each
resource to delete in Coolify, and does not reach Coolify itself. After a
rollback it removes the two volumes from before the migration itself, there
too.

After a migration that moved the tailnet name, the old node stays in the
control plane under its `<name>-vl-<op>-o` name: `--finish` removes its
local state only, and takes no tailnet authority. Delete that node
yourself, in the tailnet's admin console on Tailscale, or with
`headscale nodes delete --identifier <its id>` on Headscale.

In the tailnet shape (varlatchd with `network_mode: service:tailscale`),
run `--finish --delete-old-data` straight away rather than a plain
`--finish` first. After a plain `--finish`, or after a migration that moved
the tailnet name (which stopped the sidecar), `--delete-old-data` is
refused, because its final archive would need the old Tailscale node
running beside Go's; the data volumes are then removed by hand (on Coolify,
delete the TypeScript application with its volumes instead of step 2):

1. Back them up by your own means, and test that the backup restores,
   before you remove anything.
2. Then remove them:
   `docker volume rm <project>_postgres-data <project>_convex-data`.

Until `--finish`, after a migration the old installation stays as it is:
marked migrated out, refusing every request, its data untouched. After a
rollback, the 0.50 server's copy and the volumes from before the
migration stay.

## Old archives: the converter

The 0.50 server keeps the TypeScript server's archives (formats 1 and 2)
where they are and never deletes them. `varlatchd admin backup status`
lists them apart, as restorable through the converter, with the date their
retention ends when the migration knows it (an Object Lock retain-until
date); otherwise your bucket's lifecycle rule decides. Deleting them after
that date is yours, or the bucket's.

To turn one into a 0.50 archive:

```sh
varlatch migrate --from-archive <archive> \
  --kek-file /path/to/varlatch-kek --bek-file /path/to/backup-key \
  --out <new archive>
```

- It runs on a Linux or macOS host with Docker, one conversion at a time
  per host.
- The archive is restored in a throwaway PostgreSQL with no network, and
  exported by the last TypeScript release's image, which runs no server
  and sends nothing. The 0.50 server then imports it, runs every check of
  the migration, and seals a format 3 archive at `--out`, of the same
  installation and with the same keys. Restore it with `setup --restore`.
- `--ts-image <name>@sha256:<digest>` names the TypeScript release's image
  by its registry digest. By default it is the one this `varlatch` pins:
  0.23.0's published image.
- When `--bek-file` holds a passphrase rather than the key,
  `--out-bek-file` names the key file the new archive is sealed with.
- Any archive from 0.7.0 on converts. The converter ships with every
  release for at least 12 months, and until every old archive's retention
  has ended.
