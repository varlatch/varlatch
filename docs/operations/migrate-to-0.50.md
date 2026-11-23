# Migrating an installation to Varlatch 0.50

Varlatch 0.50 is a new server: one `varlatchd` binary with its own
database, in place of the Compose installation's services (the TypeScript
server, PostgreSQL and Convex). `varlatch migrate` moves an installation
from the last TypeScript release to it. It keeps the installation's
identity, its address and its keys, and every person, Organization,
Project, value, grant, credential and audit event, checked on both sides
before the new server opens.

> **Prerelease.** This guide follows the 0.50 prereleases. The last
> TypeScript release, 0.23.0, is published, and `varlatch migrate` starts
> from its published image only.

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
- **Dashboards and live views reconnect** to the new server on their own.

Sync Targets, webhooks and audit export are drained at the barrier and
resume on the new server from where they stopped: nothing already
delivered is sent again, and a failed delivery is retried under the same
rules.

## Before you start

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
- **The Backup Encryption Key** (`--bek-file`) and, when the Root KEK is not
  where the installation's `.env` says, its file (`--kek-file`). The new
  server uses the same two keys, so every archive, old and new, opens with
  them. No key is rotated, and no new key ceremony is needed.
- **A backup destination** (`--backup-destination`, as configured, or from
  `--destinations-file`) and its **read credentials**
  (`--read-credentials-file`): the preflight uploads a fresh backup, then
  downloads it and verifies it, as
  [Create and verify](backup.md#create-and-verify) describes.
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
      refuses before anything is made or backed up: `the target migrate
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
  Targets' connections at `https://api.github.com` included, and exits 0
  when all are allowed. For a refused one it names the `outbound_allow`
  line to set in that file, and how to restart `varlatchd` after it.

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
Projected downtime 3m0s fits the budget of 10m0s: drain up to 1m0s, export 25s, import 20s, checks 15s, address transfer 1m0s (estimated for public ingress, the target's restart included; included in the projection).
```

A dry run does not move the address, so its transfer time is the
ingress's estimate, and the report says so in the parenthesis. A
migration that measured its transfer reports the time alone.

- **Checks passed** must be `true`. The checks compare both sides without
  showing any secret: every row, every encrypted item (by keyed digests,
  under a key made for the run and then discarded), every access decision
  the old server makes, and the audit log. A failed check names its class.
- **Projected downtime** is the drain, the final copy and checks (measured
  on the same data) and the address transfer (estimated by the ingress:
  about a minute for a certificate or a Coolify domain move, seconds for
  your own proxy). The migration refuses to start its barrier when the
  projection exceeds `--max-downtime` (10 minutes by default).
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
   one that a failed start left without a network. On Coolify, you move
   the domain back when asked.
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

1. Create the 0.50 application in Coolify as a **Docker Compose** resource
   pointing at `infra/coolify/varlatchd.compose.yml` (see
   [its Coolify setup](../../infra/coolify/README.md#single-container-go-service-050)
   and [The image target](#the-image-target)),
   with `VARLATCH_VARLATCHD_DIGEST` set to the release's verified digest,
   in setup mode with nothing listening (do not click **Deploy** yet):
   - create the host configuration file (`/srv/varlatch/varlatchd.conf`, or
     `VARLATCH_CONFIG_FILE`) as a regular file before clicking **Deploy**,
     otherwise Docker creates an empty directory there and `varlatchd`
     fails with `EISDIR`;
   - set `listen = 0.0.0.0:8686` and `trusted_proxies = coolify-proxy` in
     `varlatchd.conf`, and leave `listen_https` unset (Coolify's proxy
     terminates TLS; setting `listen_https` with `listen = 0.0.0.0:8686`
     makes `varlatchd` refuse to start with exit `78` and crash-loop).
2. Run the migration with `--ingress coolify` and the image target's
   options. After the final copy it stops (exit status 75) and says, step
   by step, what to do:
   - start the 0.50 service: in Coolify, **Deploy** it (it starts isolated
     behind the migration's gate);
   - move the domain: in Coolify, move the installation's domain from the
     TypeScript application to the 0.50 `varlatchd` service on port `8686`,
     and redeploy the proxy if Coolify asks.
3. Run `varlatch migrate --resume` with the same options. It checks
   `/v1/meta` through the public URL, then switches and opens.

If the check fails, `--resume` checks again once you have fixed the
domain. `--abort` undoes the migration: it tells you to move the domain
back to the TypeScript application first.

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
- The transfer counts only once `<name>`, resolved from a client node,
  reaches the new node. Any failure before the new node opens renames both
  nodes back (each read back) and reopens the old node.

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
  not. On Coolify, `infra/coolify/varlatchd.compose.yml`'s default bind
  paths and service name match `--to-data /srv/varlatch/data`,
  `--to-keys /srv/varlatch/keys`, `--to-config /srv/varlatch/varlatchd.conf`
  and `--to-service varlatchd`, and its `VARLATCH_VARLATCHD_DIGEST`
  variable pins the digest matching `--to-image`.
- `--to-image` is pinned by its digest, and its tag is the release of the
  `varlatchd` on this host, which fills the bind paths as the image's user.
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

### Roll back

From the Compose directory of the migration (or with `--from`), with the
new server running:

```sh
sudo varlatch migrate --rollback --config /etc/varlatch/varlatchd.conf
```

(or the image target's `--to-*` options). The new server keeps running
until the address moves back:

1. The new server takes a barrier and freezes its state; it keeps running,
   isolated.
2. Its state is exported for the TypeScript release, with the same two
   changes as the forward migration: browser sessions end, and the audit
   log records the migration.
3. The TypeScript release starts on a **fresh** database: new PostgreSQL
   and Convex volumes. The volumes from before the migration are kept as
   they are.
4. The rebuilt database is checked against the new server's copy.
5. The address moves back: the new server stops serving it, and the
   TypeScript release and its ingress start on it. On Coolify, move the
   domain back to the TypeScript application when asked, then run
   `--resume`.
6. Rolled back: the new server never starts on that data directory again.

Until the address moves, an interruption, a failed check or `--abort`
undoes the rollback, and the new server goes on serving. During the
transfer, `--resume` checks again and `--abort` gives the address back to
the new server first. People sign in again after a rollback too.

On a Tailscale topology (`varlatchd` with `network_mode: service:tailscale`):

- **After a migration that moved the tailnet name**, the rollback starts
  the old `tailscale` sidecar itself, which the migration stopped at the
  switch. Its old node comes back under its temporary name. The name stays
  with the new server's node until the address moves back, then returns
  to the old node. An undo of the rollback stops the sidecar again. Give
  the tailnet authority again (see [The tailnet authority](#the-tailnet-authority)).
- **Otherwise** `varlatch migrate` never starts the old Tailscale node
  itself. If the old `tailscale` sidecar is stopped, `--rollback` refuses
  before anything and names the step: `docker compose up -d --no-deps
  tailscale`, then `varlatch migrate --rollback` again.

### Archives made during the window

The TypeScript release cannot read the 0.50 server's archives (format 3).
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
both files by absolute path):

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
   more than 5 minutes ago by the control plane's clock. This is checked
   again right before the rename. A node seen since may be the old
   installation still running, so its name is never taken; there is no
   override. Stop the old installation, wait, and run setup again.
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
- **A rerun takes the same authority.** The answers are journalled in
  `/etc/varlatch/setup.json`, and a rerun naming another control server is
  refused. A rerun reads where the takeover got to from the node's own
  state, and finishes it or leaves it done.

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
  more than 5 minutes ago, checked again right before the rename. A
  listing without a `Date`, or one more than an hour off this host's
  clock, is refused, and nothing is renamed.
- **The key is expired when the takeover ends.** When it cannot be (the
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
  transfer's barrier.
- Only once the journal records the verified archive are the old
  PostgreSQL and Convex volumes removed, with the TypeScript
  installation's `<project>_varlatch-state` volume.
- After that, the old data can be restored only through that final
  archive (with the [converter](#old-archives-the-converter)).

**After a rollback**, the TypeScript release runs again, and `--finish`
closes the window on the 0.50 side. Without `--delete-old-data`, the 0.50
server's copy is kept as it is. With it, a final archive of that copy is
made and verified (format 3, restorable with `setup --restore`), then the
copy is discarded and the volumes from before the migration, unused since
the rollback rebuilt the database, are removed.

On Coolify, the removals are yours: `--finish` names each resource to
delete in Coolify, and does not reach Coolify itself.

In the tailnet shape (varlatchd with `network_mode: service:tailscale`),
run `--finish --delete-old-data` straight away rather than a plain
`--finish` first. After a plain `--finish`, `--delete-old-data` is
refused, because its final archive would need the old Tailscale node
running beside Go's; the data volumes are then removed by hand:

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
