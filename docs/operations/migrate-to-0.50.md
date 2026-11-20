# Migrating an installation to Varlatch 0.50

Varlatch 0.50 is a new server: one `varlatchd` binary with its own
database, in place of the Compose installation's services (the TypeScript
server, PostgreSQL and Convex). `varlatch migrate` moves an installation
from the last TypeScript release to it. It keeps the installation's
identity, its address and its keys, and every person, Organization,
Project, value, grant, credential and audit event, checked on both sides
before the new server opens.

> **Not released yet.** This guide describes the migration as it ships with
> the last TypeScript release (0.23.0) and the first 0.50 release. Until
> 0.23.0 is published, `varlatch migrate` refuses every source.

<!-- pending: the whole guide follows the step 7 pull requests; each
     "pending" comment below names the one a point depends on. When it
     merges, check the point against it and remove the comment. -->

## What people notice

- **They sign in again, with the same passkey.** Every browser session ends
  at the migration. Passkeys keep working: the address stays the same, and
  a passkey belongs to its address. Nobody enrolls a new one.
- **CLIs and applications keep working.** CLI sign-ins, device sign-ins,
  machine, agent and OIDC credentials are carried over with their expiry,
  revocations and use limits. A CLI keeps its server address, so released
  CLIs and the new one go on working without a new `varlatch login`.
- **A short downtime.** From the barrier to the open, the installation
  answers `503` with a `Retry-After` hint: fetching values, OIDC
  exchanges, sign-ins and device sign-ins wait, and a CLI polling a device
  sign-in continues against the new server at the same address.
  Applications that already hold their values keep running. Do not
  schedule CI deploys during the window. The dry run measures how long it
  will be (see [The dry run](#the-dry-run)).
- **Unfinished sign-ins are retried.** A passkey ceremony or sign-in that
  was in flight at the barrier fails and is started again. The dry run
  counts them.
- **Dashboards and live views reconnect** to the new server on their own.

Sync Targets, webhooks and audit export are drained at the barrier and
resume on the new server from where they stopped: nothing already
delivered is sent again, and a failed delivery is retried under the same
rules. The final report lists each one's last delivery.

## Before you start

### Upgrade to the last TypeScript release first

`varlatch migrate` takes exactly one source: a Compose installation of the
last TypeScript release, **0.23.0**, running its published image (checked by
its registry digest). Upgrade to it first, the usual way
([Upgrade](../../infra/compose/README.md#upgrade-backup-gated-forward-only)),
and let it run. Check that its exposure backfill has finished, and that no
key rotation is in progress: the migration refuses a source in either
state.

<!-- pending: 0.23.0 published and its digest pinned in varlatch migrate
     (LastTypeScriptDigest, #357); until then every source is refused. -->

### What you need

On the installation's host, as root:

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
    run `varlatch setup` first: when the host install does not exist,
    `varlatch migrate` creates it with setup's own files (the `varlatch`
    system user, the data directory, `/etc/varlatch`, the configuration
    and the unit). It generates no keys: the target's Root KEK and Backup
    Encryption Key are the source's, copied into its key files. A host
    install you prepared yourself is accepted too, as long as its data
    directory is empty and it has not been started.
  - **The 0.50 image** (`--to-data`, `--to-keys`, `--to-config`,
    `--to-image` and `--to-service`), its service created in setup mode
    with nothing listening, and its data directory, keys directory and
    configuration as bind paths on this host. See
    [The image target](#the-image-target).

  The target's `public_url` must be the source's `VARLATCH_PUBLIC_URL`,
  scheme, host and port alike: passkeys belong to that address. A
  migration onto another address is refused; move afterwards with
  [`varlatch move`](move-installation.md).

<!-- pending 7.4e: migrate creating the host install with setup's files
     code (user, data directory, /etc/varlatch, configuration, unit; keys
     from the source through admin migrate keys, never generated), and
     accepting a prepared one (empty data directory, not started). Check
     the options it takes for the configuration it writes (listen,
     listen_https, public_url from the source) when it lands. -->

`varlatch migrate --help` lists every option.

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
Projected downtime 2m10s fits the budget of 10m0s: drain up to 30s,
export 25s, import 20s, checks 15s, address transfer 1m0s (estimated for
public ingress, the target's restart included; included in the projection).
```

- **Checks passed** must be `true`. The checks compare both sides without
  showing any secret: every row, every encrypted item (by keyed digests,
  under a key made for the run and then discarded), every access decision
  the old server makes, and the audit log. A failed check names its class.
- **Projected downtime** is the drain, the final copy and checks (measured
  on the same data) and the address transfer (estimated by the ingress:
  about a minute for a certificate or a Coolify domain move, seconds for
  your own proxy). The migration refuses to start its barrier when the
  projection exceeds `--max-downtime` (10 minutes by default).
- **Drain** is bounded by `--drain`: in-flight requests, Sync Target
  pushes, webhook deliveries and audit export batches finish within it,
  and nothing new starts.

`varlatch migrate --status` shows where a migration stands, from the
source's directory. Add `--json` for the full report.

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

Any failure after the barrier undoes the migration the same way. If the
control plane of the tailnet cannot be reached during an undo, both
installations stay closed until `--resume` finishes it. `varlatch
migrate --abort` undoes a migration that has not switched yet, the address
first.

<!-- pending #364: the interrupted phases' stated states, as G5's
     interrupted half pins them. -->

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

<!-- pending #359: --ingress public|proxy|coolify, the preflight's
     refusals, --transfer-timeout, --abort. -->

### On Coolify

`varlatch migrate` does not change anything in Coolify: you make each step
it asks for, then run it again with `--resume`.

1. Create the 0.50 application in Coolify in setup mode, from the image,
   with nothing listening (see [The image target](#the-image-target)).
2. Run the migration with `--ingress coolify` and the image target's
   options. After the final copy it stops (exit status 75) and says, step
   by step, what to do:
   - start the 0.50 service: in Coolify, **Deploy** it (it starts isolated
     behind the migration's gate);
   - move the domain: in Coolify, move the installation's domain from the
     TypeScript application to the 0.50 one (its domain setting), and
     redeploy the proxy if Coolify asks.
3. Run `varlatch migrate --resume` with the same options. It checks
   `/v1/meta` through the public URL, then switches and opens.

If the check fails, `--resume` checks again once you have fixed the
domain. `--abort` undoes the migration: it tells you to move the domain
back to the TypeScript application first.

<!-- pending #361: the image target's operator steps on Coolify (Deploy,
     Stop) and the exit-75 stops; 7.8b's Coolify rehearsal confirms them. -->

### The tailnet

When the installation serves its tailnet address, the migration hands the
tailnet name over to a new node, by rename, in the same transfer:

- Before the barrier, the new server's node joins under a temporary name
  (`<name>-vl-<id>-n`) and gets a certificate for it, which proves
  issuance works now. The old node's certificate is renewed first if it
  would expire within the rollback window and seven days.
- Under the barrier, the old node is renamed to `<name>-vl-<id>-o` and the
  new node to `<name>`, back to back, within one 180-second deadline. The
  old sidecar stops without logging out: its state is kept for the
  rollback window.
- The transfer counts only once `<name>`, resolved from a client node,
  reaches the new node. Any failure renames both nodes back.

With both a public (or Coolify) address and the tailnet address, the order
is fixed: the domain first, checked through the public URL; then the
tailnet name, checked from a client node; then both together. A failure
undoes them in reverse order.

<!-- pending 7.5b part 2 (not opened yet): the tailnet handoff wired into
     varlatch migrate, its options for the authority and the auth key, and
     the combined order. The engine is #365, the control plane #360. -->

#### The tailnet authority

The rename needs authority over the tailnet, for the migration only.

- **Tailscale**: an OAuth client with the **`devices:core`** scope and no
  other, generated in the Tailscale admin console. The migration refuses a
  client with any other scope. Each operation exchanges the client for a
  token of its own, and no token is kept. Also create an auth key for the
  new node, with the node's tags, and give it to the migration. Revoke the
  client once the migration has opened; a rollback needs one again, so
  create a new one then.
- **Headscale**: run the migration where the `headscale` CLI reaches the
  control server, or give it an API key that expires within the hour
  (`headscale apikeys create --expiration 1h`). A Headscale API key is a
  full administrator, so a longer-lived one is refused, and the migration
  expires the key when it ends.

<!-- pending 7.5b part 2: the options that take the OAuth client, the API
     key and the auth key, and how each is read (never an argument). -->

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
  not.
- `--to-image` is pinned by its digest, and its tag is the release of the
  `varlatchd` on this host, which fills the bind paths as the image's user.
  The migration does not run Docker against the service: that it runs this
  digest is yours to check.
- Starting and stopping the service are yours. The migration stops (exit
  status 75) at each step and says exactly what to run: in Coolify,
  **Deploy** or **Stop**; with Docker Compose, `docker compose up -d
  <service>` or `docker compose stop <service>`. Then run it again with
  `--resume`.

<!-- pending #361: --to-data, --to-keys, --to-config, --to-image,
     --to-service, the ownership checks and the human steps. -->

## The rollback window

For **30 days after the switch**, `varlatch migrate --rollback` returns the
installation to the last TypeScript release, with everything that changed
since. It works while every release the installation has run since is
reversible to 0.23.0: each 0.50 release says so in its `release.json`
(`reversibleTo`), and is tested against 0.23.0 before it is published. A
release that cannot keep the window says so instead
(`endsRollbackWindow`), and `varlatch upgrade` asks before upgrading to it:

> This release ends the migration's rollback window: after it, `varlatch
> migrate --rollback` can no longer return this installation to the
> TypeScript release (0.23.0). Its data stays; only the way back goes.

<!-- pending #368: reversibleTo / endsRollbackWindow in release.json.
     pending 6.6b wiring: varlatch upgrade saying the notice and asking. -->

### Roll back

From the Compose directory of the migration, with the new server running:

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

<!-- pending #370: the --rollback phases and their undo. -->

### Archives made during the window

The TypeScript release cannot read the 0.50 server's archives (format 3).
The rollback's report lists every one made since the switch:

```text
Go archive made since the switch, not deleted: <archive id> (release 0.50.0, <date>).
```

They are not deleted. Each can be restored only by a 0.50 server, onto a
fresh host:

```sh
sudo varlatch setup --restore <archive> \
  --root-kek-file /path/to/varlatch-kek --backup-key-file /path/to/backup-key
```

or by the installation a later forward migration makes.

<!-- pending #341: setup --restore. -->

### Finish

`varlatch migrate --finish` ends the window, after its 30 days or earlier
when you decide:

- it deletes the old tailnet node's retained state and certificate;
- it removes the old containers;
- with `--delete-old-data` only, it makes a final archive of the retained
  PostgreSQL and Convex volumes, verifies it, and then removes them.

Without `--finish`, the old installation stays as it is: marked migrated
out, refusing every request, its data untouched.

<!-- pending 7.6a-3 (not opened yet): --finish is still being built; this
     section is written from the design and must be checked against it. -->

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
- `--ts-image <name>@sha256:<digest>` names the TypeScript release's image,
  pinned by digest. It is required until the converter carries 0.23.0's
  digest.
- When `--bek-file` holds a passphrase rather than the key,
  `--out-bek-file` names the key file the new archive is sealed with.
- Any archive from 0.7.0 on converts. The converter ships with every
  release for at least 12 months, and until every old archive's retention
  has ended.

<!-- pending #362: --from-archive, --ts-image, --out-bek-file, Linux and
     macOS only. pending #356: the status listing TypeScript-format
     archives apart, and their retainUntil date. -->
