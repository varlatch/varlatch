# Scheduled backups with systemd (reference tooling)

A root systemd timer that runs `varlatch admin backup` nightly on
the host that runs the Compose installation: capture, delivery to an
S3-compatible destination, local verification, pruning, and a published
status file. Use it as-is on any systemd host, or as the template for your own
scheduler; the underlying commands are documented in
[`docs/operations/backup.md`](../../docs/operations/backup.md).

## Design

- **Root, installed once by a human.** Driving `docker compose` is
  root-equivalent. Rather than giving that to an unattended user account (or to
  automation that logs in as one), the job runs as root from a unit a human
  installs with `sudo`. Other accounts get read-only views:
  - `/var/lib/varlatch-backup/status.json`: world-readable per-archive
    status and warnings, refreshed after every run;
  - the `/v1/installation/backups` API (Installation Admins);
  - optionally a list-only destination key to corroborate uploads, never a
    widening of the upload key.
- **A run succeeds only if everything succeeded.** Capture, delivery, and local
  verification must all pass, or the unit fails: a local-only or unverified
  archive is a failure, never a quiet success.
- **Write-only delivery.** The host holds only an upload key. Downloading an
  archive for remote verification needs a read key, which is supplied per
  invocation and never stored here. Status warns when no
  remote verification passed within 30 days.
- **Scripts and CLI come from the running release.** Each run copies `run.sh`
  and the CLI out of the running varlatchd container
  (`/opt/varlatch/host-backup/`, `/opt/varlatch/varlatch.cjs`, root-owned in the
  image) into `/var/lib/varlatch-backup/from-image/` and runs those. Both
  always match the deployed release, so upgrades need no host step. This adds
  no trust beyond the digest-pinned image the job already drives as root. The
  installed `run.sh` is only the bootstrap, and the fallback for images that
  predate the shipped scripts (which also need a host CLI at
  `/usr/local/bin/varlatch`; see "Install the operator CLI" in `backup.md`).
  The journal logs which script and CLI version each run used.

## Files

| File | Installed to | Purpose |
| --- | --- | --- |
| `install.sh` | (none) | One-time installer; run with sudo from this directory. Idempotent; never overwrites your config. |
| `run.sh` | `/usr/local/lib/varlatch-backup/` | The nightly run. |
| `verify-remote.sh` | `/usr/local/lib/varlatch-backup/` | Periodic remote verification (see below). |
| `varlatch-backup.service` | `/etc/systemd/system/` | Oneshot unit running `run.sh`. |
| `varlatch-backup.timer` | `/etc/systemd/system/` | Nightly 03:30 UTC, randomized delay, `Persistent`. |

Configuration lives in `/etc/varlatch-backup/` (root:root 0700):

| File | Content |
| --- | --- |
| `config.env` | `COMPOSE_DIR`, optional `COMPOSE_FILE`, `DESTINATION` (default `offsite`), `LOCAL_KEEP` (default 7), optional `CLI`, `STATUS_FILE`. Written by the installer. |
| `destinations.json` | The S3-compatible destination (`backup.md`, "S3-compatible destinations"). |
| `bek` | The dedicated Backup Encryption Key. |
| `root-kek` | A copy of the Root KEK. The host already holds it as varlatchd's mounted secret, so this adds no custody surface. |
| `s3-write.json` | The write-only upload key: `{"accessKeyId":"…","secretAccessKey":"…"}`. |

Keys are root:root 0600. Keep off-host copies of the BEK and Root KEK, in
custody separate from each other and from the destination account.

## Install

Prerequisites: systemd, Docker with the compose plugin, Node.js 22+, and a
running installation.

```sh
sudo ./install.sh <compose-dir> [<compose-file-name>]
```

`<compose-dir>` is the directory the installation's compose project runs
from (`docker compose ls` shows it). If that directory holds several compose
files, name the running one as the second argument; it is recorded as
`COMPOSE_FILE` for every later call. Then, in order:

1. Place `bek`, `root-kek`, and `s3-write.json` in `/etc/varlatch-backup/`
   (root:root 0600). Scope the upload key as narrowly as your provider allows
   (`backup.md`, "Scoping destination credentials per provider").
2. Edit `/etc/varlatch-backup/destinations.json`.
3. Run once and watch: `sudo systemctl start varlatch-backup.service`, then
   `sudo journalctl -u varlatch-backup.service -n 50`.
4. Remote-verify that archive: `sudo /usr/local/lib/varlatch-backup/verify-remote.sh`.
5. Rehearse a restore on a disposable host (`backup.md`, "Restore on a fresh
   host").
6. Only then enable the schedule: `sudo systemctl enable --now varlatch-backup.timer`.

## Remote verification (at least every 30 days)

```sh
sudo /usr/local/lib/varlatch-backup/verify-remote.sh [--archive <id>] [--read-credentials-file <path>]
```

It downloads the newest archive delivered to `DESTINATION` (or `--archive`),
runs the full checks (integrity, compatibility, Root KEK match), records the
result, and republishes `status.json`. Without `--read-credentials-file` it
prompts for the read key and holds it only in a root-only `/dev/shm` file for
the duration of the command.

## Retention

Local: `run.sh` keeps the newest `LOCAL_KEEP` archives. Remote: the bucket's
lifecycle rules only. Include an incomplete-multipart-upload expiry, and never
a rule that could delete the newest verified archive. Expiring old archives is
also how old Root KEK version obligations end.
