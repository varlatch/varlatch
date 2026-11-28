# Upgrading

This page is for Linux systemd installations (`install.sh --server`). On
Docker or Coolify, upgrade by changing the pinned image digest:
[Upgrading by digest](../self-hosting/docker-and-coolify.md#upgrading-by-digest).
Still on 0.23.1? [Migrate to 0.50](migrate-to-0.50.md) first.

## Upgrade

```sh
sudo varlatch upgrade --check   # is there a newer release? Upgrades nothing
sudo varlatch upgrade           # to the newest release
```

Name a version to choose one, as in `sudo varlatch upgrade 0.50.1`. A
prerelease needs `--prerelease`. Without a terminal, add `--yes`.

The command:

1. Downloads the release's binaries, and checks that the release workflow
   signed `SHA256SUMS` for that version, and that each file matches it.
2. Shows both versions, where the changes are described, and whether you
   can go back without losing anything. Then it asks.
3. Takes an encrypted snapshot of the database, in
   `/usr/local/lib/varlatch/snapshots`
   ([how long it is kept](#what-is-kept)).
4. Stops `varlatchd`, updates a copy of the database, and puts the new
   binaries and the copy in place.
5. Starts the new release **held**: it answers `503` to everything except
   `/healthz` and does nothing in the background, while the command checks
   its health.
6. When the checks pass, it opens. When one fails, the previous binaries and
   the database from before the upgrade are put back, and the previous
   release serves.

From the stop until it opens, for some seconds, the installation does not
answer, so no change is accepted that going back would lose.

It needs root, and no keys from you. It never goes to an older release. It
refuses, before it touches the binaries or the database, when something
other than root could change the binaries or the directories it works in,
when a disk is too small, and when what it writes could not be made to
survive a power cut.

When the new release is not rollback-safe, the command says so and asks;
without a terminal it needs `--accept-not-rollback-safe`, and `--yes` is
not enough. While a migration's
[rollback window](migrate-to-0.50.md#the-rollback-window) is open, an
upgrade that would end it needs `--end-rollback-window` the same way. The
window closes as soon as you confirm, before those checks and before the
upgrade: one that is refused, fails or is undone does not open it again.

It refuses while the installation is held after a
[restore](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore):
[resume](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore)
first.

## If an upgrade is interrupted

After a reboot, a power cut, or a killed command, run it again:

```sh
sudo varlatch upgrade
```

It finishes the upgrade when the record says that its checks passed, and
undoes it otherwise, before anything else. What happens until you run it
depends on how far the upgrade was:

- **Before the stop,** the previous release serves as before.
- **From the stop until the checks passed,** `varlatchd` does not start, or
  is held and answers `503` to all but `/healthz`: what is in place may be
  half of each release. A reboot does not change that.
- **Once the checks are recorded as passed,** the new release serves after a
  reboot, also before you run the command, which then only finishes up.

`sudo varlatch doctor` and `sudo journalctl -u varlatchd` say which upgrade
is not over.

The upgrade is recorded in `/etc/varlatch/upgrade.json`. Never remove or edit
that file to get `varlatchd` started: it is what says which database is the
right one. Move it only where the command prints that step.

When it cannot go on, it says what is left and what to do. Follow what it
prints, in order, and **stop at the first command that fails**: the ones
after it count on it.

- **The undo did not complete.** `varlatchd` does not start until it does.
  Put right what the message names, a full disk for example, and run the
  command again.
- **The record is damaged.** If a newer `varlatch` wrote it, run that one's
  `upgrade` instead. Otherwise the command prints what there is, in this order:

  1. commands that say whose each database is, how far its history goes, and
     which release last changed its schema;
  2. the way on with the database in place;
  3. for each database kept beside it, with its date, the way back to it and
     its release.

  Run the first ones, and replace nothing until you know which database is the
  right one. A kept one may be an old copy, and a longer history alone does not
  make it right: a rollback replaces such a one on purpose. Where a command has
  `<release>`, put in the release that database is of. Nothing is overwritten:
  what stood in place is moved beside the kept one. With no database in place,
  start no `varlatchd` until one is back: it would make an empty one.
- **`varlatchd` is held and the record is gone.** Once no `varlatch upgrade`
  runs, `sudo systemctl restart varlatchd` serves the database in place.
- **The upgrade began with 0.50.0-rc.2 or rc.3** and its database was already
  in place: it is finished when the new release's checks pass. Otherwise both
  databases are kept, and the command prints the commands for either way.

## Go back

`varlatch upgrade` goes back by itself when the new release fails its
checks. Later, from a release that serves:

```sh
sudo varlatch upgrade --rollback
```

It returns to the release the last upgrade came from, with that release's
kept binaries. It first shows what that means for the database, and asks:

- **The database stays, with every change made since,** when the release you
  leave declared itself rollback-safe for the one you return to, and that one
  opens the database as it is.
- **Otherwise the snapshot from before the upgrade is restored, and every
  change made since it was taken is lost.** Before it asks, it shows how many
  recorded changes that is, by type, and the newest of them; the revocations,
  removals, rotations, replacements, deletions and freezes it takes back come
  first, up to 200 of them. It cannot list everything: sessions that ended
  since are valid again, and sign-ins, pending approvals and delivery
  positions go back too. Without a terminal it needs `--accept-data-loss`;
  `--yes` is not enough.

**When it says that the snapshot is restored, answer no,
[close every way in](backup.md#keep-clients-away), and run it again.** The
previous release serves as soon as its checks pass, and whatever was revoked
since the snapshot can read and write again until you revoke it again.

Like an upgrade, a rollback is held until its checks pass, is undone when one
fails, and is finished or undone by `sudo varlatch upgrade` when it was
interrupted. An undone one can be run again.

After a snapshot was restored, the command prints what to do again,
revocations first. The installation is **held**, as after any
[restore](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore):
it serves whoever reaches it, and what it would deliver or destroy on its own
waits. When you have gone through the list, resume, then open the ways in
again:

```sh
sudo varlatch admin restore resume
```

There is one step back. After a rollback, or an upgrade that was undone,
there is nothing to roll back: to go further back, restore an
[archive](backup.md#put-an-archive-back-on-the-same-host), which brings back
the database and leaves the installed binaries. It refuses when the kept
binaries are gone or are not the recorded ones; when it would restore the
snapshot, the same for the snapshot; and while a backup, a migration or a
restore holds the installation.

### To a release before 0.50.0-rc.4

Those releases cannot read a rollback's record, so the command refuses and
prints the commands to run by hand, each on a line of its own, with your
paths in them, and how to go back on each. They restore the snapshot: every
change made since it was taken is lost, and no list of them is printed.

Nor can those releases read an archive that 0.50.0-rc.4 or later made, which is
compressed: they answer `Unsupported archive format`. Keep one they made
themselves.

Those releases have no hold after a restore. Once the last command starts
`varlatchd`, revoked credentials work again, and its background work runs at
once, as the snapshot has it: webhooks, sync, audit exports, and an
organization deletion that is due, even one cancelled since. None of that can be
put right before that start. So, before the first command:

1. [Close every way in](backup.md#keep-clients-away).
2. When something in the snapshot must not be delivered or deleted, do not go
   back this way.

Run the commands in order, and **stop at the first one that fails**. They
disable the service first: an earlier release would otherwise start, after a
reboot, on what is half done.

## What is kept

Each upgrade keeps its snapshot, and a rollback that restored one keeps the
database it replaced, in `/var/lib/varlatch/upgrades`. The next upgrade
removes what is older than 30 days, but never what belongs to the last change
on record, or to the upgrade that change went back on. So they stay longer
when you do not upgrade.

What these files are, in `upgrades/<id>/`:

- `snapshot.vltbak` is a backup archive, encrypted with the backup key.
- `db/` and `original/` are **plain database files**, as the data
  directory's own: the copy that gets the new schema, and the database as
  the stopped release left it. Secret values in them stay encrypted under
  the Root KEK, but names, people, the audit log and every other record
  can be read. They exist only while an upgrade runs: once it is over,
  successful or rolled back, they are removed.
- After a rollback, `original/` stays: it is the database the rollback
  replaced, kept so that nothing written after the upgrade is lost.

Once you know you do not need it, remove a rollback's `original/` by hand,
while no `varlatch upgrade` runs (`varlatchd` may run):

```sh
sudo rm -r /var/lib/varlatch/upgrades/<id>/original
```

## Newer releases in the dashboard

The dashboard never upgrades Varlatch itself, and neither `varlatchd` nor
the browser looks for releases. `sudo varlatch upgrade --check` on the host
does. It records what it found, and Installation Admins see it under
**Installation settings**, then **Release**. On a host where you
[allow it](#upgrading-from-the-web-app), the dashboard can ask the host to
upgrade to the next release; the host decides and acts.

When it finds a newer release, it also downloads that release's
`SHA256SUMS`, its signature, `release.json` and `varlatchd-image.txt`, and
verifies them as an upgrade would: signed by the release workflow for that
version's tag, each file matching. It records what they declare (the schema,
whether the release is rollback-safe and against which release that was
checked, its image by digest) in `release-target.json` beside the check's
record, or why they could not be verified, which it also says on standard
error. A check that finds no newer release downloads nothing more. `--json`
prints the result for a script.

The Release tab shows how `varlatchd` runs (the systemd unit, or the
container image), the [pre-flight checklist](#the-pre-flight-checklist),
and the exact commands for this installation: on a systemd host
`sudo varlatch upgrade <version>`; for the image, the verified digest, the
`admin schema status` check and the redeploy steps for Coolify and for
Docker. What the check recorded is for display only: the upgrade verifies
the release again from scratch.

Every upgrade `varlatch upgrade` makes is recorded in the installation's
audit log as `installation.upgraded`, once, by the release it upgraded to:
from, to, the upgrade's id in `/etc/varlatch/upgrade.json`, the new
binaries' SHA-256 as the signed `SHA256SUMS` gave them, the pre-upgrade
snapshot's archive, when it started and ended, and `source: host`.

## Scheduling the release check

[`sudo varlatch upgrade --enable-web`](#upgrading-from-the-web-app)
installs and enables the timer below for you. Without it, nothing schedules
the check: run it once a day, as its own job, so that GitHub being
unreachable fails nothing else.

On a systemd host, a timer runs it daily at a random time in its first
hour, and at the next boot when the host was off then. Create the two
units:

`/etc/systemd/system/varlatch-release-check.service`

```ini
[Unit]
Description=Varlatch release check (varlatch upgrade --check)
Documentation=https://docs.varlatch.com/operations/upgrade/
Wants=network-online.target
After=network-online.target varlatchd.service

[Service]
Type=oneshot
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ExecStart=/usr/local/bin/varlatch upgrade --check
```

Keep `NoNewPrivileges=yes` out of this unit if you add settings that
install a system call filter (`ProtectKernelModules=`, `ProtectClock=`,
`RestrictRealtime=`, `LockPersonality=`, `SystemCallFilter=` and the
like): on some hosts the two together keep `varlatchd admin` from becoming
the data directory's owner, and the check records nothing.

`/etc/systemd/system/varlatch-release-check.timer`

```ini
[Unit]
Description=Daily Varlatch release check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Then enable the timer, and run the check once now:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now varlatch-release-check.timer
sudo systemctl start varlatch-release-check.service
```

`systemctl list-timers varlatch-release-check.timer` shows the next run, and
`journalctl -u varlatch-release-check.service` what the last one said.

Or with cron, as the file `/etc/cron.d/varlatch-release-check` (standard
output is dropped; a warning on standard error is mailed or logged, as cron
does):

```text
17 4 * * * root /usr/local/bin/varlatch upgrade --check > /dev/null
```

For the container image, schedule the same check on the Docker host, in the
running container, with the same cron file (or a Coolify scheduled task
that runs `varlatch upgrade --check` in it):

```text
17 4 * * * root docker exec <container> varlatch upgrade --check > /dev/null
```

## The pre-flight checklist

When a newer release is known, the Release tab checks, line by line, what
stands between this installation and it. Each line passes, fails or is
unknown, and each failure says what to do:

1. **The release check** ran in the last 36 hours (a daily schedule and its
   slack) and verified the release. A check that never ran, or last ran
   longer ago, fails: [schedule it](#scheduling-the-release-check). So does
   a last check that failed, or one that recorded no verification (a
   `varlatch` before this release ran it). A release whose signature or
   checksums do not verify fails with that: do not install it, and
   [verify it by hand](verify-release.md).
2. **A backup destination** is configured (`backup_destination`), and the
   last backup was delivered there in the last 24 hours
   ([S3-compatible destinations](backup.md#s3-compatible-destinations)).
3. **Both keys** have a Custody Attestation
   (`varlatchd admin custody attest`).
4. **Free space** in the data directory for the snapshot and the database
   copy: about twice the database, plus 64 MiB.
5. **Nothing in the way:** no upgrade or rollback that is not over, no
   restore hold, no maintenance, and no open migration rollback window that
   the release would end.
6. **Rollback-safe for this release:** the release declares itself
   rollback-safe, checked against exactly the release this installation
   runs, and this release opens the upgraded database. A release declares
   that only for the one before it, so an installation that is more than one
   release behind fails this line ("0.52.0 was checked against 0.51.1, not
   0.51.0: upgrade one release at a time"). Going one release at a time,
   `sudo varlatch upgrade <version>` for each, oldest first, keeps each step
   rollback-safe where each release declares it.

7. **The host helper** is installed
   ([`sudo varlatch upgrade --enable-web`](#upgrading-from-the-web-app)),
   accepts requests, and its heartbeat comes from the last release check.
   This line is only on systemd hosts.

The checklist judges; it starts nothing. `varlatch upgrade` refuses for
itself what it must, whatever the checklist says.

## Upgrading from the web app

On a systemd host you can let Installation Admins upgrade to the next
release from the dashboard. The dashboard only asks; a helper on the host,
which you install, checks everything again and runs the same upgrade as
`sudo varlatch upgrade`. It is off until you turn it on:

```sh
sudo varlatch upgrade --enable-web    # allow it
sudo varlatch upgrade --disable-web   # stop allowing it
```

`varlatch setup` asks the same question at its end, with no as the default.

### What `--enable-web` installs

- `/var/lib/varlatch-upgrade/taken`, a directory only root can read. It
  must be on the same file system as the data directory
  (`/var/lib/varlatch`), because taking a request is a rename; otherwise
  `--enable-web` refuses.
- In `/etc/systemd/system`, all run as root, each a oneshot with a private
  `/tmp`, no access to home directories, no kernel module, kernel log,
  tunable, clock or host name changes, and no core dump. They do not set
  `NoNewPrivileges`: together with those kernel settings it kept
  `varlatchd admin` from becoming the data directory's owner on some
  hosts, and a unit that is root with every capability gains nothing from
  it:
  - `varlatch-upgrade.path` and `varlatch-upgrade.service`: when
    `varlatchd` writes a request, the service runs
    `varlatch upgrade --from-request`. Nothing listens, and nothing runs
    between requests.
  - `varlatch-upgrade-recover.service`: at boot, after `varlatchd`, it
    runs `varlatch upgrade --recover`, which finishes or undoes an
    interrupted upgrade, so the installation does not stay unavailable
    until someone logs in.
  - `varlatch-release-check.timer` and its service: the
    [daily release check](#scheduling-the-release-check), run once right
    away. Each run also records that the helper is there (its heartbeat),
    which the [pre-flight](#the-pre-flight-checklist) checks.
- `/etc/varlatch/web-upgrade.conf`, which says that requests are accepted,
  and nothing else.

`--enable-web` writes `web-upgrade.conf` last, once the units are enabled;
if a step fails, it removes what it installed and says so, so the host never
claims to accept requests that nothing takes. `--disable-web` removes
`web-upgrade.conf` and the units. Both refuse while the helper is taking or
running a request. `--disable-web` does not stop a boot recovery that is
running: it finishes or undoes its upgrade first. The taken requests stay in
`/var/lib/varlatch-upgrade/taken` as a record. Without the helper, the
dashboard shows the commands to run, whatever an admin clicks.

### When the helper cannot take a request

The helper can fail before it takes a request: `varlatchd`'s configuration
names no data directory it can use, the `upgrade-request` directory was
replaced by a link, or `/var/lib/varlatch-upgrade/taken` is no longer
root's alone. The request then stays where it is. The helper records the
problem in its heartbeat, so the pre-flight's helper line says it and the
**Upgrade** button goes away, and it tries again once a minute until
`varlatchd` removes the request when it expires, 10 minutes after it was
made. `sudo journalctl -u varlatch-upgrade.service` says what failed. Put
it right, then clear the problem with a release check:

```sh
sudo systemctl start varlatch-release-check.service
```

If the helper fails again and again at once (its binary is missing, for
example), systemd stops starting it once it hits the service's start limit
(20 starts in 10 minutes), and no request is taken until you reset it.
`sudo varlatch doctor` reports that as `release.web-upgrade-units`. Once
you have put the cause right:

```sh
sudo systemctl reset-failed varlatch-upgrade.service varlatch-upgrade.path
sudo systemctl start varlatch-upgrade.path
```

### What happens when an admin asks

The **Upgrade** button appears only when every line of the
[pre-flight checklist](#the-pre-flight-checklist) passes, and only for one
step: the newest release, when it declares itself rollback-safe for the
release you run. A host that is two releases behind gets the commands, one
release at a time.

1. The admin confirms, with the downtime shown, and approves with a
   trusted passkey and its PIN, fingerprint or face. The approval is for
   that exact request (this installation, from this release, to that one,
   its id) and is used once, within 2 minutes. A passkey added from a
   signed-in session and never confirmed cannot approve it.
2. `varlatchd` writes the request (only a version, its id, who asked, and
   when it expires, 10 minutes later) into its data directory. One request
   is pending at a time; any Installation Admin can cancel it until the
   host takes it.
3. The helper takes it, by moving it into its own directory, and reads it
   as untrusted input. It refuses, and says why, when the request expired,
   the host does not accept requests, the version is a prerelease or not
   newer, it is not the newest release (it asks GitHub again itself), the
   release is not rollback-safe for this one, it would end a migration's
   rollback window, the host already undid an upgrade to that version (or
   rolled back from it), another upgrade or rollback is not over, the
   installation is held after a restore, a maintenance gate is set, or no
   backup destination is configured.
4. It verifies the release as `sudo varlatch upgrade` does, from the
   pinned repository and signing identity, and runs the same steps with no
   override: no `--accept-not-rollback-safe`, `--end-rollback-window` or
   `--prerelease`.
5. Its snapshot is made with `admin backup run --json --verify-remote`:
   uploaded to your backup destination and downloaded back and checked,
   while Varlatch still serves. If that fails, the upgrade ends before
   anything stops.
6. Every signed-in dashboard is told that Varlatch restarts. It is
   unavailable for about a minute; CLI commands, Brokers and syncs that run
   then fail or wait, and webhooks and syncs catch up after.
7. When the new release's health checks pass, it opens; when one fails, the
   previous release serves again, and the dashboard says which check
   failed.

The admin's tab shows each step. The audit log records
`installation.upgrade_requested`, `installation.upgrade_cancelled` (by an
admin, or when the request expired), `installation.upgrade_cancel_too_late`,
`installation.upgrade_refused` (with the reason's class),
`installation.upgraded` (with the request's id and `source: web`) and
`installation.upgrade_undone`.

A version the host undid is not offered again from the web: run
`sudo varlatch upgrade` after reading why (`sudo cat
/etc/varlatch/upgrade.json`), which also clears it. A newer release is
offered again as usual. Going back (`--rollback`) is not offered from the
web.

### Trust model

The web app never upgrades anything, and `varlatchd` gains no privilege:
it can only write a request that names a version, in its own data
directory. The helper decides everything else itself: which release is the
newest, from the pinned repository; whether it is signed by the release
workflow; whether it is one rollback-safe step; whether a backup reached
your destination and checks out. What `varlatchd` recorded (the release
check, the request's status, the helper's heartbeat) is display only: a
forged file can make the button appear, never make an upgrade happen.

The helper cannot check the admin's passkey itself: the passkeys are in the
database `varlatchd` controls. So a compromised `varlatchd` can file a
request no admin made. What it gets is bounded: an upgrade to the newest
genuine, signed release, one step from the installed one and rollback-safe
for it, with a backup first and the undo armed. A compromised browser
session gets less: every request needs a fresh passkey approval for it.
The actor recorded with a request is as trustworthy as `varlatchd`; the
releases, the outcome and the snapshot in `installation.upgraded` and
`installation.upgrade_undone` come from root's journal.

## The CLI on other machines

Each person updates their own CLI: `varlatch self-update`, or their package
manager ([Install the CLI](../reference/install-the-cli.md)).
