# Upgrading

This page is for installations on 0.50 or later that `install.sh --server`
installed. From 0.23.0, [migrate](migrate-to-0.50.md) first. On Coolify,
you change the image's digest:
[Pinning and upgrading by digest](../../infra/coolify/README.md#pinning-and-upgrading-by-digest).

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

## Newer releases in the dashboard

The dashboard never upgrades Varlatch, and neither `varlatchd` nor the
browser looks for releases. `sudo varlatch upgrade --check` on the host
does. It records what it found, and Installation Admins see it under
**Installation settings**, then **Release**.

Run it on a schedule, as its own job, so that GitHub being unreachable
fails nothing else. `--json` prints the result for a script.

## The CLI on other machines

Each person updates their own CLI: `varlatch self-update`, or their package
manager ([Install the CLI](../reference/install-the-cli.md)).
