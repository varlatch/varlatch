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
3. Takes an encrypted snapshot of the database, kept 30 days in
   `/usr/local/lib/varlatch/snapshots`.
4. Stops `varlatchd`, updates a copy of the database, and puts the new
   binaries and the copy in place.
5. Starts the new release **held**: it answers `503` to everyone and does
   nothing in the background, while the command checks its health.
6. When the checks pass, it opens. When one fails, the previous binaries and
   the database from before the upgrade are put back, and the previous
   release serves.

From the stop until it opens, for some seconds, the installation does not
answer, so no change is accepted that going back would lose.

It needs root, and no keys from you. It never goes to an older release. It
refuses, before it changes anything, when something other than root could
change the binaries or the directories it works in, when a disk is too
small, and when what it writes could not be made to survive a power cut.

When the new release is not rollback-safe, the command says so and asks;
without a terminal it needs `--accept-not-rollback-safe`. While a migration's
[rollback window](migrate-to-0.50.md#the-rollback-window) is open, an
upgrade that would end it needs `--end-rollback-window`.

It refuses while the installation is held after a
[restore](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore):
[resume](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore)
first.

## If an upgrade is interrupted

After a reboot, a power cut, or a killed command, run it again:

```sh
sudo varlatch upgrade
```

It finishes the upgrade when its checks had passed, and undoes it otherwise,
before anything else. Until then `varlatchd` does not start, or stays held
and answers `503`: what is in place may be half of each release. A reboot
does not change that. `sudo varlatch doctor` and
`sudo journalctl -u varlatchd` say which upgrade is not over.

The upgrade is recorded in `/etc/varlatch/upgrade.json`. Never remove or edit
that file to get `varlatchd` started: it is what says which database is the
right one. Move it only where the command prints that step.

When it cannot go on, it says what is left and what to do. Follow what it
prints: it names your files.

- **The undo did not complete.** `varlatchd` does not start until it does.
  Put right what the message names, a full disk for example, and run the
  command again.
- **The record is damaged.** The command prints, each on a line of its own,
  the commands that go on with the database in place, or that go back to the
  original database it found. If a newer `varlatch` wrote the record, run
  that one's `upgrade` instead.
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
  change made since is lost.** Those changes are listed first: the revocations,
  removals, rotations, deletions and freezes it takes back, then what else was
  recorded. It cannot list everything: sessions that ended since are valid
  again, and sign-ins, pending approvals and delivery positions go back too.
  Without a terminal it needs `--accept-data-loss`; `--yes` is not enough.

Like an upgrade, a rollback is held until its checks pass, is undone when one
fails, and is finished or undone by `sudo varlatch upgrade` when it was
interrupted. An undone one can be run again.

After a snapshot was restored, the database it replaced is kept 30 days with
the rollback, and the command prints what to do again, revocations first. The
installation is **held**, as after any
[restore](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore):
it serves people, and what it would deliver or destroy on its own waits. When
you have gone through the list:

```sh
sudo varlatch admin restore resume
```

There is one step back. After a rollback, or an upgrade that was undone,
there is nothing to roll back: to go further back, restore an
[archive](backup.md#put-an-archive-back-on-the-same-host). It refuses when
the kept binaries or the snapshot are gone or are not the recorded ones, and
while a backup, a migration or a restore holds the installation.

### To a release before 0.50.0-rc.4

Those releases cannot read a rollback's record, so the command refuses and
prints the commands to run by hand, each on a line of its own, with your
paths in them, and how to go back on each. Run them in order. They restore
the snapshot, so every change made since the upgrade began is lost, and they
disable the service first: an earlier release would otherwise start on what
is half done after a reboot.

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
