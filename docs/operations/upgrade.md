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
   can go back. Then it asks.
3. Takes an encrypted snapshot of the database, kept 30 days in
   `/var/lib/varlatch/upgrades`.
4. Updates a copy of the database, replaces the binaries and the database,
   and restarts `varlatchd`. The installation does not answer for the few
   seconds this takes.
5. Checks the new release's health. When a check fails, it puts the
   previous binaries and the database from before the upgrade back, and the
   previous release serves.

It needs root, and no keys from you. It never goes to an older release.

When the new release is not rollback-safe, the command says so and asks
for `--accept-not-rollback-safe` without a terminal. While a migration's
[rollback window](migrate-to-0.50.md#the-rollback-window) is open, an
upgrade that would end it needs `--end-rollback-window`.

It refuses while the installation is held after a
[restore](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore).

If an upgrade is interrupted, by a reboot for example, run
`sudo varlatch upgrade` again: it finishes the upgrade or undoes it, before
anything else.

## Go back

`varlatch upgrade` goes back by itself when the new release fails its
checks. There is no command yet to go back later, from a release that
serves.

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
