# Upgrading

This page is for installations on 0.50 or later that `install.sh --server`
installed. From 0.23.0, [migrate](migrate-to-0.50.md) first. On Coolify,
you change the image's digest:
[Pinning and upgrading by digest](../../infra/coolify/README.md#pinning-and-upgrading-by-digest).

## Upgrade

```sh
sudo varlatch upgrade --check   # is there a newer release? Changes nothing
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
   previous binaries and the snapshot back, and the previous release
   serves.

It needs root, and no keys from you. It never goes to an older release.

When the new release is not rollback-safe, the command says so and asks
for `--accept-not-rollback-safe` without a terminal. While a migration's
[rollback window](migrate-to-0.50.md#the-rollback-window) is open, an
upgrade that would end it needs `--end-rollback-window`.

If an upgrade is interrupted, by a reboot for example, run
`sudo varlatch upgrade` again: it finishes the upgrade or undoes it, before
anything else.

## Go back

> **Being built.** `--rollback` comes with 0.50.0. Its details may still
> change.

```sh
sudo varlatch upgrade --rollback
```

It returns to the release the last upgrade came from, with the binaries
that upgrade kept:

- **When that release can open the database as it is,** and the upgrade
  declared itself safe for it, the binaries go back and the database stays.
  Every change made since the upgrade is kept.
- **Otherwise it restores the snapshot** taken before the upgrade. Every
  change made since is lost. The command lists those changes first, and
  the revocations among them, which would be undone: a credential revoked
  since then works again. It asks, or needs `--accept-data-loss` without a
  terminal. The database it replaces is kept 30 days.

Without a terminal, `--yes` is needed too. You can go back to 0.50.0-rc.3
or later. To an earlier prerelease the command refuses, and prints the
steps to take by hand; after the restore it names, give the database back
to the service with
`sudo chown varlatch:varlatch /var/lib/varlatch/varlatch.db`.

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
