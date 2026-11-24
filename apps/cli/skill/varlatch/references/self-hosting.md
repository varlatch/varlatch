# Installing and operating a Varlatch server

These commands run on the server's host, with the host's access, most of
them as root. Installing, upgrading and migrating change a production
system: give the human the command and wait, unless they asked you to run
it.

## Installing

```text
sudo varlatch setup
```

It sets up this host in one run: `varlatchd` as a systemd service, its
configuration (`/etc/varlatch/varlatchd.conf`), the keys, the first
administrator's passkey, the first backup, and a health check. It asks on a
terminal, shows the keys once, and is resumable. The keys and the
administrator's link are the human's: never ask to see them.

## Health

```sh
varlatch --assisted doctor --json
```

It reads the installation's health on this host and changes nothing. Some
checks need root.

## Upgrading

```text
sudo varlatch upgrade --check
sudo varlatch upgrade
```

`upgrade` takes an encrypted snapshot before it stops the service or changes
the database and the binaries, keeps the new release only when its health
checks pass, and otherwise goes back. When it cannot go back it says what is
left: give the human that message. Until an interrupted upgrade is over the
server does not start or answers 503: running `sudo varlatch upgrade` again
finishes or undoes it. Never remove or edit `/etc/varlatch/upgrade.json`.

`sudo varlatch upgrade --rollback` returns to the release before. It can lose
every change made since the upgrade, and lists them first: it is the human's
to decide.

## Backups

```text
sudo varlatch admin backup run
sudo varlatch admin backup status
sudo varlatch admin backup test-bucket
```

Backups are encrypted and verified. Restoring is a human decision: what
changed since the archive is gone, and the human keeps clients away and
checks the installation first. A restored installation serves but is held:
its background work waits until the human, having put right what changed,
runs:

```text
sudo varlatch admin restore status
sudo varlatch admin restore resume
```

## In a container

An installation that runs the container image (Docker, Coolify) has no
`varlatch setup` or `varlatch upgrade`: the image's digest is the version,
and changing it is a deployment. The other commands run in the container:

```text
docker exec <container> varlatch admin backup status
docker exec <container> varlatch --assisted doctor --json
```

## From a Compose installation

`varlatch migrate` moves a Compose installation of the last TypeScript
release to this one. Beside the installation's own options, it takes a dry
run first, and has a way back:

```text
sudo varlatch migrate --dry-run
sudo varlatch migrate --rollback
```

It is the human's to start, with the migration guide
(https://docs.varlatch.com). Commands that take `--dir <compose-directory>`
are the TypeScript CLI's, for such an installation.
