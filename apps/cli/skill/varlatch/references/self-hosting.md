# Installing and operating a Varlatch server

These commands run on the server's host, with the host's access. Installing
and upgrading change a production system: give the human the command and
wait, unless they asked you to run it.

## Installing

```text
varlatch setup
```

It creates an installation in the current directory in one run: HTTPS or
tailnet-only access, keys, the first passkey, recovery keys, and a health
check. It is resumable.

## Health

```sh
varlatch --assisted doctor --json
```

It reads the installation's health on this host and changes nothing.

## Upgrading

```text
varlatch upgrade --check
varlatch upgrade
```

`upgrade` takes a verified backup before it changes anything.

## Backups

```text
varlatch admin backup create
varlatch admin backup verify
varlatch admin backup status
```

Backups are encrypted and verified; restoring is a human decision.
