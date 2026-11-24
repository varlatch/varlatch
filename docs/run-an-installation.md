# Run an installation

> **Prerelease.** This page is for Varlatch 0.50, which is not released yet.
> The current release, 0.23.0, runs on Docker Compose:
> [its version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/run-an-installation.md).

Varlatch is self-hosted: one person on your team runs an installation,
once, and everyone else signs in to it. Skip this page if someone already
runs one for you: [Join a team](join-a-team.md).

An installation is one program, `varlatchd`, with its own database. It
needs no Docker, no database server and no other service.

## What you need

- **A Linux host** with systemd, on amd64 or arm64, where you are root
  (`sudo`).
- **A way for people to reach it:** a domain name that points at the host,
  or your own reverse proxy. The choice is [below](#choose-the-address).

[Host requirements](self-hosting/requirements.md) lists memory, disk, ports
and outbound connections. To try Varlatch first, your own Linux machine is
enough: [Try it on your own machine](#try-it-on-your-own-machine). To run
it in a container, for example on Coolify, see
[The container image](#the-container-image).

An installation on 0.23.0 or earlier is moved, not installed again:
[Migrating to 0.50](operations/migrate-to-0.50.md).

## Install

On the host:

```sh
V=0.50.0  # the release to run
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sudo sh install.sh --server
```

`install.sh` downloads `varlatch`, `varlatchd` and the systemd unit, and
checks them against the release's `SHA256SUMS`. The downloaded `varlatch`
then checks that the release workflow signed `SHA256SUMS` for this version.
When a check fails, nothing is installed. To check the signature with
cosign before you run anything, follow
[Verifying a release](operations/verify-release.md).

It puts both binaries in `/usr/local/bin`, then starts `varlatch setup`,
which asks a few questions.

## Choose the address

Setup first asks how people will reach Varlatch:

| Choice | Address | You need |
|---|---|---|
| **public** | `https://vault.example.com`, with a certificate that `varlatchd` obtains from Let's Encrypt and renews | the name resolving to this host in public DNS, and ports 80 and 443 reachable from the internet |
| **proxy** | whatever your reverse proxy serves; also for a LAN-only or tailnet-only address | a proxy that forwards to `127.0.0.1:8686` |
| **localhost** | `http://localhost:8686`, on this machine only | nothing |
| **tailnet** | whatever your own proxy serves; `varlatchd` also joins your tailnet | a Tailscale auth key, and what [Tailscale](self-hosting/configuration.md#tailscale) says about it |

Choose carefully: the address is where passkeys are registered, so changing
it later means everyone registers their passkey again.

## What setup does

1. It creates the `varlatch` system user, and measures the disk that will
   hold the data.
2. It makes the two keys an installation needs, readable by root only: the
   Root KEK, which protects every stored value, and the backup key, which
   encrypts backups.
3. It writes `/etc/varlatch/varlatchd.conf` and starts the `varlatchd`
   service.
4. It shows a one-time link. Open it and create the first administrator's
   passkey. Setup waits until you have.
5. It shows both keys once, and asks you to paste them back. Keep copies
   off this host, apart from each other. Without both, no backup can be
   restored. Do not skip this.
6. It makes the first backup, verifies it, and runs `varlatch doctor`, a
   read-only health check you can run at any time.

If setup stops halfway, run it again: `sudo varlatch setup` continues where
it stopped, and never replaces a key it made. It exits 75 when it waits for
you, for the passkey or for the keys.

### Without a terminal

Every question has a flag. This sets up an installation behind your own
proxy, and stops for the passkey:

```sh
sudo varlatch setup --ingress proxy --public-url https://vault.example.com \
  --backups host --admin-wait 0s --admin-link-out /root/admin-link \
  --root-kek-out /root/root-kek --backup-key-out /root/backup-key
```

It exits 75 twice, each time waiting for you:

1. Open the link in `/root/admin-link` and create the passkey. Run the same
   command again.
2. It wrote the two keys to the files you named. Store them off this host,
   apart from each other, and delete those files. Only then run the same
   command a third time, with `--attest` added: your statement that the
   copies are safe. Setup records it, and cannot check it.

On a disk whose writes are slow, setup stops unless you add
`--accept-slow-disk`.

## Try it on your own machine

To try Varlatch before you choose a server, run the installation on your
own Linux machine and choose **localhost**. Browsers allow passkeys on
`http://localhost`, so you need no domain, no certificate and no proxy.

`varlatchd` then listens on `127.0.0.1` only: nobody else on your network
reaches it, and nobody but you can join.
[What Varlatch puts on your machine](reference/uninstall.md#what-varlatch-puts-on-your-machine)
lists everything setup writes, and how to remove it.

Every passkey is registered for the address the installation was set up
with. To move on to a real server later, the simplest way is a new
installation there. You can also keep this one and
[move it](operations/move-installation.md) to a public address, with
`--ingress public` or `--ingress external`: everyone then registers their
passkey again.

## The container image

`ghcr.io/varlatch/varlatchd` is the same server in a container, from 0.50.0.
There is no guided setup for it yet: you place the two keys and the
configuration file yourself, then bootstrap the first administrator with a
command. [A fresh install by hand](../infra/coolify/README.md#a-fresh-install-by-hand)
has every step, for Coolify and for plain Docker.

## Next steps

- **Back up off this host:** [Backup and recovery](operations/backup.md).
  A new installation backs itself up every day, but only to its own disk
  until you give it a bucket.
- **Set up your first project:** [Set up a project](set-up-a-project.md).
- **Run it day to day:** [Install and operate](self-hosting.md), and
  [Upgrading](operations/upgrade.md).
- **Every setting:** [Configuration](self-hosting/configuration.md).
