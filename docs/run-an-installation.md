# Run an installation

Varlatch is self-hosted: one person on your team runs an installation,
once, and everyone else signs in to it. Skip this page if someone already
runs one for you: [Join a team](join-a-team.md).

## What you need

A Linux host, amd64 or arm64, with Docker and Docker Compose 2.24 or
newer, and a way for people to reach it: a domain name pointing at the
host, a Tailscale network, or your own reverse proxy (the choice is
[below](#choose-the-address)). [Host requirements](self-hosting/requirements.md)
lists memory, disk, and ports.

To try Varlatch first, your own Linux machine with Docker is enough:
[Try it on your own machine](#try-it-on-your-own-machine).

## Install

On the host, download the CLI and the deployment bundle of the same
release, check them, install the CLI root-owned, and unpack the bundle
where the installation will live:

```sh
V=0.21.0  # the release to run
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/varlatch-cli-$V.cjs
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/varlatch-compose-$V.tar.gz
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
sudo install -m 755 varlatch-cli-$V.cjs /usr/local/bin/varlatch
tar -xzf varlatch-compose-$V.tar.gz
cd varlatch-$V
varlatch setup
```

Releases after 0.15.0 also sign `SHA256SUMS`: check that signature
first, as [Verifying a release](operations/verify-release.md) describes.
The CLI needs Node.js
([Node.js version](reference/install-the-cli.md#nodejs-version)), and
[Install the operator CLI](operations/backup.md#install-the-operator-cli)
explains why the host keeps its own root-owned copy.

Run `varlatch setup` as a user who can use Docker.

## Choose the address

`varlatch setup` first asks how people will reach Varlatch:

| Choice | Address | You need |
|---|---|---|
| **public** | `https://vault.example.com`, with a certificate a bundled Caddy obtains | the name resolving to this host in public DNS, and ports 80 and 443 reachable from the internet |
| **tailnet** | `https://<machine>.<tailnet>.ts.net`, for members of your tailnet only | a Tailscale auth key, and MagicDNS and HTTPS certificates enabled in the Tailscale admin console |
| **external** | whatever your reverse proxy serves; also for a LAN-only installation, or `http://localhost:8787` to try Varlatch on your own machine | a proxy forwarding to `127.0.0.1:8787`, WebSocket upgrades included; nothing for `http://localhost:8787` |

Choose carefully: the address is where passkeys are registered, so changing
it later means everyone registers their passkey again.

## What setup does

Setup also asks whether the installation should serve the CLI, so people
install it with one line from your address. That trusts the installation
to run code on their machines, so it is off unless you say yes:
[Serving the CLI](self-hosting/configuration.md#serving-the-cli).

Setup does the rest, and tells you what it is doing:

1. It generates every key and password the installation needs, as files in
   `./secrets`, and starts the services.
2. It prints a one-time link. Open it and create the first administrator's
   passkey. Setup waits until you have.
3. It walks you through keeping the two recovery keys off this host: the
   Root KEK, which every stored value depends on, and the backup key. Without
   a copy of the Root KEK, a backup cannot be restored. Do not skip this.
4. It finishes with `varlatch doctor`, a read-only health check you can run
   on the host at any time.

If setup stops halfway, for a failed download, a reboot, or a cancelled
passkey prompt, run it again: it continues where it stopped and never
replaces a key it already made.

## Try it on your own machine

To try Varlatch before you choose a server, run the installation on your
own Linux machine, with Docker, and reach it at `http://localhost:8787`.
Browsers allow passkeys on `http://localhost`, so you need no domain, no
certificate, and no proxy. In `varlatch setup`, choose **external**, and
enter `http://localhost:8787` as the address.

Every port stays on `127.0.0.1`: nobody else on your network reaches it,
and nobody but you can join. Setup writes only inside the directory you
unpacked; [What Varlatch puts on your machine](reference/uninstall.md#what-varlatch-puts-on-your-machine)
lists everything, and how to remove it.

An installation keeps the address it was set up with, and every passkey is
registered for that address. To move on to a real server later, set up a
new installation there, rather than moving this one.

## Next steps

- **Schedule backups:** [Backup and recovery](operations/backup.md) covers
  where they go and how to test a restore.
- **Set up your first project:** [Set up a project](set-up-a-project.md).
- **Upgrades and every setup option,** including running on Coolify: the
  [deployment guide](../infra/compose/README.md), and
  [Configuration](self-hosting/configuration.md).
