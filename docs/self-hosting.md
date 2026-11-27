# Install Varlatch

Varlatch is a single program (`varlatchd`) with its own SQLite database,
embedded dashboard, HTTPS certificates, and encrypted backups. It needs no
Docker, no database server, and no other services.

> Someone on your team already runs a server? Skip this page and go to
> [Join a team](join-a-team.md). Prefer containers? Use
> [Docker and Coolify](self-hosting/docker-and-coolify.md).

## Install

On a Linux server (amd64 or arm64, with systemd and `sudo`):

```sh
V=0.50.2  # latest release
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sudo sh install.sh --server
```

That downloads `varlatch`, `varlatchd`, and the systemd unit, verifies the
release's cryptographic signature and `SHA256SUMS`, installs both binaries to
`/usr/local/bin`, and launches the interactive `varlatch setup` wizard.

Want to inspect the signature with `cosign` before running `install.sh`? See
[Verifying a release](operations/verify-release.md).

## What you need

- **Linux (amd64 or arm64)** with systemd, `curl`, `sha256sum`, and `sudo`
  (1 GiB RAM, 1–2 CPU cores, 5 GB local disk; see
  [Host requirements](self-hosting/requirements.md)).
- **An address for people to reach it** (or none if you are trying it on
  `localhost` first):

| Mode | Address | What you need |
| --- | --- | --- |
| **public** | `https://vault.example.com` (automatic Let's Encrypt HTTPS) | DNS pointing to this host, plus TCP ports `80` and `443` open |
| **proxy** | Whatever your reverse proxy serves (also for LAN or tailnet-only dashboards) | A reverse proxy forwarding the root of the hostname to `127.0.0.1:8686` |
| **localhost** | `http://localhost:8686` (this machine only) | Nothing: great for trying Varlatch in 2 minutes |
| **tailnet** | Your proxy's address, plus `varlatchd` joins your tailnet | A tagged Tailscale auth key ([Tailscale setup](self-hosting/configuration.md#tailscale)) |

Choose your address carefully: passkeys are bound to the hostname, so changing
it later means everyone re-registers their passkey with
[`varlatch move`](operations/move-installation.md).

## What `varlatch setup` does

1. Creates the `varlatch` system user and benchmarks local disk write latency.
2. Generates the **Root KEK** (encrypts stored values) and **backup key**
   (encrypts backups), readable by `root` only.
3. Writes `/etc/varlatch/varlatchd.conf` and starts `varlatchd.service`.
4. Prints a one-time link to register the first administrator's passkey, and
   waits until you complete it.
5. Displays both recovery keys **once** and asks you to confirm you saved them
   off this host (apart from each other). Without both keys, no backup can be
   restored.
6. Runs the first encrypted backup, verifies it, and runs `varlatch doctor`.

If setup is interrupted, run `sudo varlatch setup` again: it picks up where it
left off and never overwrites keys it already created.

<details>
<summary>Non-interactive / headless setup (flags for scripts)</summary>

Every prompt has a flag. For example, to install behind your own reverse proxy:

```sh
sudo varlatch setup --ingress proxy --public-url https://vault.example.com \
  --backups host --admin-wait 0s --admin-link-out /root/admin-link \
  --root-kek-out /root/root-kek --backup-key-out /root/backup-key
```

It exits `75` twice while waiting for human steps:

1. Open the link written to `/root/admin-link` and register your passkey, then
   run the exact same command again.
2. Copy the keys written to `/root/root-kek` and `/root/backup-key` off this
   host (apart from each other), delete those temporary files, and run the
   command a third time with `--attest` added.

On a disk whose 99th-percentile write latency exceeds 10 ms, pass
`--accept-slow-disk` to continue.

</details>

## Try it on your own machine

To try Varlatch before provisioning a server, run the same three install
commands on your own Linux machine and pick **localhost**. Browsers allow
passkeys on `http://localhost`, so you need no domain, certificate, or proxy.

`varlatchd` listens only on `127.0.0.1:8686`. When you're done evaluating,
[Removing Varlatch](reference/uninstall.md#what-varlatch-puts-on-your-machine)
lists the exact cleanup commands, or you can
[move it](operations/move-installation.md) to a real domain later.

## Next steps

1. **Back up off this host:** [Backup and recovery](operations/backup.md) or the
   step-by-step [Backblaze B2 guide](operations/backup-b2.md). Local daily
   backups run automatically, but off-host storage protects you if you lose the
   server.
2. **Connect your first repo:** [Connect a project](set-up-a-project.md) (or
   [Set up with a coding agent](set-up-with-an-agent.md)).
3. **Day-2 operations:** [Operate and recover](self-hosting/operate.md)
   (`varlatch doctor`, key custody, break-glass recovery),
   [Upgrading](operations/upgrade.md), and
   [Configuration](self-hosting/configuration.md).

> **Upgrading from 0.23.x (Docker Compose)?** Do not run a fresh install: follow
> [Migrating from 0.23.x to 0.50](operations/migrate-to-0.50.md). Legacy Compose
> docs are in [Docker Compose (0.23.x legacy)](../infra/compose/README.md).

<details>
<summary>Moved sections (links from older pages)</summary>

- <a id="first-install"></a>First install: [Install](#install)
- <a id="with-varlatch-setup-recommended"></a>With `varlatch setup`: [Install](#install)
- <a id="existing-installations-varlatch-adopt"></a>`varlatch adopt`: [Docker Compose](../infra/compose/README.md#existing-installations-varlatch-adopt)
- <a id="by-hand"></a>By hand: [Docker Compose](../infra/compose/README.md#by-hand)
- <a id="where-to-keep-the-backup"></a>Where to keep the backup: [Operate and recover](self-hosting/operate.md#the-root-kek-is-your-responsibility)
- <a id="the-root-kek-is-your-responsibility"></a>The Root KEK is your responsibility: [Operate and recover](self-hosting/operate.md#the-root-kek-is-your-responsibility)
- <a id="passphrase-wrapped-escrow-recommended"></a>Passphrase-wrapped escrow: [Operate and recover](self-hosting/operate.md#a-passphrase-protected-copy)
- <a id="shamir-secret-sharing-multi-custodian"></a>Shamir secret sharing: [Operate and recover](self-hosting/operate.md#shares-for-several-people)
- <a id="break-glass-recovery"></a>Break-glass recovery: [Operate and recover](self-hosting/operate.md#break-glass-recovery)
- <a id="backup"></a>Backup: [Backup and recovery](operations/backup.md)
- <a id="upgrade-backup-gated-forward-only"></a>Upgrade: [Upgrading](operations/upgrade.md)
- <a id="outbound-destinations-after-upgrading-to-0220"></a>Outbound destinations after upgrading to 0.22.0: [Docker Compose](../infra/compose/README.md#outbound-destinations-after-upgrading-to-0220)
- <a id="newer-releases-in-the-dashboard"></a>Newer releases in the dashboard: [Upgrading](operations/upgrade.md#newer-releases-in-the-dashboard)
- <a id="health-check-read-only"></a>Health check: [Operate and recover](self-hosting/operate.md#health-check)
- <a id="health-check"></a>Health check: [Operate and recover](self-hosting/operate.md#health-check)
- <a id="optional-tailscale-integration"></a>Tailscale: [Configuration](self-hosting/configuration.md#tailscale)
- <a id="september-2026-upgrade-compatibility"></a>September 2026 upgrade compatibility: [Docker Compose](../infra/compose/README.md#september-2026-upgrade-compatibility)
- <a id="client-addresses-behind-proxies"></a>Client addresses behind proxies: [`trusted_proxies`](self-hosting/configuration.md#trusted_proxies)

</details>
