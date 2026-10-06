# Host requirements

This page lists what a host needs to run a Varlatch installation with the
canonical Docker Compose deployment, the one `varlatch setup` installs from
a release bundle. [Getting started](../getting-started.md#run-an-installation)
walks you through the installation itself, and
[Configuration](configuration.md) lists every setting.

| | Minimum |
|---|---|
| Operating system | Linux, on amd64 or arm64 |
| Containers | Docker with the Docker Compose plugin (`docker compose`), Compose 2.24 or newer |
| On the host | Node.js 22 or newer, for the operator CLI |
| Memory | 2 GiB |
| Processor | 2 CPU cores |
| Disk | 20 GB free for Docker's data and the installation's directory |
| Network | depends on how people reach Varlatch: [Network](#network) |

The memory, processor, and disk figures are recommendations with headroom.
[Sizing](#sizing) shows what an installation actually used, and how it was
measured.

## Operating system and architecture

Run Varlatch on Linux, on amd64 or arm64. From 0.10.0 on, the release
images are published for linux/amd64 and linux/arm64, and the Convex backend
image the release pins exists for those two platforms only. No other
architecture can run an installation.

Run the images for the host's own architecture, not under emulation. When
the release checks run the arm64 images on an amd64 machine, they still run
PostgreSQL and the Convex backend natively, because Convex's function time
limits do not hold under emulation on a small host.

## Software

- **Docker with the Docker Compose plugin, Compose 2.24 or newer.** Every
  host command (`varlatch setup`, `doctor`, `upgrade`, and `admin backup`)
  drives `docker compose`. The Tailscale overlay needs 2.24, because it uses
  `!reset` to drop varlatchd's own port mapping, and the same minimum holds
  for every ingress. `varlatch setup` stops before it changes anything when
  Compose is older, and `varlatch doctor` reports the version. Releases are
  tested with Docker 29 and Compose 5.
- **Node.js 22 or newer.** The operator CLI is a single file that needs
  only Node.js: [Get the CLI](../getting-started.md#get-the-cli).
- **systemd,** only if you use the reference backup timer in
  [`infra/host-backup`](../../infra/host-backup/README.md).

You do not install PostgreSQL, Convex, Caddy, or Tailscale yourself: each
runs in a container the Compose files define.

Apart from the Compose version, `varlatch setup` does not check free
ports, memory, or disk before it starts. When something is missing, the Docker or Compose command
it runs fails, and setup stops with that error. Fix the cause and run
setup again: it continues where it stopped.

## Access on the host

Run `varlatch setup` and the other host commands as a user who can use
Docker. Access to Docker is root-equivalent on the host, and anyone who can
open a shell in the installation's containers is an Infrastructure Operator
for it: the compose guide's
[break-glass section](../../infra/compose/README.md#break-glass-recovery)
says what that means.

File permissions matter, because the containers run as users other than
yours:

- Unpack the release bundle with the usual umask (022). The containers must
  read `postgres-init/` and `convex-supervisor.cjs`. A blanket `umask 077`
  while you prepare the directory makes every container fail, as
  [the backup runbook](../operations/backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore)
  describes.
- Secret files must be readable by the containers' users. Setup writes the
  ones containers read with mode 0644, inside a `secrets/` directory with
  mode 0700. varlatchd runs as a user of its own and cannot read a 0600
  file that you own.
  [Keys and passwords](configuration.md#keys-and-passwords) has the
  details.
- On a host where other people have a shell, mount `/proc` with
  `hidepid=2`. The Convex backend image passes its instance secret to the
  backend process as a command-line argument, which every user on the host
  can otherwise read in `/proc/<pid>/cmdline`.

## Network

### The address

Choose how people reach Varlatch before you run setup:

| Ingress | Address | Inbound to the host | You also need |
|---|---|---|---|
| **public** | `https://vault.example.com` | TCP 80 and 443 from the internet | a DNS name that resolves to this host in public DNS |
| **tailnet** | `https://<machine>.<tailnet>.ts.net` | none | a Tailscale auth key, MagicDNS and HTTPS certificates enabled in the Tailscale admin console, and Compose 2.24 or newer |
| **external** | whatever your reverse proxy serves | whatever your proxy needs | a proxy that forwards to `127.0.0.1:8787`, WebSocket upgrades for `/convex/` included |

Whichever you choose, the address must be:

- **An origin of its own:** `https://` and a host name, with no path.
  Varlatch cannot be served under a path such as
  `https://example.com/vault`.
- **HTTPS.** Browsers only allow passkeys on HTTPS. `http://localhost` works
  for local testing only.
- **Final.** Passkeys are registered for this address. Changing it later
  means everyone registers their passkey again, so setup refuses a different
  address on a rerun.

For the public ingress, the address must be a DNS name, not an IP address
or a `ts.net` name, and carry no port. Let's Encrypt validates the
certificate over ports 80 and 443. A private domain validated over DNS is
not built in: use the external ingress with your proxy's own certificate
automation.

For the tailnet ingress, the certificate covers only the machine's full name
and is published in Certificate Transparency logs, so keep the machine name
non-sensitive. The Tailscale sidecar runs in userspace mode: the host needs
no TUN device.

### Host ports

| Host port | Service | When |
|---|---|---|
| `127.0.0.1:8787` | `varlatch-web`: the dashboard, which also serves `/v1` and `/convex` | always; `varlatch setup --port` changes it |
| 80/tcp, 443/tcp, and 443/udp on all interfaces | `caddy` | public ingress |
| a free loopback port Docker picks | `varlatchd` and `convex-backend` | installations set up by `varlatch setup` |
| `127.0.0.1:8686` and `127.0.0.1:3210` | `varlatchd` and `convex-backend` | installations configured by hand, with the defaults |

Each fixed port must be free on the host, or the stack does not start.
PostgreSQL publishes no port at all. varlatchd's tailnet listener (port
8687) is reachable only over Tailscale, never through a host port.

Do not route a public domain at varlatchd's or Convex's port: passkey
sign-in works only at the public URL, which the dashboard serves.
[Host ports](configuration.md#host-ports) lists the settings.

### Outbound connections

The host connects out to:

- **ghcr.io and Docker Hub,** to pull images when you install and upgrade.
  Varlatch's images and the Convex backend come from ghcr.io; PostgreSQL,
  Caddy, and Tailscale come from Docker Hub.
- **GitHub,** when `varlatch upgrade` or `varlatch self-update` reads a
  release. `varlatch upgrade --release-dir <dir>` reads one from a local
  directory instead.
- **Let's Encrypt,** with the public ingress, to obtain and renew the
  certificate.
- **Tailscale,** with the tailnet ingress or the Tailscale overlay, so the
  node can join your tailnet.
- **Your backup destination,** when you configure an S3-compatible one.
- **The platforms of Sync Targets** (GitHub Actions, Coolify, Convex), when
  someone configures one. `VARLATCH_SYNC=off` turns delivery off:
  [Sync Targets](configuration.md#sync-targets).

The Compose file turns off the Convex backend's usage beacon.

## Sizing

### How these figures were measured

Memory and processor use were read from the containers' control groups on
2026-10-06, on a development installation that had been running for six
days: 2 organizations, 3 projects, 4 environments, and 18 identities. For
the five minutes around the readings, the dashboard received no requests
except its own health checks. The host was an Intel Core i9-9900T
(linux/amd64) with Docker 29.7.2. Only the four long-running services were
running: the Caddy and Tailscale containers of the ingress overlays are not
included.

### Memory

| Service | In use, without page cache | Total, with page cache | Peak, with page cache |
|---|---|---|---|
| `postgres` | 188 MiB (52 MiB plus 136 MiB of shared buffers) | 445 MiB | 3,860 MiB |
| `varlatchd` | 60 MiB | 115 MiB | 166 MiB |
| `convex-backend` | 72 MiB | 92 MiB | 181 MiB |
| `varlatch-web` | 2 MiB | 6 MiB | 25 MiB |
| **All four** | **322 MiB** | **658 MiB** | |

PostgreSQL's peak is almost all page cache: this installation had grown a
3.3 GiB Application Plane database under a release before 0.14.3
([Disk](#disk) explains why). The kernel reclaims page cache when other
processes need the memory.

A reading from a production installation on 2026-10-05, less than two
hours after its Convex backend restarted, was similar: 72 MiB for the
Convex backend, and 24 MiB plus 140 MiB of shared buffers for PostgreSQL,
without page cache.

The one-shot jobs were measured on a fresh development installation on
2026-10-06, sampling each container's memory ten times a second:

| Job | Peak |
|---|---|
| `convex-deploy`, deploying the Application Plane functions (every setup and upgrade) | 173 MiB |
| `varlatch admin backup create`: the host CLI | 125 MiB |
| the same backup: `varlatchd`, and the PostgreSQL dump | 83 MiB and 79 MiB, no more than they use idle |

That backup took 1.9 seconds for a small Secret Plane database; a large
audit history takes longer and more memory, as below.

**Recommended: at least 2 GiB.** That leaves room above the measured 658
MiB for the operating system, Docker, page cache, the ingress container,
and the one-shot jobs above, which run one at a time.

<!-- TODO(owner): before launch, run setup, a backup, and an upgrade on a
2 GiB host with each ingress, measuring Caddy and the Tailscale sidecar,
and confirm the recommendation. -->

For a large audit history, the
[capture measurements](../operations/backup.md#what-a-capture-costs-measured)
in the backup runbook ran PostgreSQL with 2 CPUs and 4 GB and varlatchd
with 1 CPU and 1 GB, up to ten million audit events, with no failed
requests.

### Processor

Over two idle minutes, the four services together used about a tenth of
one core: `convex-backend` 0.044, `postgres` 0.031, `varlatchd` 0.028, and
`varlatch-web` 0.004 of a core.

**Recommended: 2 cores.** The idle load is small, but a backup capture runs
the database dump while the installation keeps serving, and that costs CPU
and I/O. The capture measurements gave PostgreSQL 2 CPUs.

### Disk

The images of one release, as Docker 29.7.2 reports them for linux/amd64
with its containerd image store, which keeps both the download and the
unpacked image. Varlatch's own three images were built from the current
source:

| Image | Used by | On disk | Download |
|---|---|---|---|
| `postgres:17.6` | `postgres` | 636 MB | 161 MB |
| `varlatchd` | `varlatchd`, `varlatch-migrate` | 474 MB | 108 MB |
| `varlatch-web` | `varlatch-web` | 95 MB | 27 MB |
| Convex backend (pinned) | `convex-backend` | 800 MB | 207 MB |
| `varlatch-convex-deploy` | `convex-deploy` | 734 MB | 160 MB |
| `caddy:2.10.2` | public ingress | 85 MB | 23 MB |
| `tailscale/tailscale:v1.102.3` | tailnet ingress | 180 MB | 61 MB |

Without an ingress overlay that is about 2.7 GB on disk and 0.7 GB to
download; the overlays add 0.1 to 0.2 GB. Layers the images share are stored
once, so the real total is somewhat lower. Sizes change a little between
releases. `varlatch upgrade` does not remove the previous release's images,
so plan for two sets during an upgrade, until you remove the old ones.

The data grows over time:

- **The Secret Plane database** held 9.6 MiB on the measured installation.
  It grows with the audit history: about 0.9 GiB per million audit events
  in the backup runbook's measurements.
- **The Application Plane database** holds the dashboard's read models
  (Mirrors), which are small, and grows only when they change. Convex keeps
  each replaced version of a document for at least 14 days. Before 0.14.3,
  varlatchd stored every Mirror again once a minute even when nothing had
  changed, and the measured installation reached 3.3 GiB that way: an
  installation upgraded from an earlier release may hold several GiB of
  such versions.
- **Backup archives** hold only the Secret Plane database: about 76 MiB per
  million audit events. `backup create` writes them to `backups/` in the
  installation's directory, and the reference timer keeps the newest 7
  there.
- **Backup scratch space,** in the system's temporary directory unless you
  pass `--scratch-dir`, holds the dump and the decrypted copy that
  verification reads while a backup runs.

**Recommended: 20 GB free.** That covers two release sets, the databases,
and local backups, with room for the audit history to grow. Watch the free
space of Docker's data directory.
Where the data lives:

| Volume or directory | Holds |
|---|---|
| `postgres-data` | both databases: `varlatch` (the Secret Plane) and `convex_self_hosted` (the Application Plane) |
| `convex-data` | Convex's module bundles and file storage |
| `varlatch-state` | backup and restore state shared by the services, and the backup history |
| `caddy-data`, `caddy-config` | the certificate and the ACME account (public ingress) |
| `tailscale-state` | the node's identity and certificate (tailnet ingress) |
| `secrets/`, `recovery/`, `backups/` | key files, the Root KEK escrow file, and local archives, in the installation's directory |

Keep every volume through restarts and upgrades. Docker names them after
the Compose project, `varlatch`: for example `varlatch_postgres-data`.
