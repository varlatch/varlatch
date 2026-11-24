# Host requirements

> **Prerelease.** This page is for Varlatch 0.50, which is not released yet.
> The current release, 0.23.0, runs on Docker Compose:
> [its version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/self-hosting/requirements.md).

This page lists what a host needs to run a Varlatch installation.
[Run an installation](../run-an-installation.md) walks you through the
installation itself, and [Configuration](configuration.md) lists every
setting.

| | Minimum |
|---|---|
| Operating system | Linux, on amd64 or arm64 |
| Service manager | systemd, or a container runtime for the image |
| Memory | 1 GiB |
| Processor | 1 CPU core; 2 recommended |
| Disk | 5 GB free, on a local disk |
| Network | depends on how people reach Varlatch: [Network](#network) |

The memory, processor, and disk figures are recommendations with headroom.
[Sizing](#sizing) shows what was measured.

## Operating system and architecture

Run Varlatch on Linux, on amd64 or arm64. `varlatchd` and `varlatch` are
single programs with no dependencies: no Docker, no database server, no
Node.js. The container image is published for the same two architectures.

## Software

- **systemd,** for an installation from `install.sh --server`. The unit uses
  credentials (`LoadCredential`), as in the systemd of every current
  distribution.
- **`curl`, and `sha256sum`,** which `install.sh` uses.
- **Docker, or another container runtime,** only for the container image.

## Access on the host

`varlatch setup` and the other host commands run as root. Anyone who is root
on the host is an Infrastructure Operator of the installation:
[Break-glass recovery](../self-hosting.md#break-glass-recovery) says what
that means.

The service itself runs as the `varlatch` user, with no privilege but
binding ports 80 and 443. It can write only to its data directory. Files you
make for it, such as a bucket's key file, need `root:varlatch` and mode
0640. Setup makes every other file itself.

If the credentials that deploy or roll back this installation come from
Varlatch itself, keep a break-glass credential outside it before anyone
relies on the [incident freeze](../reference/incident-freeze.md): a freeze
stops every deploy whose credentials Varlatch serves, a rollback of
Varlatch included. Store it where Varlatch does not serve or push it, scope
it as narrowly as your platform allows, and rotate it after each use.
`varlatch admin unfreeze` lifts a freeze from the host.

## Network

### The address

Choose how people reach Varlatch before you run setup:

| Ingress | Address | Inbound to the host | You also need |
|---|---|---|---|
| **public** | `https://vault.example.com` | TCP 80 and 443 from the internet | a DNS name that resolves to this host in public DNS |
| **proxy** | whatever your reverse proxy serves | whatever your proxy needs | a proxy that forwards to `127.0.0.1:8686` |
| **localhost** | `http://localhost:8686` | none | nothing |
| **tailnet** | whatever your own proxy serves | whatever your proxy needs | a Tailscale auth key ([Tailscale](configuration.md#tailscale)) |

Whichever you choose, the address must be:

- **An origin of its own:** `https://` and a host name, with no path.
  Varlatch cannot be served under a path such as
  `https://example.com/vault`.
- **HTTPS.** Browsers only allow passkeys on HTTPS. `http://localhost` works
  on the machine itself only.
- **Final.** Passkeys are registered for this address. Changing it later
  means everyone registers their passkey again.

For the public ingress, the address must be a DNS name, not an IP address.
Let's Encrypt validates the certificate over ports 80 and 443. A private
domain validated over DNS is not built in: use the proxy ingress with your
proxy's own certificate automation.

### Host ports

| Port | When |
|---|---|
| `127.0.0.1:8686` | always ([`listen`](configuration.md#listen)) |
| 80/tcp and 443/tcp on all interfaces | public ingress |
| the tailnet listener's port, 8687 by default, on the node's tailnet addresses only | with [`tailnet`](configuration.md#tailnet) |
| the tailnet browser endpoint's port, on the same addresses | with [`tailnet_https_port`](configuration.md#tailnet_https_port) |

Each port must be free on the host, or the service does not start.

### Outbound connections

The host connects out to:

- **GitHub,** when you install, and when `varlatch upgrade` or `varlatch
  self-update` reads a release; and, with
  [`serve_cli`](configuration.md#serve_cli), when `varlatchd` downloads the
  CLI. Nothing looks for new releases by itself.
- **Sigstore's public servers** (`tuf-repo-cdn.sigstore.dev`), for the keys
  a release's signature is checked with.
- **Let's Encrypt,** with the public ingress, to obtain and renew the
  certificate.
- **Tailscale,** or your own control server, with
  [`tailnet`](configuration.md#tailscale).
- **Your backup destination,** when you configure one.
- **The platforms of Sync Targets** (GitHub Actions, Coolify, Convex), when
  someone configures one. [`sync = off`](configuration.md#sync) turns
  delivery off.
- **What Organizations configure:** audit webhook receivers, Coolify and
  Convex instances, GitHub, and OIDC issuers. `varlatchd` sends these
  requests to public addresses over https only, unless you allow a private
  destination with [`outbound_allow`](configuration.md#outbound_allow).
  [Outbound policy](../reference/outbound-policy.md) has the details.

## Sizing

### How these figures were measured

Memory, disk and file sizes were read on 2026-11-24 from new installations
of 0.50.0-rc.1 and rc.2 on linux/amd64, with one administrator and no
Organizations, shortly after they started. Plan for more: the
recommendations above leave headroom. Measurements of larger installations
will follow.

### Memory

An idle `varlatchd` used 50 to 65 MiB. **Recommended: at least 1 GiB** for
the host, which leaves room for the operating system and for work in
parallel.

### Processor

**Recommended: 2 cores.** One is enough for a small team. A backup seals the
whole database while the installation keeps serving, and that costs CPU and
I/O.

### Sharing the host with other workloads

The figures above are for a host that runs Varlatch alone. On a host shared
with other containers, they all compete for the same cores. When the cores
are busy, the kernel shares CPU time between containers by their CPU
weight, and every container has the same weight unless it sets one.

This matters most on a small host that also runs Coolify. Coolify's
scheduler does its periodic work at the start of every minute.
- **What was measured:** a 2-core host on 2026-11-19, with a Varlatch
  server under a benchmark load of 50 requests a second, first with extra
  writes (1.7 times the profile's), then without.
- **Coolify:** over the first ten seconds of each minute (:00 to :09), its
  container used on average 0.65 to 0.70 of a core, and the host's two
  cores were 88 to 94 % busy from :01 to :06.
- **The Varlatch server** got less CPU in those seconds, and its requests
  waited. Its p95 latency was up to 858 ms in them (132 ms without the
  extra writes), against 22 to 28 ms in the rest of the minute.

To give Varlatch priority, give it a higher CPU weight than the other
workloads:

- **Installed with `install.sh`,** in a drop-in for the service. 100 is what
  a service that sets nothing has:

  ```sh
  sudo systemctl edit varlatchd     # add the two lines below
  sudo systemctl restart varlatchd
  ```

  ```ini
  [Service]
  CPUWeight=300
  ```

- **In a container,** with `cpu_shares`, in the Compose file or in Coolify's
  setting ([Deploying on Coolify](../../infra/coolify/README.md#sharing-the-host)).

**Measured once (2026-11-19).** The same host and load, with the extra
writes. The Varlatch server ran in one container that Coolify deployed, so
its CPU weight came from Coolify's setting. The server's p95 latency at the 50 requests a second:

| CPU weight | Runs | :00 to :09 | :10 to :59 |
|---|---|---|---|
| 39 (Coolify's default on that host) | 2 | 1,329 and 1,549 ms | 33 and 31 ms |
| 157 (`cpu_shares` 4096 on that host) | 1 | 55 ms | 25 ms |

- Coolify's container used the same CPU in those seconds in all three runs.
- In the runs at weight 39, some requests could not be sent on time, so
  their figures are the requests' own response times. The run at 157 is
  measured from each request's scheduled start.
- The comparison is not fully controlled. In the two runs at 39, the
  server's Sync Target runs overlapped the first seconds of every minute;
  in the run at 157 they did not.

- **It changes nothing on an idle host.** The weight counts only while the
  cores are busy. It also favours Varlatch's own heavy work over the other
  containers, a backup capture for instance.
- **In a container, use 4096, not 1024 or 2048.** On cgroup v2, Docker
  converts `cpu_shares` to the kernel's CPU weight, where a container that
  sets nothing gets 100. The conversion depends on the container runtime:

  | `cpu_shares` | Weight, older runtimes (linear) | Weight, runc 1.5 |
  |---|---|---|
  | 1024 | 39 | 100 |
  | 2048 | 79 | 174 |
  | 4096 | 157 | 303 |

  Only 4096 is above 100 under both. 2048 would lower Varlatch's priority
  on an older runtime. On such a runtime, Coolify's default of 1024 for
  the containers it deploys gives them weight 39.
- **Check the weight a container gets.** Read it from the host, which works
  whatever the image contains (the path is for Docker's systemd cgroup driver, the
  usual one):

  ```sh
  cat /sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' <the varlatchd container>).scope/cpu.weight
  ```
- **cgroup v2 only.** Current distributions use cgroup v2. On a cgroup v1
  host there is no `cpu.weight`, and `cpu_shares` applies as `cpu.shares`
  (1024 for a container that sets nothing).

### Disk

Every write waits until the disk has it. A slow disk makes every change
slow, so put the data directory on a local disk. Network block storage is
not supported. Setup measures the disk for five seconds: it wants the
99th-percentile write latency under 10 ms, and stops on a slower disk unless
you accept it. `varlatch doctor` measures it again.

| What | Size |
|---|---|
| `varlatchd` | 64 MB |
| `varlatch` | 27 MB |
| the container image | 133 MB |
| a new installation's database | under 1 MiB |

The database grows with the audit history. Beside it, plan for the local
archives (7 by default), a working copy during a backup, and during an
upgrade a second copy and a snapshot. Each upgrade keeps that snapshot (30
days) and the previous release's binaries in `/usr/local/lib/varlatch`, which
may be another disk; going back to a snapshot also keeps the database it
replaced, 30 days. A large import or read also uses
temporary files for as long as it runs: in the data directory in the
container image, in the service's own `/var/tmp` with systemd.
**Recommended: 5 GB free.**

Where the data lives:

| Directory | Holds |
|---|---|
| `/var/lib/varlatch` | the database, `backups/`, `upgrades/`, and, when used, `acme/` (the certificate), `tailnet/` (the node's identity) and `cli/` |
| `/etc/varlatch` | the configuration and the two keys |
| `/usr/local/lib/varlatch/releases` | the binaries of earlier releases |
| `/usr/local/lib/varlatch/snapshots` | the encrypted snapshots from before upgrades |

### Deleting an organization

Deleting an organization runs as one database transaction when its waiting
period ends: it erases every value version, ends every membership and
revokes everything the organization holds. Its time grows with the
organization's value versions. Figures measured for the TypeScript server
are in
[0.23.0's version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/self-hosting/requirements.md#deleting-an-organization).
