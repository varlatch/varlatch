# Host requirements

This page lists what a host needs to run a Varlatch installation.
[Install Varlatch](../self-hosting.md) walks through setup in three commands,
and [Configuration](configuration.md) lists every setting.

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
[Break-glass recovery](operate.md#break-glass-recovery) says what
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

The figures above assume a host dedicated to Varlatch. On a small (2-core) host
shared with other containers, especially **Coolify**, whose scheduler spikes CPU
during the first 10 seconds of every minute: give Varlatch higher CPU priority:

- **systemd (`install.sh`):** add a drop-in (`sudo systemctl edit varlatchd`)
  with:
  ```ini
  [Service]
  CPUWeight=300
  ```
  Then `sudo systemctl restart varlatchd`.
- **Docker / Coolify container:** set `cpu_shares` to **`4096`** (not `1024` or
  `2048`: on older cgroup v2 runtimes, `1024` maps to weight `39`, *below* the
  default `100`).

<details>
<summary>Measured Coolify latency benchmarks & cgroup v2 conversion details</summary>

- **What was measured (2026-11-19):** a 2-core host running a Varlatch server
  under 50 requests/second alongside Coolify.
- **Coolify's minute spike:** from `:00` to `:09` of each minute, Coolify's
  container used 0.65–0.70 cores and total CPU hit 88–94%.
- **Effect on Varlatch p95 latency** (with extra writes, 1.7× profile):

  | CPU weight | Runs | `:00` to `:09` | `:10` to `:59` |
  | --- | --- | --- | --- |
  | `39` (Coolify default `cpu_shares=1024`) | 2 | 1,329 ms / 1,549 ms | 33 ms / 31 ms |
  | `157` (`cpu_shares=4096`) | 1 | 55 ms | 25 ms |

  (Without extra writes on a separate systemd test, p95 during `:00–:09` was
  132 ms vs 22–28 ms in the rest of the minute. In the weight-39 runs, Sync
  Target runs also overlapped the minute boundary; in the weight-157 run they
  did not. In the weight-39 runs, some requests could not be sent on time, so
  their figures are the requests' own response times; the weight-157 run is
  measured from each request's scheduled start.)

- **Why `4096` on cgroup v2:** Docker maps `cpu_shares` to `cpu.weight`
  (default `100` for containers that set nothing):

  | `cpu_shares` | Weight (older runtimes, linear) | Weight (`runc` 1.5) |
  | --- | --- | --- |
  | `1024` | `39` | `100` |
  | `2048` | `79` | `174` |
  | `4096` | `157` | `303` |

  Only `4096` stays above `100` under both formulas. Check a container's actual
  weight from the host (Docker systemd cgroup driver):

  ```sh
  cat /sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' <varlatchd-container>).scope/cpu.weight
  ```

  Weight has no effect on an idle host. On legacy cgroup v1 hosts, `cpu_shares`
  applies directly as `cpu.shares` (default `1024`).

</details>

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
upgrade a second copy and a snapshot. Each upgrade keeps that snapshot and
the previous release's binaries in `/usr/local/lib/varlatch`, which may be
another disk; going back to a snapshot also keeps the database it replaced
([how long](../operations/upgrade.md#what-is-kept)). A large import or read
also uses temporary files for as long as it runs: in the data directory in
the container image, in the service's own `/var/tmp` with systemd.
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
