# Canonical Varlatch deployment (Docker Compose)

This directory is Varlatch's deployment contract. Coolify deployments
use this same Compose file through Coolify's Compose support: same topology,
different UI clicks.

**Current scope:** Secret Plane only (`postgres`, `varlatch-migrate`,
`varlatchd`). The Convex Application Plane, `varlatch-web`, and the optional
Tailscale profile are added as those components land.

## First install

Self-hosters should start from a release, not this checkout: download
`varlatch-compose-<version>.tar.gz` from the GitHub release (this directory
with digest-pinned images instead of source builds) and unpack it.

### With `varlatch setup` (recommended)

```sh
cd varlatch-<version>          # or infra/compose in a checkout
varlatch setup
```

It first asks how people will reach Varlatch (`--ingress`):

| Choice | Public URL | You need |
|---|---|---|
| **public**: a bundled Caddy obtains the HTTPS certificate itself | `https://vault.example.com` (`--public-url`) | the name resolving to this machine in public DNS; ports 80 and 443 reachable from the internet |
| **tailnet**: the Tailscale sidecar serves HTTPS, tailnet members only | `https://<machine>.<tailnet>.ts.net`, read from the node once it has joined | a Tailscale auth key (`--tailscale-auth-key-file`, used once) and, in the Tailscale admin console, MagicDNS and HTTPS certificates enabled; `--tailnet-machine` picks the machine name (default `varlatch`) |
| **external**: your own reverse proxy; also for LAN-only installations | whatever your proxy serves (`--public-url`) | a proxy forwarding to `127.0.0.1:8787` (`--port`), including WebSocket upgrades for `/convex/` |

The public URL is the passkey origin: it never changes on a rerun, and a
tailnet machine or tailnet renamed later is a domain change (every passkey
re-binds), not a setup rerun. Tailnet certificates cover only the machine's
full name and are published in Certificate Transparency logs, so keep machine
names non-sensitive; the Tailscale state volume holds the node's identity and
certificate, keep it with the other volumes. Reaching the dashboard over the
tailnet never satisfies a Tailnet Constraint; only the tailnet listener does.
A private custom domain (DNS-01) is not built in: use `external`
with your proxy's own certificate automation.

Everything else is automatic: it generates every secret as a file in
`./secrets` (mounted only into the services that need it, #28), writes a
managed `.env` with paths and derived origins (one public origin; Convex at
`<public URL>/convex`), starts the stack, deploys the Application Plane, and
prints a one-time link for the first administrator's passkey and waits
until that passkey exists, walks you through keeping the Root KEK and
backup key off this host, and finishes with `varlatch doctor`.

Recovery keys (step 6): the Root KEK can be escrowed as a
passphrase-protected file in `./recovery/` (safe to store anywhere; only the
passphrase must be kept separately), split into Shamir shares for several
people, or copied by you; the backup key is copied by you, apart from the
Root KEK copy. Setup then asks you to confirm the copies are off this host
and records that as a dated **attestation**. The installation cannot verify
copies elsewhere, and `varlatch doctor` says so and asks you to re-confirm
after 180 days. Non-interactively: `--escrow passphrase|shamir|copy`
(`--escrow-passphrase-file`, `--shares`, `--threshold`) and `--attest`;
without confirmation setup exits 4 (escrow pending) and a rerun resumes at
this step. Every step
checks real state first, so rerunning it after an interruption (a failed
pull, a reboot, a cancelled passkey prompt) continues where it stopped and
never regenerates a key. `--no-wait` prints the link and exits; `--port`
sets the dashboard's host port (default 8787).

Setup refuses to take over a hand-written `.env` (existing installations
move to managed configuration through `varlatch adopt`) and refuses a
different public URL on rerun: that re-binds every passkey and is its own
procedure. Keep copies of `secrets/varlatch-kek` and `secrets/backup-key`
off this host (setup's recovery-key step walks you through it).

### Existing installations: `varlatch adopt`

An installation configured by hand (below, or before `setup` existed) keeps
working; `varlatch doctor` lists it as not adopted (advisory). `varlatch
adopt` moves it to managed configuration without changing what works,
keeping a separate Convex origin, ports, and extra `.env` lines:

```sh
varlatch adopt           # the plan; changes nothing
varlatch adopt --apply   # every step, each verified with doctor before the next
```

It records the configuration in `varlatch-install.json`, moves secrets from
variables into files (current values, never printed), points Convex at
`varlatchd`'s fixed name, replaces `CONVEX_ADMIN_KEY` with the derived key
once that has worked, records custody (the same escrow step as `setup`,
same flags), and finally hands `.env` to `setup`, but only if the resolved
Compose configuration stays identical. `--only <step>` runs one step and
refuses an unsafe order. Every `.env` change is checkpointed in `.adopt/`;
`--revert <step>` restores one only if `.env` is unchanged since (the trust
step has no revert). Afterwards `varlatch setup` reruns like on any managed
installation.

### By hand

```sh
cd infra/compose
cp .env.example .env            # then edit: set the passwords and CONVEX_INSTANCE_SECRET
mkdir -p secrets
openssl rand -hex 32 > secrets/varlatch-kek
docker compose up -d --build
docker compose run --rm convex-deploy   # deploy the Application Plane functions
```

`convex-deploy` reconciles the Application Plane with this release: it deploys the functions and applies Convex's trust configuration only
where they differ, and derives the Convex admin key itself, so there is no
admin key to generate or store. Running it again on an unchanged
installation changes nothing; `varlatch upgrade` runs it for you.

Then bootstrap the first Installation Admin (host-exec authority):

```sh
docker compose exec varlatchd node dist/cli.js admin bootstrap --name "Your Name"
```

This prints a one-time CLI credential. Store it in a password manager
immediately; it is never retrievable again.

## The root KEK is your responsibility

- `secrets/varlatch-kek` is the root of the entire encryption hierarchy.
- **Back it up off this host**, separately from database backups:
  - encrypted archive + BEK + matching KEK + pinned release/configuration = recovery inputs
  - database backup + lost KEK = permanent data loss
  - KEK stored *with* the backup = weakened theft protection
- Verify a backup copy at any time without exposing key material:

```sh
docker compose exec varlatchd node dist/cli.js admin kek verify --file /path/inside/container
```

### Where to keep the backup

Keep at least two copies in two custody domains, neither of which is this
host or the bucket that holds database dumps:

1. A password manager vault entry (the KEK is 64 hex characters).
2. An offline copy, printed on paper or on an encrypted USB key, in a
   physically separate location.

Never: the Coolify host, Coolify env settings, the DB backup bucket, or git.

### Passphrase-wrapped escrow (recommended)

`kek export` wraps the KEK with a passphrase-derived key (scrypt +
AES-256-GCM). The resulting blob is safe to store **anywhere**, including
next to database backups, because the blob alone yields nothing; only the
passphrase must be custodied separately (password manager, printed, memorized).

```sh
# create an escrow blob (prompts for a passphrase, min 12 chars)
docker compose exec -it varlatchd node dist/cli.js admin kek export --out /tmp/kek-escrow.json
docker compose cp varlatchd:/tmp/kek-escrow.json ./kek-escrow.json

# disaster recovery: restore the database, then
docker compose exec -it varlatchd node dist/cli.js admin kek restore \
  --in /path/to/kek-escrow.json --out /run/secrets-restore/varlatch-kek
# restore verifies the recovered KEK against the installation canary first
```

Non-interactive use: `--passphrase-file <path>` or `VARLATCH_KEK_PASSPHRASE`.

### Shamir secret sharing (multi-custodian)

`kek split` produces n shares of which any k reconstruct the KEK and any
k-1 reveal nothing. Give each share to a different custodian; never store
two together. Each share embeds a fingerprint so a wrong or corrupted share
is detected at combine time.

```sh
docker compose exec varlatchd node dist/cli.js admin kek split --shares 5 --threshold 3

# reconstruct (shares one per line on stdin, or repeated --share flags)
docker compose exec -iT varlatchd node dist/cli.js admin kek combine \
  --out /run/secrets-restore/varlatch-kek < shares.txt
```

## Backup

Use `varlatch admin backup create|verify|restore|status` from the Compose host.
Archives contain the Secret Plane database, encrypted under an independent
Backup Encryption Key (BEK); restore rebuilds the Application Plane.
Capture is online: the installation keeps serving while it runs.

```sh
varlatch admin backup create --bek-file /secure/backup-key --kek-file /secure/root-kek-copy
varlatch admin backup verify --in ./backups/ARCHIVE-ID.vltbak \
  --bek-file /secure/backup-key --kek-file /secure/root-kek-copy --record
```

See [the backup and recovery runbook](https://github.com/varlatch/varlatch/blob/main/docs/operations/backup.md)
for key custody, S3 destinations, scheduling, fresh-host restore, interrupted
restore recovery, and scratch-space requirements. Keep `convex-supervisor.cjs`
with the Compose file and preserve the `varlatch-state` volume.

## Upgrade (backup-gated, forward-only)

Each GitHub release attaches the deployment unit: `varlatch-release.json`
(digest manifest), `docker-compose.release.yml` (this file with every
`build:` replaced by a digest-pinned image), and
`varlatch-compose-<version>.tar.gz` (first-install bundle), plus
`varlatch-cli-<version>.cjs` (the single-file operator CLI, Node 22+) and
`SHA256SUMS`. Digests are the canonical runtime pin; tags are for humans.
From 0.10.0 on, images are published for linux/amd64 and linux/arm64 with
provenance and SBOM attestations, and releases from the public repository
sign `SHA256SUMS` and the images:
[Verifying a release](../../docs/operations/verify-release.md).

The canonical path is the CLI, run on the host in this directory. Install it
as described in [Install the operator CLI](../../docs/operations/backup.md#install-the-operator-cli),
and replace it with the new release's file after each upgrade:

```sh
varlatch upgrade --bek-file /secure/backup-key --kek-file /secure/root-kek-copy
varlatch upgrade --check    # show installed vs. available, change nothing
```

It reads the target release, refuses downgrades, creates an encrypted archive in
`./backups/`, verifies it with the BEK and candidate KEK against that release, and applies
the pinned compose file + manifest and refreshes the ingress overlays this
directory has (`docker-compose.caddy.yml`, `Caddyfile`, the Tailscale
overlays and `tailscale-serve.json`, their images pinned by digest from
0.10.0 on), keeping the previous files as `*.pre-<version>`, then pulls,
starts the stack (`varlatch-migrate` gates `varlatchd`), waits for health,
recreates `convex-backend` when the Convex supervisor file changed, reloads
Caddy when the Caddyfile changed, then runs `convex-deploy` so the
Application Plane functions can never go stale. Overlays are release files:
put local changes in `.env` or a separate override file, not in them. Non-interactive:
`varlatch upgrade --yes --bek-file /secure/backup-key --kek-file /secure/root-kek-copy`.

The upgrade is **complete only when the target release's upgrade gate
passes**: the new release's own CLI, taken from its `varlatchd`
image, runs `varlatch doctor --gate` here. Services, Secret Plane readiness,
release consistency, public URL, Mirror catch-up, the Application Plane
functions and the supervisor must each *pass*; a check that cannot run
(unknown) blocks like a failure. Until then the release stays pending: fix
what the gate names and rerun the same `varlatch upgrade <version>`; it
resumes on the archive it already verified. Advisory findings (backups,
custody) are listed but never block. `varlatch doctor --gate` shows the same
verdict at any time. When your CLI is older than the release, the upgrade
leaves the release's CLI as `varlatch-cli-<version>.cjs` here: use it from
then on.

Local customization must live in `.env` or a `docker-compose.override.yml`,
because the upgrade replaces `docker-compose.yml` wholesale.

For the published v0.7.0 release, use the 0.8.0 or newer CLI and plan an offline
maintenance window: see the [first-upgrade bridge](../../docs/operations/backup.md#first-upgrade-from-the-published-v070-release).
Disable unattended Coolify upgrades; every schema-changing deployment needs
this archive/verification step first.

Manually, the same steps are:

1. Read the target release notes; confirm the upgrade path is supported.
2. Create an archive and run `backup verify --target-release <target-manifest>` with both keys.
3. Replace `docker-compose.yml` with the release's
   `docker-compose.release.yml` (and keep its `varlatch-release.json`).
4. `docker compose pull && docker compose up -d`
5. Wait for health (`curl -fsS localhost:8686/readyz`), then
   `docker compose run --rm convex-deploy`.

Recovery = restore the pre-upgrade archive with its BEK and matching Root KEK
on a release that explicitly supports that source. The 0.7.0 migration-16
archive is restored using 0.8.0; the old release has no archive restore command.
There are no downgrade migrations.

## Health check (read-only)

```sh
varlatch doctor --dir /srv/varlatch          # human-readable
varlatch doctor --dir /srv/varlatch --json   # for scripts; exit 1 on a mandatory failure
```

`doctor` changes nothing: it lists the Compose services and runs read-only
checks inside `varlatchd`: Secret Plane readiness (schema, Root KEK against
the canary, maintenance state), the public URL, whether dashboard Mirrors
have caught up (it waits up to `--wait` seconds, default 15), backup status,
the release manifest and any unfinished upgrade, the host CLI version, and
the dashboard's live-update endpoint. Each check is pass, fail, or unknown,
and mandatory or advisory; "unknown" is never reported as pass. For example,
browser reachability can only be measured from a browser, and off-host key
copies can never be verified by the installation. Like `admin backup`, it
needs Docker access on the host and no Varlatch login. For a Compose project
started with non-default files or project name, set Compose's own
`COMPOSE_PROJECT_NAME` / `COMPOSE_FILE` / `COMPOSE_ENV_FILES`.

## Break-glass recovery

If installation-level human access is lost:

```sh
# recover a named existing Installation Admin
docker compose exec varlatchd node dist/cli.js admin recover --identity <idn_...>
# re-enable + recover a disabled admin (explicit intent)
docker compose exec varlatchd node dist/cli.js admin recover --identity <idn_...> --enable
# only when zero enabled Installation Admins exist
docker compose exec varlatchd node dist/cli.js admin recover --new-admin
```

Anyone with exec/terminal access to these containers is an Infrastructure
Operator for this installation. That is authority they already possess
through the host, made explicit and audited here.

## Optional Tailscale integration

```sh
# .env additionally needs TS_AUTHKEY and VARLATCH_TAILNET_NAME
docker compose -f docker-compose.yml -f docker-compose.tailscale.yml up -d
```

varlatchd joins the Tailscale sidecar's network namespace, so its dedicated
tailnet listener (port 8687, reachable only over Tailscale) sees true tailnet
peer addresses and verifies them via WhoIs with your tailnet pinned. Tailnet
Requirements ("require tailnet for production-tier retrieval") are created
through the API/CLI; without this overlay they simply fail closed. Never
reverse-proxy the tailnet listener: that would break the socket-level
identity guarantee.

The overlay needs Docker Compose 2.24 or newer (it uses `!reset` to drop
varlatchd's own port mapping; the sidecar publishes 8686 instead). Earlier
revisions of this overlay did not start: Docker refuses published ports on a
container that shares another's network namespace, and the dashboard could
not resolve `varlatchd`. Both are covered by `scripts/test-backup-compose.mjs`
now.

## September 2026 upgrade compatibility

Migration 0017 adds commit-ordered audit positions and clears the old idempotency retry cache to remove unkeyed plaintext-derived hashes. Do not replay pre-upgrade mutations assuming their old idempotency keys still deduplicate. The sync worker rescans historical triggers once; delivery remains convergent. Back up the databases and matching KEK before migration.

OIDC clients must now specify the intended organization (`varlatch login --server <url> --oidc --org <slug>`; API JSON `organization`). Upgrade clients together with the daemon. Browser Convex clients must use invalidation signals and fetch records through `/v1`.

If `convex-backend` is down, the dashboard keeps working: it shows "Live updates reconnecting", reloads what is on screen from `/v1` every 15 to 60 s, and refreshes everything when live updates return. The CLI, API and credential broker never depend on Convex.

### Client addresses behind proxies

varlatchd limits some requests per client: 600 requests a minute, and for device sign-in at most 10 pending sign-ins and 20 wrong codes every 10 minutes. The device sign-in confirmation also shows the address that asked. Every request reaches varlatchd through the dashboard's nginx, often with a TLS proxy in front, so varlatchd reads the caller's address from `X-Forwarded-For`. It believes that header only when the request comes from a proxy named in `VARLATCH_TRUSTED_PROXIES`. It reads the header from the right and takes the first address that is not a trusted proxy. An address a caller writes into the header is therefore never used, and a request that reaches varlatchd directly is limited by its own address.

The Compose files set it for you:

| Files | `VARLATCH_TRUSTED_PROXIES` |
| --- | --- |
| `docker-compose.yml` | `varlatch-web` |
| with `docker-compose.caddy.yml` | `varlatch-web,caddy` |
| with `docker-compose.tailnet-https.yml` | `varlatch-web,tailscale` |
| `docker-compose.coolify-tailscale.yml` | `varlatch-web,coolify-proxy` |

Entries are compose service or container names, which are resolved again every 10 seconds, IP addresses, or CIDR ranges. If you put your own reverse proxy in front of the dashboard, set the variable in `.env` and add your proxy's name or address. That proxy must replace `X-Forwarded-For` with the client's address or append the address to it. varlatchd logs each name's resolved address at startup, and warns when a name does not resolve. Until it resolves, every caller behind that proxy counts as one client. Trust from a name lasts only as long as its resolution. A refresh that fails drops the name's addresses at once, so a container that is gone is never trusted at the address it had. varlatchd never relies on a resolution more than 30 seconds old. Never list a range that contains a Docker network's gateway address: callers on the host reach containers from that address.

`VARLATCH_SYNC=off` disables outbound sync. `VARLATCH_SYNC_ADAPTERS=github-actions,coolify` restricts adapters; an empty value allows the built-in set. Both settings are forwarded by canonical Compose.

`varlatch upgrade` writes a pending manifest while applying a release and promotes it only when the upgrade gate passes. If it fails, retry the same target version; the original `*.pre-<version>` files are preserved.

`./scripts/ci-e2e.sh` from the repository root creates a disposable Compose project with temporary credentials, loopback ports, and volumes, then removes that project on exit. It does not reset an existing installation.

Historical webhook URL audit fields are redacted on API export and delivery. Previously written database records and backups remain immutable; rotate any webhook URL tokens that were exposed under older versions.
