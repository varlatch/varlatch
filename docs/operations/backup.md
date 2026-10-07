# Installation backup and recovery

Run `varlatch admin backup` on the Infrastructure Operator's Docker Compose
host, with `--dir` pointing at the canonical Compose directory. No Varlatch
login is needed: host/container access is the authority. Backup destinations
are operator files, never Organization Platform Connections.

## Install the operator CLI

Each release attaches `varlatch-cli-<version>.cjs`, a single-file build of
the CLI that needs only Node.js 22 or newer: no checkout, pnpm, or build.
Install it root-owned on the Compose host:

```sh
V=0.15.0  # the release the installation runs
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/varlatch-cli-$V.cjs
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
sudo install -m 755 varlatch-cli-$V.cjs /usr/local/bin/varlatch
varlatch --version
```

Releases after 0.15.0 sign `SHA256SUMS` itself: check its signature
first, as [Verifying a release](verify-release.md) describes.

From then on, `varlatch self-update` does the same for a newer release:
it checks the signature on `SHA256SUMS` when cosign is installed and the
release is signed, checks the file, and replaces the CLI after you confirm.
Run it with `sudo` for a root-owned copy such as `/usr/local/bin/varlatch`.

The varlatchd image carries the same file at `/opt/varlatch/varlatch.cjs`, so
on the Compose host you can also take it from the running release, trusted
exactly as far as the digest-pinned image you already run:

```sh
cd /srv/varlatch && docker compose cp varlatchd:/opt/varlatch/varlatch.cjs ./varlatch.cjs
sudo install -m 755 varlatch.cjs /usr/local/bin/varlatch
```

The CLI embeds its release's compatibility manifest, so it is
version-coupled to the installation: a stale host CLI records failed
compatibility checks against archives from a newer release. **Replace the host
CLI with the new release's file after every upgrade**, before the next
scheduled backup runs; `varlatch upgrade` prints a reminder when the CLI and
the installation differ. The reference host timer (`infra/host-backup`) does
this itself: every run extracts the CLI from the running image. Releases up
to 0.8.0 predate this artifact and need the CLI built from a checkout of that
tag (`pnpm install --frozen-lockfile && pnpm build`, then
`node apps/cli/dist/main.js`).

## Keys and recovery inputs

Generate an independent 32-byte Backup Encryption Key (BEK), for example:

```sh
umask 077
openssl rand -hex 32 > /secure/operator/backup-key
```

Keep a separately held copy of both this BEK and the Root KEK. Do not derive
the BEK from the Root KEK, put either key in the backup bucket, or place them
in the archive output directory. Key files accept hex or base64. As an
alternative to `--bek-file`, use `--bek-passphrase-file` (at least 12 bytes;
a final newline is removed). Keys and passphrases are never command arguments
or status fields. `verify --kek-file -` accepts a candidate Root KEK on stdin.

Recovery requires the encrypted archive, its BEK, the Root KEK version named
in its manifest, a compatible pinned release, and installation configuration.
Losing either key makes the corresponding encrypted data unrecoverable.
Retain historical BEKs and Root KEKs for as long as their archives must remain
restorable. A successful key check does not prove that an off-host custody
copy exists.

## Create and verify

```sh
varlatch admin backup create --dir /srv/varlatch \
  --bek-file /secure/operator/backup-key \
  --kek-file /secure/operator/root-kek-copy

varlatch admin backup verify --dir /srv/varlatch \
  --in /srv/varlatch/backups/ARCHIVE-ID.vltbak \
  --bek-file /secure/operator/backup-key \
  --kek-file /secure/operator/root-kek-copy --record

varlatch admin backup status --dir /srv/varlatch
```

`create` prints the actual path and archive ID. `--out` overrides the default
`<compose-dir>/backups/<id>.vltbak`. The archive contains the Secret Plane
database only (archive format 2). The Application Plane, Convex's
database and storage, holds nothing a restore cannot rebuild, so restore
rebuilds it instead. The archive alone never recovers an installation: it
also takes the BEK, the matching Root KEK, the release artifacts, and the
installation configuration.

Capture is **online**: nothing is paused or gated. varlatchd takes the
*capture exclusion*, which key rotation, `migrate`, and restore also need,
then opens a single database snapshot, and the dump reads that snapshot while
the installation keeps serving disclosures, writes, sign-in, and its workers.
Metadata (installation, release, required Root KEK versions, canary) comes
from the same snapshot. The dump still costs CPU and I/O, so schedule it for
low load. A migration started during a capture waits for it (up to 15
minutes); a capture refuses to start during an incomplete key rotation.

A daemon older than online capture (for example the release `varlatch
upgrade` starts from) is captured with the previous, frozen protocol: it
answers ordinary traffic with a retryable `503 MAINTENANCE` while both
databases and Convex storage are dumped, and produces a format-1 archive.

The capture deadline defaults to 300 seconds; `--timeout-seconds` accepts
1 to 86400 seconds. When it expires, varlatchd stops the dump and confirms it
has exited before it releases the capture exclusion. A lost or expired
capture never produces an archive, even if its dump process eventually
succeeds: the CLI publishes only after varlatchd confirms the capture is
still valid and still holds its exclusion. A daemon restart, or losing the
capture's database connection, invalidates an active capture. The
operator execution lock prevents concurrent create/restore commands across
Compose invocations; it does not replace the restore isolation gate.

### What a capture costs (measured)

Measured 2026-09-24 with `scripts/measure-capture.mjs`.

**Setup:**
- PostgreSQL limited to 2 CPUs / 4 GB. The dump runs in its container, sharing that budget.
- varlatchd limited to 1 CPU / 1 GB.
- Audit history seeded to shape like real disclosures.
- Two clients disclosing secrets every 250 ms throughout. That stays under
  varlatchd's per-client limit of 600 requests a minute, and each disclosure
  commits an audit event.

| Audit events | Database | Archive | Snapshot held (dump) | Disclosure p50 / p95 / p99, no backup | … during `backup create` | Failed requests | Restore (isolating, incl. rebuild) |
|---|---|---|---|---|---|---|---|
| 100,000 | 0.09 GiB | 8 MiB | 1.1 s (0.9 s) | 28 / 40 / 242 ms | 28 / 40 / 40 ms | 0 | 20 s |
| 1,000,000 | 0.85 GiB | 76 MiB | 7.5 s (7.3 s) | 23 / 37 / 238 ms | 19 / 37 / 83 ms | 0 | 41 s |
| 10,000,000 | 8.7 GiB | 759 MiB | 79 s (79 s) | 23 / 26 / 247 ms | 24 / 51 / 229 ms | 0 | 161 s |

What this means:
- **No request failed or was held back during any capture.** Latency during
  a capture stays close to normal. At ten million audit events the p95 rose
  from 26 to 51 ms while the 79-second snapshot was open.
- **Capture time grows with audit history:** about 8 seconds and 76 MiB
  (compressed) per million audit events on this budget. The default
  `--timeout-seconds 300` covers roughly 35 million events on such a host;
  above that, raise it to several times the measured dump time.
  `backup create` prints the snapshot hold and dump time of every capture
  and records them with the archive.
- **Schedule for load, not for downtime.** A capture no longer needs a
  maintenance window. On a small host, off-peak hours keep its I/O out of
  the way.
- **Restore is the window that still isolates**: 20 s, 41 s,
  and 161 s at the three sizes, including the Application Plane rebuild.
  Plan recovery around it.
- Occasional 1 to 2 s outliers appear in every phase on this CPU-limited setup,
  the no-backup baseline included. They are not caused by the capture.
- An earlier revision loaded the whole varlatchd CLI (about 0.8 s of CPU)
  for each backup control call, taken from the running daemon. It pushed
  p99 during `backup create` to about 1 s. The control calls now use a
  minimal client (about 35 ms).

To reproduce or measure your own hardware:
`MEASURE_SIZES=100000,1000000 node scripts/measure-capture.mjs`. See the
script header for the limits and load it applies.

Use `--scratch-dir /private/scratch` to choose temporary storage. Temporary
plaintext dumps live in a mode-0700 directory with mode-0600 files; ordinary
completion/error paths remove them. Abrupt host failure/SIGKILL can leave
scratch files: use an encrypted scratch filesystem and remove abandoned
`varlatch-capture-*`, `varlatch-backup-*`, and `varlatch-verify-*` directories
when no operation is running. Finished archives are encrypted, mode 0600,
atomically published, and never overwrite an existing path. Version 1 limits
an archive's plaintext components to 60 GiB (below AES-GCM's per-message limit).
Plan disk capacity for dumps, decrypted verification scratch, and the encrypted
archive; verification is streaming but uses private disk scratch.

`verify` reports three independent results: integrity, compatibility, and key
match. Failure exits nonzero. It can run on a machine with neither Docker nor
the original installation. The default compatibility target is the verifier's
embedded release manifest; `--target-release /path/varlatch-release.json`
overrides it. Missing/unsupported compatibility metadata fails closed.
`--record` explicitly attaches the result to the running installation's
per-archive status; omit it for independent disaster verification. Failed key
or compatibility checks are also recorded when requested. Integrity failures
cannot safely supply an authenticated archive identity and are not recorded
against a guessed ID.

Checks passed does not mean the dumps have loaded or every secret decrypts.
A restore additionally loads the data, verifies the restored canary, and
republishes Mirrors. Automated disposable `backup drill` remains post-MVP.

## S3-compatible destinations

New to S3? Start with the [Backblaze B2 setup guide](backup-b2.md).

Create `backup-destinations.json` in the Compose directory:

```json
{
  "offsite": {
    "endpoint": "https://s3.example.net",
    "region": "us-east-1",
    "bucket": "varlatch-backups",
    "prefix": "production/",
    "forcePathStyle": true,
    "writeCredentialsFile": "/secure/operator/backup-s3-write.json"
  }
}
```

For AWS's standard endpoint, omit `endpoint`. Credentials files contain
`accessKeyId`, `secretAccessKey`, and optional `sessionToken`. Keep them
operator-readable only. `--destinations-file` overrides the configuration
path. Credential paths in that file are relative to the file's directory.

```sh
varlatch admin backup create --dir /srv/varlatch --destination offsite \
  --bek-file /secure/operator/backup-key --kek-file /secure/operator/root-kek-copy

varlatch admin backup verify --dir /srv/varlatch --destination offsite \
  --archive ARCHIVE-ID --read-credentials-file /secure/operator/backup-s3-read.json \
  --bek-file /secure/operator/backup-key --kek-file /secure/operator/root-kek-copy --record
```

Objects are `<prefix>/<archive-id>.vltbak`. Upload uses bounded-memory multipart
transfer for large archives. Scope scheduled credentials to writes under that
prefix; multipart uploads also need completion/abort permissions appropriate
to the provider. Lifecycle policies should expire incomplete multipart uploads.
An upload failure leaves the finished local archive available. No remote-read
credentials are stored by Varlatch; each remote verification invocation supplies
them separately. Upload completion and download-plus-verification remain
distinct facts. An ETag is not treated as a universal content checksum.

Bucket lifecycle manages retention. Status tracks recorded archives, not the
bucket's inventory: removing an object does not automatically remove its
historical custody warning. Off-host safety depends on the configured endpoint
actually being off-host; an S3-compatible server on the same disk is not a
second failure domain.

Schedule these CLI commands using cron, systemd, or Coolify: `create`, then a
local `verify --in <archive> --record` (keys already on the host; no extra
downtime). Give separate read credentials only to the job that performs remote
verification, and run it at least every 30 days. The
Installation settings page (`/installation/settings`) displays per-archive
checks/delivery and warnings; only Installation Admins can read that endpoint.
Warnings are actionable: no archive within 48 hours, a newest archive that is
undelivered or has not passed local verification, a failed latest remote check,
no passing remote check within 30 days, or a Root KEK version without a
successful check within 30 days.
Nothing in a tenant can configure a destination or initiate recovery.

### Scoping destination credentials per provider

The scheduled job needs only to **write** under its prefix: `PutObject`, the
multipart calls (`CreateMultipartUpload`, `UploadPart`,
`CompleteMultipartUpload`), and `AbortMultipartUpload` on failure. Remote
verification needs only `GetObject`. Give each job its own key, as narrow as
the provider allows, so a compromised host cannot read, list, or delete
existing archives.

A write-only key can still **overwrite** an object if it knows the key name.
Random UUID names only help against a key stolen *off* the host: the host
itself knows recent names (the local `backups/` directory and the status
file). On providers where overwritten versions expire through lifecycle rules
(B2 counts a superseded version as hidden), overwriting is effectively
deletion. The real protection against a hostile host is provider-side
immutability: versioning plus Object Lock, or the provider's equivalent.

**Backblaze B2:** `writeFiles` scoped to the bucket and prefix; the
[B2 setup guide](backup-b2.md) walks through it. `writeFiles` can hide a file
two ways: re-uploading its name (the old version becomes hidden) or
`b2_hide_file`. A lifecycle rule then deletes hidden versions after its
`daysFromHidingToDeleting`. Keep that value long enough to notice and unhide
(for example 30 days, not 1), or enable Object Lock on the bucket.

**AWS S3:** put-only and prefix-scoped are both possible. IAM authorizes all
three multipart calls with `s3:PutObject`; abort needs `s3:AbortMultipartUpload`.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
    "Resource": "arn:aws:s3:::YOUR-BUCKET/production/*"
  }]
}
```

The read key's policy has `"Action": "s3:GetObject"` on the same resource.
Against overwrites, enable versioning (a write-only key cannot delete old
versions) or Object Lock in compliance mode. Omit `endpoint` in the
destinations file for AWS.

**Cloudflare R2:** no put-only credential exists. The narrowest API token is
*Object Read & Write* on specific buckets, which can also read, list,
overwrite, and delete. (Prefix-scoped temporary credentials exist but expire,
so an unattended job would have to store the parent token.) Protect the prefix
with an
[R2 bucket lock](https://developers.cloudflare.com/r2/buckets/bucket-locks/)
(`npx wrangler r2 bucket lock add <bucket>`); with this key, the lock is the
only thing stopping a compromised host from deleting archives. The read key is
*Object Read*, which also allows listing.

**MinIO:** put-only and prefix-scoped, with the AWS policy above:

```sh
mc admin policy create ALIAS varlatch-backup-put backup-put.json
mc admin user add ALIAS varlatch-backup-writer 'LONG-RANDOM-SECRET'
mc admin policy attach ALIAS varlatch-backup-put --user varlatch-backup-writer
```

Create the read user the same way with a `s3:GetObject`-only policy. Versioning plus object locking makes
archives immutable. Avoid the built-in `writeonly` policy: it covers all
buckets.

**Scaleway Object Storage:** create an IAM application with the
`ObjectStorageObjectsWrite` permission set (no delete), then narrow it to the
prefix with a bucket policy allowing only `s3:PutObject` on
`YOUR-BUCKET/production/*` for that application. Two caveats:
- `AbortMultipartUpload` belongs to `ObjectStorageObjectsDelete`, so a failed
  upload cannot abort its parts. Varlatch tolerates that, but the lifecycle
  rule for incomplete multipart uploads is then mandatory.
- Once a bucket policy exists, every other principal (including your own
  console access) must be listed in it, and pushing a policy replaces the old
  one.

The read side is `ObjectStorageObjectsRead` plus a bucket policy allowing only
`s3:GetObject`. Object lock in compliance mode (it requires versioning)
prevents overwrites.

## Restore on a fresh host or retry an interrupted restore

1. Install Docker and the pinned compatible release set. Include
   `docker-compose.yml`, `convex-supervisor.cjs`, `postgres-init`, and the
   release manifest. Configure domains/ingress, fresh DB passwords, a fresh
   Convex instance secret, and the matching Root KEK mount. A fresh host may
   use fresh TLS and host tailnet enrollment. Do not bootstrap a new
   Installation before restoring.

   File permissions matter twice over (rehearsal-tested failure modes):
   restrict **only key material** to mode 0600, and only the copies the host
   CLI reads (the BEK, a Root KEK copy). The key files containers read, the
   mounted Root KEK and the database passwords, need mode 0644 inside a
   mode-0700 directory: the containers run as other users. `postgres-init/`,
   `convex-supervisor.cjs`, and any source tree used for image builds must be
   world-readable (`chmod -R a+rX`), because containers run as non-root users
   and `docker build` **bakes host permissions into images** (symptom:
   `ERR_INVALID_PACKAGE_CONFIG: permission denied` from every container). A
   blanket `umask 077` while preparing the directory causes all three.
2. **Set `VARLATCH_PUBLIC_URL` to the original installation's public URL**
   (its exact issuer string), even though the recovery host does not serve
   that domain. The restored Application Plane keeps the original
   `VARLATCH_ISSUER`/`VARLATCH_JWKS_URL` values and rejects mirror
   reconciliation JWTs otherwise (symptom: restore fails at reconciliation
   with `Convex mutation mirror:upsert failed: HTTP 401`). If the stored
   `VARLATCH_JWKS_URL` names a compose-internal host, it must resolve in the
   recovery topology. Archives from the Coolify/Tailscale variant name
   `http://tailscale:8686/...`: the canonical Compose file gives varlatchd
   the legacy alias `tailscale` for exactly this, so no extra
   file is needed any more (older releases needed a `jwks-alias.yml` override
   adding that alias).

   Resetting both Convex env vars during restore would need a running
   Application Plane, which the gate correctly prevents; the alias carries
   reconciliation, and restore resets them afterwards (below).
3. Obtain the archive, BEK, and candidate Root KEK through their separate
   custody channels. Run standalone `verify` against the intended release.
4. Run:

   ```sh
   varlatch admin backup restore --dir /srv/varlatch \
     --in /recovery/ARCHIVE-ID.vltbak \
     --bek-file /secure/operator/backup-key \
     --kek-file /secure/operator/root-kek-copy \
     --target-release /srv/varlatch/varlatch-release.json
   ```

Restore validates all components before replacing data. It creates a durable
gate on the `varlatch-state` volume **before** starting a fresh daemon, drains
existing work, stops Convex, and refuses an existing different Installation ID.
The running target binaries must implement the chosen compatible release.
The Secret Plane database is recreated under its canonical role with fresh
deployment passwords; its grants and append-only audit permissions come from
the dump. The loaded KEK is then checked against the restored canary and the
restore event is recorded; only then does isolation clear.

The Application Plane is **rebuilt, not restored**: its database
and storage are reset to empty. That holds for format-1 archives too, whose Convex
components `verify` still checks but restore ignores. Once isolation has
cleared, restore starts the rest of the installation (the dashboard, and the
ingress proxy where one is configured) without touching the services already
running. It then runs the `convex-deploy` job, which deploys
this release's functions and sets `VARLATCH_ISSUER`/`VARLATCH_JWKS_URL` to
this host's configuration, then publishes every Mirror from the restored
Secret Plane. Until then the dashboard works from `/v1` without live updates.
If the deploy job fails, the data is restored but the dashboard has no live
updates: run `docker compose run --rm convex-deploy`, then `varlatch doctor`.
If a service did not start, restore says so: run `docker compose up -d`, then
`varlatch doctor`.

After a restore, run `varlatch doctor`, then create and verify a fresh archive.
The backup history lives on the `varlatch-state` volume, so after a restore
onto a fresh host doctor reports no recent archive until you do.

A failed restore is incomplete. Ordinary requests and both planes'
workers stay blocked across process/host restart. Re-run the same restore with
the original valid archive; do not delete `maintenance.json` to make readiness
green. Capture lease expiry has no effect on this durable gate. The supported
abort procedure is to abandon the disposable recovery installation and remove
its volumes, then provision a fresh target; there is deliberately no command
that exposes partially restored data. Keep the `varlatch-state` volume alongside
the installation through restarts and restore retries.

The restored host adopts the archived Installation ID, identities, credentials,
contracts, audit, and key hierarchy. JWT signing keys stored in the Secret Plane
are restored with it; fresh deployment credentials do not invalidate those.
Installations that still set `CONVEX_ADMIN_KEY` must regenerate it for the
fresh instance secret and update operator tooling using the old admin key;
without one, the deploy job derives its key from the instance secret. No Root KEK is automatically rotated. Restoring old authorization
state also restores the revocations/state as of that checkpoint: reconcile any
post-backup security changes before returning the recovered installation to
normal external access.

## Upgrade gate

```sh
varlatch upgrade VERSION --dir /srv/varlatch \
  --bek-file /secure/operator/backup-key \
  --kek-file /secure/operator/root-kek-copy --yes
```

The upgrade creates an encrypted archive and verifies it against the target
release before changing deployment files. The former `--skip-db-backup` and
`--kek-backup-verified` assertions no longer satisfy the gate. Each release's
`packages/backup/src/release.json` declares its migration/PostgreSQL versions
and explicitly allowed restore sources; release tooling uses that same
manifest. Unsupported paths fail rather than infer compatibility.

### First upgrade from the published v0.7.0 release

Use the **0.8.0 or newer CLI** for this upgrade. The published v0.7.0 daemon has no
capture lease/control socket. Its release manifest identifies the one supported
offline bridge: version 0.7.0, migration 16, PostgreSQL 17, canonical local
Convex storage. Source-built 0.7.0 installations at migration 18 use ordinary
capture instead. Unknown combinations are refused.

The bridge stops every Compose application service while leaving PostgreSQL
running, dumps both databases, and copies Convex storage from the stopped
container. It verifies an encrypted archive before deploying 0.8.0. Plan downtime
for capture, encryption, verification, and upgrade: unlike ordinary capture,
the legacy services **remain stopped**, including if capture fails. Fix and
retry, or explicitly restart the original release before any migration has run.
External writers must also be stopped for this offline procedure.

For a manual deployment, create the bridge archive explicitly:

```sh
varlatch admin backup create --dir /srv/varlatch \
  --legacy-release /srv/varlatch/varlatch-release.json \
  --bek-file /secure/operator/backup-key \
  --kek-file /secure/operator/root-kek-copy
```

Verify it against the target release before proceeding. The bridge creates a
local archive; configure scheduled S3 uploads after upgrading. Recovery of this
migration-16 archive is supported on 0.8.0, which applies migrations before
reconciliation. Never start old binaries against forward-migrated databases.

A failed upgrade retains `varlatch-release.json.pending`, the original release
files, and `backup.pre-VERSION.json`. Retry re-verifies the original archive;
it does not replace it with a capture of partially upgraded state.

### Coolify and older emergency dumps

Disable automatic deployments for stateful upgrades. Before a manual Coolify
deployment, create and verify an archive against its target release using the
Compose configuration for the actual running installation. Preserve custom
networking, mounts, and the shared `varlatch-state` volume when applying changes.

The previous automatic `pg_dumpall | gzip` job is removed: it produced
unencrypted dumps without Convex file storage, and it did not meet the backup design.
Existing `postgres-backups` volumes are not deleted by this change. They contain
sensitive plaintext; retain them securely until a checked encrypted replacement
and a restore rehearsal exist, then remove them deliberately. Do not use volume
pruning as part of an upgrade.
