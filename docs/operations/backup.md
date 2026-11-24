# Installation backup and recovery

> **Prerelease.** This page is for Varlatch 0.50, which is not released yet.
> The current release, 0.23.0, runs on Docker Compose:
> [docs.varlatch.com](https://docs.varlatch.com/operations/backup/).

An installation backs itself up: `varlatchd` makes an encrypted archive of
its database every day, checks it, and uploads it when you gave it a bucket.
You need no scheduler and no other program. The host commands below need
root on the host; no Varlatch login is needed, and nothing in a tenant can
configure a destination or start a recovery.

## Keys and recovery inputs

To restore, you need all of these:

1. an archive (`<id>.vltbak`);
2. the **backup key** (the Backup Encryption Key), which opens the archive;
3. the **Root KEK** the archive's values depend on;
4. a `varlatchd` of a release that can read the archive: the one that made
   it, or a newer one.

Setup makes both keys, in `/etc/varlatch/backup-key` and
`/etc/varlatch/root-kek`, readable by root only, and shows each once for you
to keep elsewhere. Losing either key makes every archive that needs it
useless. Keep old copies for as long as you keep archives that need them.
Never put a key in the backup bucket. Keep the two keys apart from each
other: whoever has the archive and both keys has every value.
[The Root KEK is your responsibility](../self-hosting.md#the-root-kek-is-your-responsibility)
says how to keep the copies.

## Create and verify

```sh
sudo varlatch admin backup run      # make, check and deliver a backup now
sudo varlatch admin backup status   # every archive, and the warnings
```

`run` prints the archive's path, what each check found, and how long the
database snapshot was held. Every archive, scheduled or not, is checked
before it counts:

- **integrity:** the archive opens with the backup key, whole;
- **compatibility:** this release can restore it;
- **Root KEK match:** the installed Root KEK opens what the archive holds.

A backup pauses nothing: people and applications go on working while it
runs. It takes a consistent snapshot of the database, seals it with the
backup key, and puts it in `/var/lib/varlatch/backups` (mode 0600). The
archive holds the database and the settings of `varlatchd.conf`, never a
key. It does not run during maintenance, and
`backup run` then says so.

### The schedule

| Setting | Default | |
|---|---|---|
| [`backup_interval`](../self-hosting/configuration.md#backup_interval) | `24h` | how often; `off` turns the schedule off |
| [`backup_keep`](../self-hosting/configuration.md#backup_keep) | `7` | how many archives stay on this host |
| [`backup_destinations_file`](../self-hosting/configuration.md#backup_destinations_file) | none | the buckets archives can go to |
| [`backup_destination`](../self-hosting/configuration.md#backup_destination) | `offsite` | which of them is used |

A backup that fails is tried again an hour later. The journal says why.

### Warnings

`backup status`, `varlatch doctor` and the dashboard (**Installation
settings**, for Installation Admins) show the same warnings:

- no archive within 48 hours;
- the newest archive was not delivered to a destination, or did not pass
  its checks;
- a remote copy failed its check, or none passed within 30 days;
- a Root KEK version that archives need had no successful check within 30
  days.

### What a capture costs (measured)

The snapshot is taken online, so its cost is processor and disk time, not
downtime. `backup run` prints both for your installation, and `status`
records them with each archive. Both grow with the audit history.

Keep free space for a copy of the database, plus the archive:
`varlatch doctor` checks it. Finished archives are encrypted. A killed run
can leave its working files in `/var/lib/varlatch/backups`; the next run
removes them.

### Deleted Projects and Organizations

Deleting a Project or an Organization erases its values from the live
database, not from archives. An archive taken before the deletion holds the
data until your retention removes it, and restoring that archive restores
the whole installation, deleted data included. When data must be gone from
backups too, let the retention of every destination run its course.

## S3-compatible destinations

Until you give it a bucket, an installation keeps its archives on its own
disk, and loses them with it. New to S3? Start with the
[Backblaze B2 setup guide](backup-b2.md).

1. Write `/etc/varlatch/backup-destinations.json`:

   ```json
   {
     "offsite": {
       "endpoint": "https://s3.example.net",
       "region": "us-east-1",
       "bucket": "varlatch-backups",
       "prefix": "production/",
       "forcePathStyle": true,
       "writeCredentialsFile": "/etc/varlatch/bucket-write.json"
     }
   }
   ```

   For AWS's standard endpoint, leave `endpoint` out. `prefix` defaults to
   `varlatch/`, `forcePathStyle` to `true`.

2. Write the bucket's key in `/etc/varlatch/bucket-write.json`:

   ```json
   { "accessKeyId": "YOUR_KEY_ID", "secretAccessKey": "YOUR_KEY" }
   ```

   `sessionToken` is optional. The service reads this file itself, so its
   group must be able to read it, and nobody else:

   ```sh
   sudo chown root:varlatch /etc/varlatch/bucket-write.json
   sudo chmod 640 /etc/varlatch/bucket-write.json
   ```

3. Add both settings to `/etc/varlatch/varlatchd.conf`, and restart:

   ```ini
   backup_destinations_file = /etc/varlatch/backup-destinations.json
   backup_destination = offsite
   ```

   ```sh
   sudo systemctl restart varlatchd
   ```

4. Test the bucket, then make a backup:

   ```sh
   sudo varlatch admin backup test-bucket
   sudo varlatch admin backup run
   ```

On a new installation, setup does step 3: answer **bucket** when it asks
where backups go, or pass `--backups bucket --backup-destinations-file
/etc/varlatch/backup-destinations.json --backup-destination offsite`. The
`varlatch` group exists only once setup has run, so make the key file
readable when setup's first backup says `permission denied`, then run setup
again.

`test-bucket` uploads a small test archive with none of the installation's
data in it, and reports three things:

| Check | Passes when |
|---|---|
| delivery | the upload worked |
| retention | the uploaded version has a retention, and deleting it was refused |
| recoverability | the uploaded version was downloaded and opened |

It exits 1 unless all three pass. Retention needs a bucket with versioning
and Object Lock, with a default retention: it is what keeps a stolen host
from erasing its own backups. The test archive stays in the bucket for that
retention.

Objects are `<prefix>/<archive id>.vltbak`. A failed upload leaves the
archive on this host. The bucket's own lifecycle decides how long archives
stay there: Varlatch deletes nothing at a destination. Add a rule that
expires incomplete multipart uploads, and never one that could remove the
newest archive. A bucket on the same disk is no second place.

`sudo varlatchd admin backup run --json --verify-remote` makes a backup,
then downloads its uploaded copy and checks it. Run it at least every 30
days, with a key that may read.

A bucket behind a private certificate authority needs that authority among
the [certificates the server trusts](../reference/outbound-policy.md#a-private-certificate-authority).

### Scoping destination credentials per provider

A backup needs only to **write** under its prefix: `PutObject`, the
multipart calls (`CreateMultipartUpload`, `UploadPart`,
`CompleteMultipartUpload`), and `AbortMultipartUpload` on failure. Give the
server a key of its own, as narrow as the provider allows, so a compromised
host cannot list or delete existing archives.

A destination has one key, and the server uses it for everything. So choose:

- **A key that may write only.** A compromised host cannot read archives,
  but the server cannot download one either: `test-bucket` then reports
  that retention and recoverability could not be checked, and the status
  keeps the warning that no remote copy was verified within 30 days. Check
  archives from another machine instead, with a read key and a
  [restore rehearsal](#rehearse-a-restore).
- **A key that may also read** (`GetObject` and `GetObjectRetention`) under
  the prefix. `test-bucket` and the remote check then work. Archives are
  encrypted with the backup key, so a stolen copy opens only with that key.

A write-only key can still **overwrite** an object if it knows the key name.
Random UUID names only help against a key stolen *off* the host: the host
itself knows recent names (the local `backups/` directory). On providers where overwritten versions expire through lifecycle rules
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

For a key that may also read, add `"s3:GetObject"` and
`"s3:GetObjectRetention"`. Against overwrites, enable versioning (a write-only key cannot delete old
versions) or Object Lock in compliance mode. Omit `endpoint` in the
destinations file for AWS.

**Cloudflare R2:** no put-only credential exists. The narrowest API token is
*Object Read & Write* on specific buckets, which can also read, list,
overwrite, and delete. (Prefix-scoped temporary credentials exist but expire,
so an unattended job would have to store the parent token.) Protect the prefix
with an
[R2 bucket lock](https://developers.cloudflare.com/r2/buckets/bucket-locks/);
with this key, the lock is the only thing stopping a compromised host from
deleting archives.

**MinIO:** put-only and prefix-scoped, with the AWS policy above:

```sh
mc admin policy create ALIAS varlatch-backup-put backup-put.json
mc admin user add ALIAS varlatch-backup-writer 'LONG-RANDOM-SECRET'
mc admin policy attach ALIAS varlatch-backup-put --user varlatch-backup-writer
```

Versioning plus object locking makes archives immutable. Avoid the built-in `writeonly` policy: it covers all
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

For a key that may also read, add `ObjectStorageObjectsRead` and
`s3:GetObject`. Object lock in compliance mode (it requires versioning)
prevents overwrites.

## Restore on a fresh host or retry an interrupted restore

Keep the archive and the two keys in files only root can read, and give
them to a fresh host on which Varlatch was never set up:

```sh
V=0.50.0  # the release that made the archive, or a newer one
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sudo sh install.sh --server -- --restore /root/backup.vltbak \
  --root-kek-file /root/root-kek --backup-key-file /root/backup-key
```

Or, when the binaries are already there, `sudo varlatch setup --restore`
with the same flags.

It installs your keys, restores the archive, checks that the Root KEK opens
it, then goes on as setup does: it starts `varlatchd`, makes a backup and
runs `varlatch doctor`. It asks the same questions, such as the ingress and
where backups go. The address must be the one the archive's installation
had (`--public-url`): its passkeys belong to it. To change the address,
restore first, then [move it](move-installation.md). Setup refuses a host
that holds other keys. If it stops, run it again.

The restored installation is the one the archive holds: the same people,
passkeys, credentials and audit log, as they were then. What was revoked
since the archive was made is not revoked in it: revoke it again before
people use the installation. Two copies of one installation must never
serve at the same time.

- **Public ingress:** the certificate is not in the archive; the new host
  obtains its own. Point the name at it.
- **Tailnet:** the node's state is not in the archive. Setup can take the
  old node's name over, with `--tailscale-oauth-client-file`, or
  `--tailnet-control-url` and `--headscale-api-key-file`.

### Put an archive back on the same host

```sh
sudo systemctl stop varlatchd
sudo varlatch admin backup restore --in /var/lib/varlatch/backups/ARCHIVE-ID.vltbak
sudo chown varlatch:varlatch /var/lib/varlatch/varlatch.db
sudo systemctl start varlatchd
sudo varlatch admin backup run
```

It uses the keys in `/etc/varlatch`; `--backup-key-file` names another
backup key. Every change since the archive is lost. The restore runs as
root, so the `chown` gives the restored database back to the service:
without it, `varlatchd` cannot open it.

It prints the archive's settings, to compare with `varlatchd.conf`. It
refuses while `varlatchd` runs, an archive of another installation, and an
archive this release cannot read.

A restore that fails or is killed leaves the installation closed: it
answers `503` until you run the same restore again with the same archive.

### Rehearse a restore

A backup you never restored is a hope. Restore an archive onto a disposable
machine, isolated from the network the real installation reaches, and look
at what you find. Delete that machine and its copies of the keys
afterwards.

## Archives of 0.23.0 and earlier

Varlatch 0.50 does not restore an archive made by 0.23.0 or earlier. Keep
the old release, its archives and their keys together for as long as you
may need them. [Old archives: the converter](migrate-to-0.50.md#old-archives-the-converter)
turns one into an archive 0.50 restores.

The commands of those releases (`backup create`, `verify` and `restore`
with `--dir`) are in
[their version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/operations/backup.md):

- <a id="install-the-operator-cli"></a>[Install the operator CLI](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/operations/backup.md#install-the-operator-cli).
  From 0.50, `install.sh --server` installs it.
- <a id="upgrade-gate"></a>[Upgrade gate](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/operations/backup.md#upgrade-gate).
  From 0.50: [Upgrading](upgrade.md).
- <a id="first-upgrade-from-the-published-v070-release"></a>[First upgrade from the published v0.7.0 release](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/operations/backup.md#first-upgrade-from-the-published-v070-release)
- <a id="coolify-and-older-emergency-dumps"></a>[Coolify and older emergency dumps](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/operations/backup.md#coolify-and-older-emergency-dumps)
- <a id="passkeys-that-shared-a-credential-migration-39"></a>[Passkeys that shared a credential (migration 39)](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/operations/backup.md#passkeys-that-shared-a-credential-migration-39)
