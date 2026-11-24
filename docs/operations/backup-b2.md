# First off-host backup with Backblaze B2

> **Prerelease.** This page is for Varlatch 0.50, which is not released yet.
> The current release, 0.23.0, runs on Docker Compose:
> [docs.varlatch.com](https://docs.varlatch.com/operations/backup-b2/).

An installation makes encrypted backups on its own disk without any cloud
storage. A copy off the host is needed to survive losing the host. B2 is one
supported S3-compatible destination; an AWS account is not required.

## Create the bucket and credentials

1. Create a Backblaze B2 account, select your preferred storage region, and
   enable account MFA. Create a **private** bucket with a unique name, such as
   `varlatch-backups-YOURNAME`. Record its **S3 endpoint** and bucket name.
2. Create `varlatch-backup-upload` restricted to that bucket and the filename
   prefix `production/`, with the exact **writeFiles** capability. Use the B2
   CLI below; the GUI's Write Only preset is broader than a backup
   needs. Never configure Varlatch with the account's master key.
3. Create `varlatch-backup-verify` for the same bucket and prefix, with
   **readFiles** access. Keep it off the host, for restores and for checking
   archives from another machine.
4. Save each key ID and application key in a password manager when displayed.
   The application key cannot be retrieved again. Do not paste secrets into
   chat, source control, command arguments, or the destination configuration.

See Backblaze's [bucket quickstart](https://www.backblaze.com/docs/cloud-storage-developer-quick-start-guide)
and [application-key instructions](https://www.backblaze.com/docs/cloud-storage-create-and-manage-app-keys).
Install the [official B2 CLI](https://www.backblaze.com/docs/cloud-storage-command-line-tools)
on your operator workstation and run `b2 account authorize` interactively using
an account credential authorized to create keys. Keep that administrative
credential off the installation's host. Then run:

```sh
b2 key create --bucket YOUR-BUCKET --name-prefix production/ varlatch-backup-upload writeFiles
b2 key create --bucket YOUR-BUCKET --name-prefix production/ varlatch-backup-verify readFiles
```

These commands display each new key ID and secret once: save the output
privately. [B2's capability mapping](https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys)
confirms that `writeFiles` covers uploads and multipart completion/abort;
deletion requires the separate `deleteFiles` permission. This uploader addresses
a known bucket and object, so it does not need bucket/object listing rights.
Upload-only credentials are not immutable storage: turn on Object Lock with a
default retention too, after validating your retention needs. The server uses
one key for everything, so with a write-only key it cannot check what it
uploaded: [Scoping destination credentials](backup.md#scoping-destination-credentials-per-provider)
explains the choice.

<a id="store-credential-files-on-the-operator-host"></a>

## Store the upload key on the host

In an editor, as root, create `/etc/varlatch/bucket-write.json`:

```json
{
  "accessKeyId": "YOUR_UPLOAD_KEY_ID",
  "secretAccessKey": "YOUR_UPLOAD_APPLICATION_KEY"
}
```

The service reads this file itself. Let its group read it, and nobody else:

```sh
sudo chown root:varlatch /etc/varlatch/bucket-write.json
sudo chmod 640 /etc/varlatch/bucket-write.json
```

Never store the read key on this host. The S3 keys give access to storage.
They are **not** the backup key or the Root KEK: keep off-host copies of
those two as the [recovery runbook](backup.md#keys-and-recovery-inputs)
describes.

## Configure Varlatch

Create `/etc/varlatch/backup-destinations.json`, and replace every
placeholder:

```json
{
  "offsite": {
    "endpoint": "https://s3.YOUR-REGION.backblazeb2.com",
    "region": "YOUR-REGION",
    "bucket": "YOUR-BUCKET",
    "prefix": "production/",
    "forcePathStyle": true,
    "writeCredentialsFile": "/etc/varlatch/bucket-write.json"
  }
}
```

Copy the endpoint from B2 rather than guessing it. The region is the segment
between `s3.` and `.backblazeb2.com`.

Then add both settings to `varlatchd.conf`, restart, test the bucket and make
a backup: [S3-compatible destinations](backup.md#s3-compatible-destinations)
has the commands. Download that archive with the read key to an isolated
machine, and [rehearse a restore](backup.md#rehearse-a-restore) there. A
successful upload is not a restore test.

Then choose the bucket's retention. Include an
incomplete-multipart-upload expiry rule. Retain both encryption keys
for as long as any archive needs them. Avoid a lifecycle policy that silently
deletes the only recovery point before a replacement has been checked.
The `writeFiles` upload key can also *hide* files, either with `b2_hide_file`
or by re-uploading a name (the previous version becomes hidden), and a
lifecycle rule deletes hidden versions after `daysFromHidingToDeleting`. Keep
that long enough to notice and unhide, e.g. 30 days rather than 1, or enable
Object Lock on the bucket, so a compromised host cannot erase archives
through the lifecycle.

Safe details to share when asking for setup help: bucket name, endpoint, region,
and file paths. Never share the file contents.
