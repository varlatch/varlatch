# First off-host backup with Backblaze B2

Varlatch can make local encrypted backups without cloud storage. An off-host
copy is needed to survive losing the installation host. B2 is one supported
S3-compatible destination; an AWS account is not required.

## Create the bucket and credentials

1. Create a Backblaze B2 account, select your preferred storage region, and
   enable account MFA. Create a **private** bucket with a unique name, such as
   `varlatch-backups-YOURNAME`. Record its **S3 endpoint** and bucket name.
2. Create `varlatch-backup-upload` restricted to that bucket and the filename
   prefix `production/`, with the exact **writeFiles** capability. Use the B2
   CLI below; the GUI's Write Only preset is broader than the scheduled job
   needs. Never configure Varlatch with the account's master key.
3. Create `varlatch-backup-verify` for the same bucket and prefix, with
   **readFiles** access. Keep it separately; scheduled uploads do not need it.
4. Save each key ID and application key in a password manager when displayed.
   The application key cannot be retrieved again. Do not paste secrets into
   chat, source control, command arguments, or the destination configuration.

See Backblaze's [bucket quickstart](https://www.backblaze.com/docs/cloud-storage-developer-quick-start-guide)
and [application-key instructions](https://www.backblaze.com/docs/cloud-storage-create-and-manage-app-keys).
Install the [official B2 CLI](https://www.backblaze.com/docs/cloud-storage-command-line-tools)
on your operator workstation and run `b2 account authorize` interactively using
an account credential authorized to create keys. Keep that administrative
credential off the scheduled-backup host. Then run:

```sh
b2 key create --bucket YOUR-BUCKET --name-prefix production/ varlatch-backup-upload writeFiles
b2 key create --bucket YOUR-BUCKET --name-prefix production/ varlatch-backup-verify readFiles
```

These commands display each new key ID and secret once: save the output
privately. [B2's capability mapping](https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys)
confirms that `writeFiles` covers uploads and multipart completion/abort;
deletion requires the separate `deleteFiles` permission. This uploader addresses
a known bucket and object, so it does not need bucket/object listing rights.
Upload-only credentials are not immutable storage: consider Object Lock
separately after validating your retention needs.

## Store credential files on the operator host

These are example paths, not files that Varlatch creates automatically:

```sh
install -d -m 700 "$HOME/.config/varlatch-backup"
```

Use a local editor to create `s3-write.json` in that directory:

```json
{
  "accessKeyId": "YOUR_UPLOAD_KEY_ID",
  "secretAccessKey": "YOUR_UPLOAD_APPLICATION_KEY"
}
```

Use the same JSON shape for `s3-read.json`, with the separate read key. Set
both files to mode 0600. Keep the read file on the recovery operator's machine
or supply it only when verifying; Varlatch never saves it as a destination.
The S3 keys authorize access to storage. They are **not** the Backup Encryption
Key (BEK) or Root KEK. Preserve off-host copies of those encryption keys through
separate custody channels as described in the [recovery runbook](backup.md).

## Configure Varlatch

Create `backup-destinations.json` in the actual installation's Compose
directory. Replace every placeholder, including the absolute credential path:

```json
{
  "offsite": {
    "endpoint": "https://s3.YOUR-REGION.backblazeb2.com",
    "region": "YOUR-REGION",
    "bucket": "YOUR-BUCKET",
    "prefix": "production/",
    "forcePathStyle": true,
    "writeCredentialsFile": "/ABSOLUTE/PATH/s3-write.json"
  }
}
```

Copy the endpoint from B2 rather than guessing it. The region is the segment
between `s3.` and `.backblazeb2.com`. Do not put `~` in the credential path.
The Compose directory must describe the running installation, not a fresh
checkout or disposable test installation.

Follow the [S3 create and remote verify commands](backup.md#s3-compatible-destinations).
First upload, then verify **that same archive ID** by downloading it with the
read key. Finally download that archive to an isolated recovery host and follow
the fresh-host restore procedure. Keep that rehearsal isolated from production
sync destinations. A successful upload or verification is not a restore test.

Only after the rehearsal, choose a backup schedule and bucket retention policy.
Include an incomplete-multipart-upload expiry rule. Retain both encryption keys
for as long as any archive needs them. Avoid a lifecycle policy that silently
deletes the only recovery point before a replacement has been checked.
The `writeFiles` upload key can also *hide* files, either with `b2_hide_file`
or by re-uploading a name (the previous version becomes hidden), and a
lifecycle rule deletes hidden versions after `daysFromHidingToDeleting`. Keep
that long enough to notice and unhide, e.g. 30 days rather than 1, or enable
Object Lock on the bucket, so a compromised host cannot erase archives
through the lifecycle.

Safe details to share when asking for setup help: bucket name, endpoint, region,
Compose directory, and credential-file paths. Never share the file contents.
