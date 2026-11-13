# Audit export

An organization's audit log lives in the installation's database. Whoever
runs the host can, in the worst case, change or remove it there. The audit
export keeps a copy in an S3-compatible bucket you control, with Object
Lock retention that nobody on the Varlatch side can shorten: not whoever
holds the export's key, not the host operator, not us.

Every audit event of the organization is copied once, in order, within
about a minute. Nothing is filtered: a filtered copy could not show that
something did not happen. Events without an organization (failed sign-ins,
installation events) belong to none and are not exported.

Nothing changes for an organization until an admin sets up an export.

## What it guarantees, and what it does not

- **It keeps what was delivered** for its retention, against everyone,
  when the bucket has Object Lock in compliance mode. Governance mode can be
  bypassed by accounts allowed to.
- **It does not guarantee delivery.** Events not yet exported when a host is
  compromised can be removed from the database first. The export runs every
  minute, so that window is short, not zero.
- **It does not stop the host operator** from stopping the export (the
  installation switch, the process, the database row, the key). The hourly
  heartbeat makes a stop visible at the bucket: see
  [Watch the heartbeat](#watch-the-heartbeat). Watching it is the bucket
  owner's job; Varlatch cannot do it for you.
- **The copy is only independent** if people other than the host operator
  control the bucket's account, and if it is not the backup destination.
  Varlatch cannot check either.

## Before you start

- A bucket in an account the host operator does not control, with **Object
  Lock** enabled (which needs versioning). Use **compliance** mode for at
  least **400 days** unless you have a reason not to.
- A key that can **write objects and set their retention** under one
  prefix, and nothing else: no delete, no list. Reading is optional: with a
  key that can read, Varlatch compares an existing object's checksum when a
  write finds its name taken, and reads the retention back to verify Object
  Lock (see [What the check does](#what-the-check-does)).
- The provider must refuse to overwrite an existing object when asked
  (conditional writes, `If-None-Match: *`). Varlatch checks this before it
  saves anything, and refuses a destination that overwrites.
- `organization.manage` in the organization, and a person's sign-in:
  machine credentials can never set up or change an export.

### AWS S3

1. Create the bucket with Object Lock enabled, for example
   `aws s3api create-bucket --bucket acme-audit --region eu-central-1
   --create-bucket-configuration LocationConstraint=eu-central-1
   --object-lock-enabled-for-bucket`. Versioning is turned on with it.
2. Create an IAM user (or a role you can mint a static key for) with this
   policy, and an access key for it. Replace the bucket and prefix:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["s3:PutObject", "s3:PutObjectRetention"],
       "Resource": "arn:aws:s3:::acme-audit/acme/varlatch-audit/*"
     }]
   }
   ```

   To let Varlatch verify Object Lock and compare existing objects, add
   `s3:GetObject` and `s3:GetObjectRetention` on the same resource. Never
   grant `s3:BypassGovernanceRetention`, `s3:DeleteObject` or
   `s3:ListBucket`.
3. Use the endpoint `https://s3.<region>.amazonaws.com`, the region, the
   bucket, and the prefix (`acme/` above, or none), without path-style
   addressing.

Temporary credentials (STS) are not supported: the key must stay valid.

### Backblaze B2

1. Create a private bucket with **Object Lock** enabled, and record its S3
   endpoint (`https://s3.<region>.backblazeb2.com`) and region.
2. Create an application key restricted to the bucket and the name prefix,
   with the capabilities to write files and set their retention, using the
   [official B2 CLI](https://www.backblaze.com/docs/cloud-storage-command-line-tools)
   on your own workstation:

   ```sh
   b2 key create --bucket acme-audit --name-prefix acme/varlatch-audit/ varlatch-audit-export writeFiles,writeFileRetentions
   ```

   Add `readFiles,readFileRetentions` to let Varlatch verify Object Lock and
   compare existing objects. Do not add `deleteFiles` or
   `bypassGovernance`.
3. Use the bucket's S3 endpoint and region, the bucket, and the prefix
   (`acme/` above). Path-style addressing works with B2.

### Other providers

Any S3-compatible store that honours conditional writes and Object Lock
headers can be used. Varlatch treats AWS S3 and Backblaze B2 as verified
providers (recognised by their endpoints): a write with lock headers that
succeeds there means the lock was applied. Elsewhere, the Security page says
"lock headers accepted, not verified for this provider" unless the key can
read the retention back, which verifies it anywhere. A MinIO or other store
on your LAN, a Docker network or a tailnet needs the host operator's
outbound allow list (`VARLATCH_OUTBOUND_ALLOW`, see
[Outbound policy](outbound-policy.md)).

## Set it up

In the dashboard: the organization's **Security** page, **Audit export**,
**Set up audit export**. Or with the CLI, which reads the secret access key
from standard input, a file or a hidden prompt, never from the command line:

```sh
varlatch audit-export check --endpoint https://s3.eu-central-1.amazonaws.com --region eu-central-1 \
  --bucket acme-audit --prefix acme/ --access-key-id AKIA... --retention compliance:400
varlatch audit-export create --endpoint https://s3.eu-central-1.amazonaws.com --region eu-central-1 \
  --bucket acme-audit --prefix acme/ --access-key-id AKIA... --retention compliance:400
varlatch audit-export show
```

By default the export starts with the whole audit log (a backfill), then
copies each new event. `--from now` (or "Now" in the dashboard) starts at
its own creation instead.

## What the check does

The check runs before an export is saved, before a destination change is
saved, and whenever you ask for it (`varlatch audit-export check`, or
**Check destination**). It writes a few bytes under
`<prefix>varlatch-audit/<organization>/probe/` and:

1. writes a test object, with the retention headers when retention is set;
2. writes the same name again with `If-None-Match: *`, which must be refused
   (HTTP 412). A destination that overwrites is refused: "this destination
   overwrote an existing object; audit export needs conditional writes";
3. reads the object's metadata (HEAD). If the key may, the object must carry
   the SHA-256 Varlatch wrote, or the check fails; if the key may not, the
   key is write-only, which is fine;
4. with retention set, reads the retention back if the key may. It must be
   at least what was asked: the same mode (or compliance where governance
   was asked) and a retain-until date no earlier than requested. A weaker
   retention, or none, fails the check, whatever the provider.

The probe objects stay: Object Lock may keep them, and they are a few bytes.
The check never saves anything else.

**About the retain-until date:** a provider may store it to the second,
dropping the milliseconds, and the check accepts that. A provider that
rounds the date more coarsely than a second (to the minute, say) would fail
the check, because its date would be earlier than requested. No such
provider is known; if you meet one, please tell us.

## Watch the heartbeat

Each hour the export writes a heartbeat object:
`<prefix>varlatch-audit/<organization>/<stream>/heartbeat/<yyyy-mm-ddThh>.json`,
with the position it delivered up to and the organization's latest
position at that time. **No new heartbeat for two hours means the export
stopped**, whoever stopped it. Set up a check of your own, with a read key
for the bucket that the host operator does not hold. For example, with the
AWS CLI:

```sh
aws s3 ls s3://acme-audit/acme/varlatch-audit/ --recursive | grep /heartbeat/ | sort | tail -1
```

The Security page shows the last heartbeat too, but a stopped installation
cannot tell you it stopped: the bucket can.

## What is in the bucket

Under `<prefix>varlatch-audit/<organization>/<stream>/`:

- `stream.json`: where the stream starts, the stream before it, why it
  started (`created`, `restored`, `destination_changed`, `plan_expired`,
  `plan_discarded`), and, after a restart, a range of positions an earlier
  stream may hold too;
- `<first>-<last>.ndjson.gz`: batches of up to 1,000 events, gzipped NDJSON.
  The first line is a header (the positions it holds, and the last position
  of the batch before it, so a missing object shows); then one event per
  line, as `varlatch audit export` and webhooks write them, with its
  position;
- `heartbeat/`: the hourly heartbeats.

Positions are installation-wide, so one organization's have gaps. A new
stream starts after a destination change, a backup restore, or a restart
of a pending object that could no longer be written. Nothing is ever
overwritten; to read the whole history, take every stream in order and
drop events whose position you already have.

## Changes and approvals

| Change | Approval |
|---|---|
| Set up an export | none |
| Lengthen retention, governance to compliance, set retention | none |
| A new endpoint, region, bucket, prefix or addressing | always |
| A new key | always |
| Shorten or remove retention, compliance to governance | always |
| Remove the export | always |

"Always" means the approval of the person asking, with a trusted passkey,
whatever the organization's [security controls](security-controls.md) say.
A change that loosens one field and tightens another needs it. Changes are
refused while the organization is frozen for an incident or being deleted;
the copy keeps going meanwhile.

- **A new destination** starts a new stream at the current position. The
  new bucket gets no history; the old one keeps what it received.
- **A new key** keeps the stream and any object waiting to be written. It is
  not checked when saved: check it first with `varlatch audit-export check
  --access-key-id ...`. What the key may read is then shown as "not
  determined": the next time a write finds its name taken, Varlatch learns
  whether the key can read objects; whether it can read retention is only
  learnt at the next destination change.
- **Removal** stops the copy and clears the key from the installation.
  What was delivered stays in the bucket.

**Coding agents and creation.** Creating an export needs no approval, by
design: it only adds a copy. So a coding agent working with a person's CLI
credential, in [assisted mode](assisted-mode.md) or not, can set up an
export to a bucket of its choosing for an organization where that person
has `organization.manage`. The audit log holds who did what and when,
never values. Changing or removing an export always needs the person's
passkey approval, which an agent cannot give. `varlatch audit-export
remove` also needs `--confirm <organization>` in every mode; in assisted
mode the agent adds it only after the person agreed, and otherwise prints
the command for the person's own terminal.

## When the organization is deleted

The final audit events (`organization.deleted` and the memberships that
end) are written when the organization's key is destroyed. So that the
bucket gets them, the export's key, and only that key, is encrypted again
under the installation's root key at that moment, and the export keeps
delivering. Once the final events are delivered, the key is cleared. If
that has not happened 30 days after the deletion, the key is cleared anyway
and the export is abandoned; the people who could read the audit log can
still export it with `varlatch audit export --deleted-org
<organization-id>`. The deletion confirmation says this when an export
exists.

## For the host operator

- **`VARLATCH_AUDIT_EXPORT=off`** turns audit export off on the whole
  installation: nothing is delivered, and no export can be set up or
  changed; organizations see that the host operator stopped it, and can
  still remove theirs. It is on by default. See
  [Configuration](../self-hosting/configuration.md#varlatch_audit_export).
  Turning it off does not end a deleted organization's 30 days early or late.
- **A destination on a private network** (a MinIO on the LAN, a tailnet)
  needs an entry in `VARLATCH_OUTBOUND_ALLOW`.
- **A pending object that can no longer be written** (its retention date
  passed during a long outage, or it was planned by a release in a format
  this one cannot write) stops the export with a message on the Security
  page. An expired one restarts on its own in a new stream. For a format
  this release cannot write, run `varlatchd admin audit-export
  discard-plan --export <id> --reason unsupported-format`, or finish it with
  the earlier release. The command refuses any other case, so it can never
  skip events.
- `varlatchd admin security reset` does not touch exports.
