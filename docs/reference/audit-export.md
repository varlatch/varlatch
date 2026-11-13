# Audit export

An organization's audit log lives in the installation's database. Whoever
runs the host can, in the worst case, change or remove it there. The audit
export keeps a copy in an S3-compatible bucket you control. **With Object
Lock retention in compliance mode**, nobody on the Varlatch side can delete
or shorten what was delivered: not whoever holds the export's key, not the
host operator, not us. Without retention, or in governance mode, the copy
is only as safe as the bucket's own permissions (see
[Before you start](#before-you-start)).

Every audit event of the organization is copied once, in order. The export
runs every minute and writes up to 20 objects per run, so a healthy export
is usually a minute or two behind; a backfill of a long log, or a
destination that fails, takes longer, and the Security page shows how far
behind it is. Nothing is filtered: a filtered copy could not show that
something did not happen. Events without an organization (failed sign-ins,
installation events) belong to none and are not exported.

Nothing changes for an organization until an admin sets up an export.

## What it guarantees, and what it does not

- **It keeps what was delivered** for its retention, against everyone,
  when retention is set in compliance mode. Governance mode can be bypassed
  by accounts allowed to; with no retention, whoever can delete objects in
  the bucket can delete the copy.
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
  Lock** enabled (which needs versioning).
- **Choose the retention deliberately.** The dashboard proposes compliance
  for 400 days; the CLI sets **no retention, and so no Object Lock**, unless
  you pass `--retention <mode>:<days>`. Compliance for at least 400 days is
  what we recommend for evidence that must survive the host.
- **Compliance retention cannot be undone.** Every object the export writes
  is locked for the whole period, nobody can delete it early (the bucket
  owner and the provider's own support included), and you pay to store it.
  That covers every object, not only the batches: the probe objects of each
  check, each stream's `stream.json`, and the hourly heartbeats. Try a
  destination with `governance:1` first; once the copy looks right, raise
  it to compliance, which needs no approval.
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

In object names below, `<organization>` is the organization's **id**
(`org_…`), not its slug: `varlatch audit-export show --json` prints it as
`export.organizationId`.

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
   `s3:ListBucket` to this key.
3. Use the endpoint `https://s3.<region>.amazonaws.com`, the region, the
   bucket, and the prefix (`acme/` above, or none), without path-style
   addressing.

Temporary credentials (STS) are not supported: the key must stay valid.

### Backblaze B2

1. Create a private bucket with **Object Lock** enabled, and record its S3
   endpoint (`https://s3.<region>.backblazeb2.com`) and region.
2. Create an application key restricted to the bucket and the name prefix,
   using the
   [official B2 CLI](https://www.backblaze.com/docs/cloud-storage-command-line-tools)
   on your own workstation. These are the capabilities Varlatch's own
   requests use: writing a file with its retention, and, for the optional
   read rights, reading a file's metadata and its retention.

   ```sh
   b2 key create --bucket acme-audit --name-prefix acme/varlatch-audit/ varlatch-audit-export writeFiles,writeFileRetentions
   ```

   Add `readFiles,readFileRetentions` to let Varlatch verify Object Lock and
   compare existing objects. Do not add `deleteFiles` or
   `bypassGovernance`.
3. **Check the key before you save the export:** run `varlatch audit-export
   check` with it (see [Set it up](#set-it-up)), or **Check** in the
   dashboard's setup. We have not run this minimal key against B2 ourselves.
   If B2 refuses it (`AccessDenied` in the check's answer), B2's S3 API may
   want more for a key restricted to one bucket: add `listBuckets` (and
   `readBuckets` if it still refuses), create the key again, and check
   again. Neither lets the key delete anything.
4. Use the bucket's S3 endpoint and region, the bucket, and the prefix
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
**Set up audit export**. With the CLI, the secret access key never goes on
the command line: pass it on standard input (`--secret-stdin`) or in a file
(`--secret-file <path>`). Without either, the CLI asks for it with a hidden
prompt, which only works in a terminal; scripts and
[assisted mode](assisted-mode.md) need one of the two flags.

```sh
# Check first: nothing is saved.
varlatch audit-export check --endpoint https://s3.eu-central-1.amazonaws.com --region eu-central-1 \
  --bucket acme-audit --prefix acme/ --access-key-id AKIA... --secret-file ~/audit-export.secret \
  --retention governance:1

# Then create it, here with the secret on standard input.
varlatch audit-export create --endpoint https://s3.eu-central-1.amazonaws.com --region eu-central-1 \
  --bucket acme-audit --prefix acme/ --access-key-id AKIA... --secret-stdin --retention governance:1 \
  < ~/audit-export.secret

varlatch audit-export show            # --json for scripts
```

By default the export starts with the whole audit log (a backfill), then
copies each new event. `--from now` (or "Now" in the dashboard) starts at
its own creation instead.

Later changes, each named in [Changes and approvals](#changes-and-approvals):

```sh
varlatch audit-export change --retention compliance:400     # stronger: no approval
varlatch audit-export change --no-retention                 # weaker: your approval
varlatch audit-export change --bucket acme-audit-2          # a new destination: your approval
varlatch audit-export change --access-key-id AKIA... --secret-stdin < ~/new.secret   # a new key: your approval
varlatch audit-export check                                 # the export's own destination and key
varlatch audit-export remove --confirm acme                 # your approval
```

## What the check does

The check runs before an export is saved, before a destination change is
saved, and whenever you ask for it (`varlatch audit-export check`, or
**Check destination**). It writes a few bytes under
`<prefix>varlatch-audit/<organization>/probe/` and:

1. writes a test object, with the retention headers when retention is set;
2. writes the same name again with `If-None-Match: *`, which must be refused
   (HTTP 412). A destination that overwrites is refused with: "This
   destination overwrote an existing object; audit export needs conditional
   writes (If-None-Match)";
3. reads the object's metadata (HEAD). If the key may, the object must carry
   the SHA-256 Varlatch wrote, or the check fails; if the key may not, the
   key is write-only, which is fine;
4. with retention set, reads the retention back if the key may. It must be
   at least what was asked: the same mode (or compliance where governance
   was asked) and a retain-until date no earlier than requested. A weaker
   retention, or none, fails the check, whatever the provider.

The probe objects stay, under the retention the check asked for: a few
bytes each, but in compliance mode they cannot be removed before their date
either. The check never saves anything else.

**About the retain-until date:** a provider may store it to the second,
dropping the milliseconds, and the check accepts that. A provider that
rounds the date more coarsely than a second (to the minute, say) would fail
the check, because its date would be earlier than requested. No such
provider is known; if you meet one, please tell us.

## Watch the heartbeat

Each hour the export writes a heartbeat object,
`<prefix>varlatch-audit/<organization>/<stream>/heartbeat/<yyyy-mm-ddThh>.json`,
with the position it delivered up to and the organization's latest
position at that time. **No new heartbeat for two hours means the export
stopped**, whoever stopped it. The Security page shows the last heartbeat
too, but a stopped installation cannot tell you it stopped: the bucket can.

Watch it from somewhere the host operator does not control, with a key of
your own that can only list names under the organization's part of the
prefix. Scope everything to the organization's id: several organizations
may share a prefix, and a healthy one must not hide a stopped one. On AWS,
the watching key's policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:ListBucket",
    "Resource": "arn:aws:s3:::acme-audit",
    "Condition": { "StringLike": { "s3:prefix": "acme/varlatch-audit/org_0123456789abcdef/*" } }
  }]
}
```

On B2: `b2 key create --bucket acme-audit --name-prefix
acme/varlatch-audit/org_0123456789abcdef/ varlatch-audit-watch listFiles`.

Then, every hour or so, list each stream's heartbeats newer than two hours
ago. This reads only names, and only the heartbeats of the last two hours,
never the batches (GNU `date`; the AWS CLI shown, any S3 client works):

```sh
BUCKET=acme-audit
BASE=acme/varlatch-audit/org_0123456789abcdef/   # the organization's id, not its slug
SINCE=$(date -u -d '2 hours ago' +%Y-%m-%dT%H)
FOUND=0
for STREAM in $(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$BASE" --delimiter / \
                  --query 'CommonPrefixes[].Prefix' --output text); do
  [ "$STREAM" = None ] && continue   # no stream yet
  COUNT=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "${STREAM}heartbeat/" \
            --start-after "${STREAM}heartbeat/${SINCE}.json" --query 'length(Contents || `[]`)')
  FOUND=$((FOUND + COUNT))
done
[ "$FOUND" -gt 0 ] || echo "No audit export heartbeat for two hours: the copy stopped" >&2
```

A new stream (after a destination change, a restore, or a restart) is a new
`<stream>/` under the same base, so the loop finds it without changes.

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

Every one of these carries the export's retention when it was written.

Positions are installation-wide, so one organization's have gaps. A new
stream starts after a destination change, a backup restore, or a restart
of a pending object that could no longer be written. Nothing is ever
overwritten; to read the whole history, take every stream in order and
drop events whose position you already have.

## Changes and approvals

| Change | Approval |
|---|---|
| Set up an export | none |
| Set retention where there was none, lengthen it, or governance to compliance | none |
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
  not checked when saved: check it first with `varlatch audit-export check`,
  giving the export's destination options (`--endpoint`, `--region`,
  `--bucket`, `--prefix`) and `--access-key-id <id> --secret-stdin`. What
  the key may read is then shown as "not determined": the next time a write
  finds its name taken, Varlatch learns whether the key can read objects;
  whether it can read retention is only learnt at the next destination
  change.
- **Removal** stops the copy and clears the key from the installation.
  What was delivered stays in the bucket.

**Coding agents.** What needs no approval can be done by anyone holding a
person's CLI credential with `organization.manage`, a coding agent included,
in [assisted mode](assisted-mode.md) or not:

- **setting up an export** to a bucket of its choosing. The audit log holds
  who did what and when, never values;
- **strengthening retention:** setting it where there was none, lengthening
  it, or governance to compliance, for example `varlatch audit-export change
  --retention compliance:3650`. In compliance mode that cannot be undone:
  every object written from then on stays, and is paid for, for ten years.

A new destination, a new key, a shorter or removed retention, compliance to
governance and removal always need the person's passkey approval, which an
agent cannot give. `varlatch audit-export remove` also needs `--confirm
<organization>` in every mode; in assisted mode the agent adds it only
after the person agreed, and otherwise prints the command for the person's
own terminal. If an agent should not be able to do the first two, do not
let it work with a credential that holds `organization.manage`.

## When the organization is deleted

The final audit events (`organization.deleted` and the memberships that
end) are written when the deletion is finalized, after its waiting period,
in the same step that destroys the organization's key. So that the bucket
gets them, the export's key, and only that key, is encrypted again under
the installation's root key at that moment, and the export keeps
delivering. Once the final events are delivered, the key is cleared. If
that has not happened **30 days after the deletion was finalized**, the key
is cleared anyway and the export is abandoned; the people who could read
the audit log can still export it with `varlatch audit export --deleted-org
<organization-id>`. The deletion confirmation says this when an export
exists.

With the installation switch off (below), nothing is delivered after the
deletion either: the final events never reach the bucket, and the key is
cleared at the 30-day deadline.

## For the host operator

- **`VARLATCH_AUDIT_EXPORT=off`** turns audit export off on the whole
  installation: nothing is delivered, and no export can be set up or
  changed; organizations see that the host operator stopped it, and can
  still remove theirs. It is on by default. See
  [Configuration](../self-hosting/configuration.md#varlatch_audit_export).
  A deleted organization's export key is still cleared at its deadline, but
  its final events are not delivered.
- **A destination on a private network** (a MinIO on the LAN, a tailnet)
  needs an entry in `VARLATCH_OUTBOUND_ALLOW`.
- **A pending object whose retention date is too close.** An object is
  planned with its retain-until date before it is written; if a long
  outage brings that date within one hour, the object is not written.
  The export starts a new stream on its own, from what was delivered, and
  records it (`audit_export.stream_started`, reason `plan_expired`).
- **A pending object in a format this release cannot write** (it was
  planned by another release) stops the export, with a message on the
  Security page. Finish it with the release that planned it, or run
  `varlatchd admin audit-export discard-plan --export <id> --reason
  unsupported-format`. The export's id (`aex_…`) is `export.id` in the
  organization's `varlatch audit-export show --json`. The command refuses a
  pending object it could still write, so it can never skip events; with
  `--reason expired` it does by hand what the export does on its own for a
  date that is too close.
- `varlatchd admin security reset` does not touch exports.
