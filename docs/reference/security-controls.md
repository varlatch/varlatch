# Security controls and approvals

Security controls are optional protections an organization can turn on.
They all start **off**, on new and upgraded installations alike: with every
control off, Varlatch works exactly as it did before they existed (see
[Off by default](#off-by-default)).

This page covers the controls, their modes, how to turn them on safely, how
a change is approved with your passkey, and the way back for whoever runs
the server.

At a glance:

| Control | With `enforce` | `report` counts | The way back |
| --- | --- | --- | --- |
| [`requirement-protection`](#requirement-protection) | Editing or removing a Tailnet Requirement needs the approval of the person asking; a machine credential is refused. | each edit or removal | [reset](#the-way-back-the-host-operators-reset) `--control requirement-protection` |
| [`admin-step-up`](#admin-step-up) | Each of [40 administrative operations](#what-report-mode-counts) needs the approval of the person asking; a machine credential is refused. | each such operation | reset `--control admin-step-up` |
| [`passkey-verification`](#passkey-verification) | A person's request to the organization is refused unless their sign-in was made with a trusted passkey that verified them. | each such request, per person and reason | `admin reenroll`, or reset `--control passkey-verification` |
| [`credential-lifetime`](#credential-lifetime) | Machine credentials get a default lifetime and none above a maximum. | would-default and would-refuse | reset `--control credential-lifetime` |

## Off by default

- **Every control is off** on every installation and in every
  organization, new ones included. Installing, upgrading, a setting or an
  environment variable never turns one on: only an admin of the
  organization does, on its Security page or with `varlatch security set`.
  A release that can enforce a control changes no mode either.
- **With every control off, nothing changes.** Every request is allowed
  or refused as before, with the same answer; credentials are issued with
  the lifetime asked for, or none; no approval is asked for that was not
  asked for before; nothing is counted; and nothing that worked before
  records a new audit event (confirming a passkey, which is new, records
  `authentication.passkey_confirmed`). The test suite checks this route by
  route: with every control off, each route's answer and the tables it
  changes must match a recorded baseline.
- **What exists regardless of the modes**, so that turning a control on
  later has something to rely on:
  - each passkey's provenance (trusted or unconfirmed, see [Trusted
    passkeys only](#trusted-passkeys-only)) and, for each sign-in, whether
    the passkey verified the person and which passkey it was;
  - the dashboard removes passkeys through Varlatch's
    `DELETE /v1/me/passkeys/{id}` instead of Better Auth's own endpoint,
    which is turned off; with no control enforced anywhere you belong, it
    behaves as before;
  - the read-only views: the [Security page](#the-security-page),
    `varlatch security status`, `varlatch security report`, machine reach,
    and the `Varlatch-Credential-Expires` header with the CLI's expiry
    warning on stderr;
  - `security.enforce.<control>` in `GET /v1/meta` and `enforce` in each
    control's `availableModes`.
- **Approvals that do not depend on a control.** Turning a control down
  needs an approval whatever its mode, and so does lengthening or clearing
  the lifetimes `credential-lifetime` keeps while it is off (it keeps them
  when turned off without `--clear-config` or by the operator's reset, or
  saved while it was off: `security set credential-lifetime off
  --default-ttl <s> --max-ttl <s>` is tightening and needs no approval).
  Lifting an [incident freeze](incident-freeze.md) always needs one, and so do the changes that weaken an [audit
  export](audit-export.md). These exist only once someone turns a control
  on, freezes the organization or creates an export.

## Turning controls on

Turn one control on at a time, in `report` first:

1. **Make sure every admin has a trusted passkey.** The Security page's
   approval keys show, per admin, which passkeys are trusted. Only a
   trusted passkey can approve, and once a control is enforced, turning it
   back down needs an approval. Confirm unconfirmed passkeys first (see
   [Trusted passkeys only](#trusted-passkeys-only)).
2. **Set the control to `report`** (`varlatch security set <control>
   report`). Nothing is refused or changed.
3. **Let the organization work as usual** for long enough to cover what
   runs rarely: CI pipelines, deploys, scheduled jobs, the people who sign
   in once a week.
4. **Read the counts** on the Security page or with `varlatch security
   status --json`. Each count is a request that `enforce` would have
   refused or asked an approval for (see [What report mode
   counts](#what-report-mode-counts)). The reason `machine-credential`
   marks automation that will stop.
5. **Set it to `enforce`** once you know who and what it will stop. Keep
   the [host operator's reset](#the-way-back-the-host-operators-reset) in
   mind as the way back.

> **Before enforcing `passkey-verification`, check in report mode that
> your sign-ins record user verification.** This control refuses every
> request of a person whose sign-in did not verify them, admins included,
> and a person whose passkeys cannot verify them gets back in only through
> whoever runs the server.
>
> 1. `varlatch security set passkey-verification report`.
> 2. Ask every member to sign in again, in the dashboard and with
>    `varlatch login`, with the passkey they will use from now on, and to
>    use the organization as usual. Sign-ins made before Varlatch recorded
>    user verification count as `no-evidence` until then.
> 3. Read `passkey-verification`'s counts per person and reason. Every
>    person counted would be refused:
>    - `not-user-verified`: their authenticator signed them in without a
>      PIN, fingerprint or face (`userVerified` false), for example a
>      security key without a PIN. Set one up, or use another passkey, and
>      sign in again;
>    - `untrusted-passkey`: confirm that passkey with a trusted one;
>    - `no-evidence`: sign in again; a credential issued without a passkey
>      sign-in (`admin bootstrap`, `admin recover --cli-credential`) never
>      qualifies, so replace it with `varlatch login`.
> 4. Enforce only when every person who needs access has made requests
>    since signing in again and none of them is counted. The counts are a
>    lower bound: someone who made no request is not counted at all, and
>    access counts are best-effort.
>
> Turning it on from your own sign-in is refused when that sign-in would
> not qualify, so you cannot lock yourself out by saving it; other people
> can be locked out, which is what report mode shows first.

## The controls

Each organization has four controls:

| Control | What it is about |
| --- | --- |
| `requirement-protection` | Editing or revoking a tailnet requirement. |
| `admin-step-up` | Administrative changes: machine identities and their credentials, grants, roles, groups and teams, admins, integrations, deletion, and `.env` export. |
| `passkey-verification` | People's access with a sign-in by a trusted passkey that verified them with a PIN, fingerprint or face. |
| `credential-lifetime` | Expiry of machine credentials: a default lifetime and a maximum, in seconds (`0 < default <= maximum`). |

Each control has a mode:

- **`off`**: no effect. The default.
- **`report`**: nothing is refused and nothing changes. Each time the
  control would have refused a request, asked for an approval or changed
  an outcome, Varlatch counts it, so you can see what turning it on would
  do before you decide (see [What report mode counts](#what-report-mode-counts)).
- **`enforce`**: the control applies. **This release offers `enforce`
  for all four controls** (see [Requirement
  protection](#requirement-protection), [Credential
  lifetime](#credential-lifetime), [Passkey
  verification](#passkey-verification) and [Admin
  step-up](#admin-step-up)). Offering it changes no default: every
  control stays off until an admin turns it on. A release says which
  controls it can enforce: each control's `availableModes`, and the
  capability `security.enforce.<control>` in `GET /v1/meta`. Nothing
  changes this at runtime. A server that cannot enforce a control refuses
  `enforce` for it with `CONTROL_MODE_UNAVAILABLE`, and the dashboard
  shows it as coming in a later release.

A control's state has a version that goes up by one with every change. A
control nobody has changed is off at version 0.

## Seeing and changing them

In the dashboard, open the organization's **Security** page (see [The
Security page](#the-security-page)). With the CLI:

```sh
varlatch security controls            # each control, its mode, lifetimes, version, last change
varlatch security set admin-step-up report
varlatch security set requirement-protection enforce
varlatch security set credential-lifetime report --default-ttl 86400 --max-ttl 2592000
varlatch security set credential-lifetime enforce        # keeps the lifetimes it has
varlatch security set credential-lifetime report --max-ttl 604800   # keeps the default
varlatch security set credential-lifetime off --clear-config
```

Add `--json` for one JSON document, `--org` to name another organization.
`security set` reads the control's current version and sends it with the
change; a change made by someone else meanwhile is refused with
`VERSION_CONFLICT`, and nothing changes.

Who may do what:

- **Reading** needs `organization.read`, so members see what applies to
  them.
- **Changing** needs `organization.manage` (organization admins have it)
  and a person's sign-in: the dashboard or the CLI. A machine credential
  can never change a control, whatever its grants.

## The Security page

Each organization has a **Security** page in the dashboard, next to
Settings, at `/o/<organization>/security`. It is the place to decide
which controls to turn on: try one in `report`, watch what it counts for
a while, then decide. Every control is off until an admin changes it.
`enforce` is offered for the controls this server can enforce and shown
as coming in a later release for the others.

At the top it shows the organization's [incident
freeze](incident-freeze.md) (freeze it, or the freeze in force) and which
controls are on. Then seven sections, each shown to whoever may read it
(see "Who sees what" below):

- **Controls.** Each control with its mode, what `report` counts and what
  `enforce` would change, and its counts of the last 30 days per
  operation, reason and person or machine. The current hour is live; the
  page refreshes it every minute. Admins change the mode here (and the
  lifetimes of `credential-lifetime`); turning a control down or off asks
  for your approval in a dialog (see [Approvals](#approvals)).
- **Approval keys.** For each admin of the organization, how many of
  their passkeys are trusted and how many unconfirmed, by name. Only a
  trusted passkey can approve, so an admin without one cannot turn a
  control down. Its owner confirms a passkey under **Account**,
  **Security**; with no trusted passkey left, whoever runs the server can
  send a link that enrolls one (`varlatch admin reenroll --identity
  <id>`). No key material is ever shown.
- **Machine credentials.** The credential review: machine credentials
  never used, unused for 30 days, or without expiry, and the service
  credentials that expire within 7 days or have expired. Revoke or replace
  them in **Access**, **Machines**. Nothing is revoked automatically.
- **Refused destinations.** The webhooks, connections and OIDC issuers
  this installation's [outbound policy](outbound-policy.md) refuses, so
  their deliveries and checks fail.
- **Audit export.** The organization's [audit export](audit-export.md),
  on a server that offers it (capability `audit.storage-export`).
- **Tailnet Requirements.** How many there are, with a link to their
  editor (**Access**, **Advanced**) and the mode of
  `requirement-protection`, which protects them.
- **Checklist.** A few things worth doing whatever the controls say, each
  linked to its page in these docs: report mode (this page), trusted
  passkeys ([Your passkeys](passkeys-and-sessions.md#your-passkeys)),
  finding copies of secrets ([`varlatch scan
  --find-files`](secret-scanning.md#finding-copies-of-secrets)), backups
  the host cannot erase ([Object
  Lock](../operations/backup.md#scoping-destination-credentials-per-provider)),
  and the [threat model](../THREAT-MODEL.md).

Who sees what: every member sees the controls and their modes
(`organization.read`). The counts, the approval keys, the refused
destinations and the audit export need `organization.manage`, the credential review
`identity.manage`, and the requirements `policy.read`; organization admins hold all of them, and a
grant can give any of them to someone else. The page first asks the
server which of these you hold (`GET
/v1/organizations/{org}/me/permissions`) and shows exactly those parts;
for the rest it names what they need. It never asks for what you cannot
read, so visiting it records no refusals in the audit log. If that first
question fails, the page says so and shows nothing it would have to
guess.

The counts say when they were loaded. If loading them fails, the
Controls section says so with a way to retry; if a refresh fails, the
last counts stay, marked as not current. `passkey-verification` counts
only requests that were allowed and succeeded, and access counts are
best-effort (see [What report mode counts](#what-report-mode-counts)), so
its count, zero included, is a lower bound.

The same from the CLI, as text or one JSON document:

```sh
varlatch security status
varlatch security status --json
```

It prints the same parts, grouped and short (the three largest counts
per control; `--json` has all of them), and the freeze in force, if any.
Refused destinations are in `varlatch security report` instead. For machine credentials it gives
two separate lines: the use and expiry policy (never used, unused for 30
days, no expiry) and the expiry warnings (expiring within 7 days or
expired), so a credential that already expired is never hidden behind
"nothing to review". `varlatch security report` starts with the same two
lines. For whoever may manage the organization, `security status` also
prints an "Audit export" section (in JSON, `auditExport`, the last key):
see [Audit export](audit-export.md). Like the page, `security status`
asks the server which parts you may read first, and does not ask for the
others. A part you cannot read, or that
the server does not offer, is named under "Not shown" (in JSON,
`unavailable`, with the reason `not-permitted` or `not-supported`), and
the command still exits 0. It exits 1 only when the server has no
security controls, and fails on any other error. See [Scripting the
CLI](scripting.md) for the JSON fields.

## What report mode counts

In `report` mode a control refuses nothing and changes nothing. Each time
it would have refused a request, asked for an approval, or changed what is
issued, Varlatch adds one to a counter. Only what actually happened is
counted:

- **A change** (a write) is counted in the same database transaction as
  the change, so it is counted only if the change was saved. A request that
  was refused, failed, or changed nothing is not counted: an edit to the
  same values, adding a member or project that is already there,
  reactivating a machine identity that is not retired, or replacing a
  grant with an identical one.
- **An access** (`passkey-verification`) is counted only when the request
  was allowed and succeeded. Someone outside the organization, or a
  request that was refused, is never counted. Access counts are
  best-effort: they are made after the response is sent, so they never
  slow or fail a request, and a count that cannot be made within about a
  second (a busy database, or too many counts waiting in one server
  process) is dropped, and so are counts still waiting when the server
  stops or enters maintenance (a backup or restore). Counts of changes are
  never dropped.

Per control:

| Control | Counted | Reasons |
| --- | --- | --- |
| `requirement-protection` | Editing (`requirement.update`) or revoking (`requirement.revoke`) a tailnet requirement. Creating one is not counted. | `no-approval`, `machine-credential` |
| `admin-step-up` | Each operation below. | `no-approval`, `machine-credential` |
| `passkey-verification` | Each request by a person's dashboard or CLI sign-in to the organization, when that sign-in was not made with a trusted passkey that verified the person (PIN, fingerprint or face). Machine credentials are never counted. | `no-evidence`, `not-user-verified`, `untrusted-passkey` |
| `credential-lifetime` | Issuing a machine credential: creating a machine identity that gets one (`identity.create`) and `credential issue` (`credential.issue`). OIDC and agent-run credentials are not counted. | `would-default`, `would-refuse` |

`admin-step-up` counts these operations:

- machine identities and credentials: `identity.create`,
  `credential.issue`, `identity.reactivate`, `oidc_binding.create`,
  `oidc_binding.delete`;
- access: `grant.create`, `grant.replace`, `grant.revoke`; `role.create`,
  `role.update`, `role.delete`; `group.create`, `group.update`,
  `group.delete`, `group.member_add`, `group.member_remove`;
  `team.create`, `team.update`, `team.delete`, `team.member_add`,
  `team.member_remove`, `team.project_add`, `team.project_remove`;
- people: `member.invite_admin` (an invitation as admin),
  `member.promote`, `member.demote`, `member.remove` (removing someone
  else; leaving an organization yourself is not counted);
- integrations: `webhook.create`, `webhook.update`, `webhook.delete`;
  `connection.create`, `connection.replace_credential`,
  `connection.delete`; `github_app.register`, `github_app.import`,
  `github_app.replace_key`, `github_app.remove`;
- deletion: `project.delete`, `organization.delete` (scheduling it);
- export: `secret.export`, the dashboard's `.env` download (a disclosure
  with the purpose `export`). Reading values and `varlatch run` are not
  counted.

What the reasons mean:

- `no-approval`: a person did it without an approval. With `enforce`,
  these would need one.
- `machine-credential`: a machine credential did it. A machine can never
  give an approval, so with `enforce` it would be refused.
- `no-evidence`: the sign-in recorded no evidence, such as a sign-in from
  before this release. Signing in again records it.
- `not-user-verified`: the passkey did not verify the person.
- `untrusted-passkey`: the passkey that signed in is not trusted (see
  [Trusted passkeys only](#trusted-passkeys-only)).
- `would-default`: no lifetime was given, so the credential would have
  got the default lifetime.
- `would-refuse`: the lifetime asked for is above the maximum, so the
  request would have been refused.

For `passkey-verification`, the operation is the first permission the
request was allowed (for example `project.read` or `secret.reveal`),
`organization.access` for a request allowed without one, or
`convex.token` for the dashboard's realtime token, which counts once for
each organization it covers.

### How counts appear

Counters are kept per organization, control, the control's version,
operation, person or machine, reason and hour (UTC). The version is the
control's version when the request was decided, so counts made before and
after a change of mode or lifetimes stay apart.

- **Live:** the current hour's counters and the counts of the last 30
  days are available from `GET
  /v1/organizations/{org}/security/control-report?days=30` (capability
  `security.report`). It needs `organization.manage`, because it names
  who did what.
- **Summaries:** about 10 minutes after each hour ends, Varlatch writes one
  `security_control.would_block` event to the audit log for each counter
  of that hour: the control, its version, the operation, the person or
  machine, the reason, the hour and the count. Audit events are never
  changed afterwards; a count that arrives late for an hour already
  summarized is added to the current hour.
- **Retention:** counters are deleted 35 days after their summary. The
  summaries stay in the audit log. When an organization is deleted, its
  counters go with it.

### What is stored

Only the fields named above. Never a request body, a URL, a token, a
hash or a value, and no target: a count says "12 grant changes without an
approval by this person", not which grants.

## Tightening and loosening

A change is compared with the current state field by field:

- **Loosening:** the mode moves towards off (`enforce` to `report`,
  `enforce` to `off`, `report` to `off`), a lifetime grows, or the
  lifetimes are cleared. A change that does any of these is loosening,
  even when it also tightens something else.
- **Tightening:** anything else, such as `off` to `report`, or a shorter
  lifetime.

Tightening applies at once. **Loosening needs your approval with a trusted
passkey**, for exactly that change. Otherwise a stolen sign-in could turn a
control off first and then do what it protected against. This holds
whatever the controls' modes are: turning `report` back to `off` already
needs an approval.

Every change is recorded in the audit log as `security_control.changed`,
with the old and new state, whether it loosened the control, and the
approval it used.

Your authority (`organization.manage`) is checked again inside the change,
after the organization is locked. If you lost it meanwhile, the change is
refused and, when the approval was used, it stays unused. While at least
one control is at `report` or `enforce` before the change, the audit log
records one `authorization.denied` for that refusal. With every control
off before the change (so also for `off` to `report` from all off), it
records nothing, as before.

## Approvals

An approval is your passkey, with your PIN, fingerprint or face, saying yes
to one exact change that you asked for.

1. You ask for a loosening change. The server keeps a pending approval for
   exactly that request (the control, the new state, the version it
   expects, and the sign-in that asked) and answers `STEP_UP_REQUIRED`
   with its address, `https://<your server>/approve/<id>`. A server
   without a public URL gives only the approval's id: open
   `/approve/<id>` on the dashboard where you sign in.
2. You open that address in a browser where you are signed in to
   Varlatch. The page shows what the change does, written by the server,
   and how long is left. Approve it with a **trusted** passkey, which must
   verify you, or deny it.
3. The CLI or the dashboard sends the same request again, now carrying the
   approval, and the server makes the change. An approval is used once.

What holds:

- **Only you see your approval.** For anyone else, an organization admin
  included, it does not exist. Only you can approve it, from a dashboard
  session.
- **It covers exactly one request**: the same sign-in, the same change and
  the same version of the control. For the CLI, the sign-in is the CLI
  credential that asked; for the dashboard, the browser session that
  asked, even if the dashboard renewed its access token meanwhile. Another
  session or another CLI sign-in cannot use it, and neither can that
  browser session once it has ended (you signed out, or it expired). Anything else is refused with
  `APPROVAL_INVALID`, and the change is not made. If the control changed
  meanwhile, ask again.
- **It expires** 2 minutes after the dashboard asked for it, or 10 minutes
  after the CLI did. Approving does not extend it.
- **It is used together with the change.** If the change fails, the
  approval stays usable until it expires; once the change is made, the
  approval can never be used again.
- **Limits:** at most 5 open approvals per CLI sign-in or dashboard
  access token, and 30 per person in 10 minutes; past either, the server
  answers `RATE_LIMITED` (429). The CLI checks every 5 seconds; checking
  faster is slowed down, as for a CLI sign-in.
- **A refused use** answers `APPROVAL_INVALID` (409) with
  `error.details.reason`, for example `pending` (not approved yet),
  `expired`, `consumed` (already used), `closed` (cancelled or reset),
  `mismatch` (given for another request), `stale` (the target changed) or
  `session-ended`.

### Trusted passkeys only

Only a **trusted** passkey can approve (see [Your
passkeys](passkeys-and-sessions.md#your-passkeys)). A passkey you added in the
dashboard while signed in is unconfirmed until you confirm it with a
trusted one: someone with a stolen session could add a passkey of their
own, and it must not be able to approve. Signing in still works with any of
your passkeys.

If you have no trusted passkey, you cannot approve anything. Confirm a
passkey with a trusted one under **Account**, **Security**, or ask whoever
runs the server for a link that enrolls a trusted one (`varlatch admin
reenroll --identity <your identity id>`).

### From the dashboard

When you make a loosening change in the dashboard, an approval dialog opens
at once with the same summary. Approve with your passkey and the change is
saved; deny or close it and nothing changes.

### From the CLI

The CLI prints what is asked and the address on stderr, then waits:

```text
This needs your approval with a trusted passkey: Turn off the admin-step-up security control of Acme
  mode: report -> off (loosens)
Open this address in a browser where you are signed in to Varlatch as yourself, check what it says, and approve with a trusted passkey:
  https://vault.example.com/approve/apr_...
It expires at 2026-11-10T12:10:00.000Z. Only you can approve it.
Waiting for your approval (Ctrl-C stops waiting and cancels it)...
```

Once you approved, it sends the change again and prints the result. If the
approval expires first, it exits 75; if it was denied, cancelled or cannot
be used, 77. Ctrl-C stops waiting, cancels the approval, and exits 130.
Nothing changes in any of these cases.

To finish later, run the same command again with `--approval <id>` before
the approval expires: the CLI waits until it is approved, then sends the
command with it.

```sh
varlatch --approval apr_... security set admin-step-up off
```

### Coding agents

A coding agent cannot approve anything: approvals need your passkey. In
[assisted mode](assisted-mode.md), the CLI does not wait. It prints the
address, tells the agent to stop and show it to you, prints the command to
run again with `--approval <id>`, and exits 75. Approve it yourself, then
let the agent run that command. The output never contains a secret value:
only the server's summary, the address and the expiry.

## Requirement protection

`requirement-protection` is about [Tailnet
Requirements](../../CONTEXT.md): rules that say values can only be read
from certain devices on your tailnet. Without it, anyone holding
`policy.manage` (an organization admin's CLI sign-in, for example) can
edit or remove a Requirement from anywhere, off the tailnet, and then read
what it protected. Each change is audited, but nothing stops it.

Turn it on from the Security page, or:

```sh
varlatch security set requirement-protection report    # see first what it would ask for
varlatch security set requirement-protection enforce
```

Turning it on is tightening: it needs no approval. Turning it down again
(to `report` or `off`) needs your approval, like any loosening.

### What it guarantees

With `requirement-protection` at `enforce`:

- **Editing or removing a Tailnet Requirement needs the approval of the
  person asking**, with a trusted passkey that verifies them (PIN,
  fingerprint or face), for exactly that change. The approval covers the
  Requirement, what it will cover and which devices it will allow
  afterwards, and the version you edited (for a removal, the version the
  server saw when it asked). If the Requirement changes in between, the
  approval no longer fits; ask again. See [Approvals](#approvals).
- **A machine credential cannot do either.** It can never give an
  approval, so it is refused with `PERMISSION_DENIED` (reason
  `machine-credential`), and no approval is created.
- **Creating a Requirement needs no approval**: it only takes access
  away. Neither does an edit that changes nothing.
- **Removing a trusted passkey needs an approval** for everyone with a
  live membership in the organization (see [Removing a
  passkey](#removing-a-passkey)). Otherwise a stolen session could remove
  the person's passkeys and add its own.
- The mode is read inside the change, after the organization is locked: a
  change either completes before the control changes, or sees the new
  mode.
- The approval is used once, together with the change. A change that
  fails leaves it usable until it expires.

Report mode counts the same edits and removals without refusing them.
While the organization is [frozen for an incident](incident-freeze.md),
editing or removing a Requirement is refused before any approval is asked
for; adding one still works.

### Approving a change

- **Dashboard** (**Access**, **Advanced**, and the installation's Tailnet
  tab): saving an edit or removing a Requirement opens the approval dialog
  with the server's summary, for example "Remove the Tailnet Requirement
  on the production tier (tailnet example.ts.net: tags tag:prod). What it
  constrained is no longer constrained". A change that can let in a
  device the Requirement used to refuse is marked as weakening it.
  Approve, and the change is saved; close the dialog and nothing changes.
- **CLI**: `varlatch tailnet remove <id>` prints the approval's address
  and waits, as described in [From the CLI](#from-the-cli). Resume with
  `varlatch --approval <id> tailnet remove <id>`.
- **API**: `PATCH` and `DELETE /v1/organizations/{org}/requirements/{id}`
  answer `403 STEP_UP_REQUIRED` with the approval; repeat the identical
  request with `Varlatch-Approval: <id>` once it is approved. A removal
  whose Requirement was edited while it ran answers `STATE_CHANGED`, and
  nothing is removed.

`requirement.updated` and `requirement.revoked` in the audit log name the
approval that was used.

### What it does not do

- **It is not a second person.** The approval comes from the person who
  asked. Someone who has both their sign-in and one of their trusted
  passkeys can still change a Requirement.
- **It protects Requirements, not every path to a value.** Grants, roles,
  groups and memberships also decide who can read what, and changing them
  is [`admin-step-up`](#admin-step-up)'s business: enforce both to cover
  both paths.
- **Whoever controls the host or the deployment can turn it off** with
  the [host operator's reset](#the-way-back-the-host-operators-reset).
- **Coding agents stop.** A coding agent cannot approve; in assisted mode
  the CLI prints the address and exits 75 (see [Coding
  agents](#coding-agents)).
- What was removed before you turned it on stays removed.

### The way back

If you lost your trusted passkeys, nobody else can approve for you:

- whoever runs the server can send you a link that enrolls a trusted
  passkey: `varlatch admin reenroll --identity <your identity id>`. Then
  approve as usual;
- or they can turn the control off: `varlatch admin security reset --org
  <slug> --control requirement-protection`. This also closes the open
  approvals for Requirement changes.

## Credential lifetime

`credential-lifetime` bounds how long machine credentials last. Without
it, a service credential lasts until someone revokes it unless a
lifetime is given when it is issued, and nothing stops a lifetime of ten
years. It has two settings, in seconds: a default lifetime and a maximum
(`0 < default <= maximum`).

Turn it on from the Security page, or:

```sh
varlatch security set credential-lifetime report --default-ttl 2592000 --max-ttl 7776000   # see first what it would change
varlatch security set credential-lifetime enforce
```

Turning it on, or shortening a lifetime, is tightening: it needs no
approval. Turning it down (to `report` or `off`), lengthening a lifetime
or clearing the lifetimes needs your approval, like any loosening.

### What it guarantees

With `credential-lifetime` at `enforce`, for every machine credential
issued in the organization from then on, both when a service, workload
or broker identity is created with its first credential and with
`varlatch credential issue` (or **Issue credential** in the dashboard):

- **A credential asked for without a lifetime gets the default.** The
  answer's `credentialExpiresAt` or `expiresAt` says when it expires, the
  CLI says it is the organization's default, and the `credential.issued`
  audit event carries `lifetimeDefaulted`.
- **A lifetime above the maximum is refused** with
  `CREDENTIAL_LIFETIME_EXCEEDED` (HTTP 422, with `requestedTtlSeconds` and
  `maxTtlSeconds` in `error.details`), and nothing is created or issued.
  A lifetime equal to the maximum is accepted.
- **It holds for every caller**: a person, or a machine credential that
  may manage identities. No approval is involved in issuing.
- The mode and the lifetimes are read inside the issuance, after the
  organization is locked: a credential is issued either before a change
  of the control or under its new settings.

Report mode issues exactly as before and counts `would-default` and
`would-refuse` separately (see [What report mode counts](#what-report-mode-counts)).
While the organization is [frozen for an incident](incident-freeze.md),
issuing is refused with `ORGANIZATION_FROZEN` before the lifetime is
looked at.

### What it does not do

- **Existing credentials never change.** A credential issued without
  expiry before the control was enforced keeps working until it is
  revoked. Find them with `varlatch security report` or the Security
  page's machine credentials, then replace and revoke them.
- **It covers machine credentials issued for a lifetime, not everything
  that signs in.** People's dashboard and CLI sign-ins keep their own
  limits (12 hours by default, 24 at most, across organizations), and
  OIDC-exchanged and agent-run credentials keep their own, shorter caps
  (an hour at most). `ci` and `agent` identities get no credential when
  they are created, so it does not apply to them.
- **A use budget is not a lifetime.** `--max-uses` stays optional; the
  control bounds time only.
- **A shorter lifetime is not a revocation.** A stolen credential works
  until it expires or is revoked; the control only makes sure it expires.
- **Whoever controls the host or the deployment can turn it off** with
  the [host operator's reset](#the-way-back-the-host-operators-reset).
- Enforcing it, like any control, makes removing a trusted passkey need an
  approval (see [Removing a passkey](#removing-a-passkey)).

### The way back

A program that needs a credential longer than the maximum gets one only
after an admin lengthens the maximum, which needs their approval. If
nobody can approve, whoever runs the server can turn the control off:
`varlatch admin security reset --org <slug> --control
credential-lifetime`. Credentials issued while it was enforced keep the
expiry they got; issue new ones if needed.

## Passkey verification

`passkey-verification` is about how a person signed in. A passkey can
verify the person holding it (a PIN, fingerprint or face) or not: a
security key without a PIN set up proves only that someone has the key.
Varlatch records, for each sign-in, whether the authenticator verified the
person and which passkey signed in. This control makes an organization
accept only sign-ins that did, with a trusted passkey.

**Look at report mode first.** Turned on, it refuses everyone in the
organization whose sign-in does not qualify, admins included, and someone
whose passkeys cannot verify them can only get back in through whoever
runs the server. Report mode counts each such request, per person and
reason, without refusing anything:

```sh
varlatch security set passkey-verification report    # who would be refused, and why
varlatch security status                             # the counts
varlatch security set passkey-verification enforce
```

Every person it counts would be refused. Sign-ins from before Varlatch
recorded this count as `no-evidence` until the person signs in again. A
credential keeps the evidence of the sign-in that issued it however it is
passed later (`--token-stdin`, `VARLATCH_TOKEN`); a credential issued
without a passkey sign-in, for example by `admin bootstrap` or `admin
recover` with `--cli-credential`, has none and is always refused.

### What it guarantees

With `passkey-verification` at `enforce`, a request to the organization by
a person's dashboard or CLI sign-in is refused with `403
PASSKEY_VERIFICATION_REQUIRED` unless that sign-in:

- was made with a passkey whose authenticator **verified the person**
  (`userVerified`), and
- that passkey is **trusted** when the request arrives: a passkey added
  from a signed-in session counts only once it is confirmed with a trusted
  one (see [Trusted passkeys only](#trusted-passkeys-only)), and a removed
  passkey no longer counts.

`error.details.reason` says what the sign-in lacks: `no-evidence` (no
record of how it was made), `not-user-verified`, or `untrusted-passkey`.

- **Every route of the organization**, reads included: projects,
  environments, values, retrieval and `varlatch run`, validation,
  disclosure and export, access, settings and the Security page. The
  organization's Convex token for the dashboard's live updates leaves it
  out.
- **People only.** Machine credentials (services, CI and OIDC, brokers
  and agents) are never affected, whatever their mode. Capability exercise
  is a broker's, so it is never affected either.
- **Only that organization.** The person's other organizations, their
  account pages and their list of organizations work as before, and so do
  the audit logs of deleted organizations
  (`/v1/deleted-organizations/{organization}/audit-events` and its
  export), which have no live organization to enforce anything.
- **Other refusals come first.** The refusal replaces an answer that would
  have let the request through: someone outside the organization still
  gets "not found", a member asking for something their role does not
  allow still gets `PERMISSION_DENIED`, and a request for something that
  does not exist (a project, a revision, a grant, a value) still gets
  "not found". Nothing is written, disclosed, decrypted or sent for a
  refused request, no approval is asked for, and each refusal is recorded
  once as `authorization.denied` with `metadata.reason`
  `passkey_verification_required` and `metadata.evidence` what the
  sign-in lacks.
- **It checks the person asking, never anyone else.** Removing a member,
  the exposure report and machine reach still show other people's
  authority as it is.
- **Each sign-in carries its own evidence.** A dashboard session has what
  its own sign-in recorded; signing in again with a verifying passkey in
  one browser does not change another session. A CLI sign-in carries what
  its approval recorded (device sign-in), or what the browser session it
  came from recorded (browser sign-in).
- Turning it on is tightening: it needs no approval. **Turning it on from a
  sign-in it would refuse is refused** (`PASSKEY_VERIFICATION_REQUIRED`,
  `details.change: "refused"`), so you cannot lock yourself out by saving
  it.

### When it decides

The person is identified when the request arrives; the decision is taken
where the request's own consistency point is, after the checks that say
whether what it asks for exists, and before anything happens:

- **A change** decides under its lock on the organization, in the
  transaction that makes the change. Changing a security control takes
  that lock exclusively, so a change either finishes under the old mode
  before the control changed, or reads the new one; a change that waited
  for the control change is refused under `enforce` and changes nothing.
  Changes that run with the strictest isolation (removing a member,
  changing a member's role) start again when the control changed while
  they ran, so they never finish under a mode that was already replaced.
- **A retrieval, validation or disclosure** decides in its snapshot, the
  one consistent read the request makes, after it found the project, the
  environment and the values it would return, and before any disclosure is
  recorded or any value decrypted. Nothing is read again afterwards.
- **A read of settings or metadata** decides once it has looked everything
  up, before the answer is sent.
- **An operation that reaches outside Varlatch** (an access check, a
  destination listing, GitHub App setup, an App Connection, an App key
  replacement) decides after it found the connection or app it uses,
  before any credential is decrypted or any request sent, and keeps its
  lock on the organization until the call and what it saves are done:
  changing a security control waits for it, so the call either finishes
  before the control changed or is refused. While the control is at
  `report` or `enforce`, such an operation is stopped after 90 seconds
  (`STATE_CHANGED`, `details.reason: "external-effect-deadline"`):
  Varlatch's own changes for the request are rolled back, but what a call
  already did outside Varlatch may have happened. With the control off it
  runs to completion, as before. The check of a webhook URL,
  an OIDC issuer or a base identity against the server's outbound policy
  only looks the name up, and comes before, as before.
- **A repeated request** with the same `Idempotency-Key` is decided too:
  the stored answer is returned only if the request is allowed now.
- **Report mode** counts the decision the request's change took under its
  lock (or its snapshot's, for a retrieval), once per successful request
  and organization: a request that failed, was refused or found nothing
  is not counted, and a change that started again is counted once.

### Getting a sign-in it accepts

- **Dashboard:** when an organization refuses your sign-in, the dashboard
  says so and offers **Sign in again**. Sign in with a trusted passkey and
  use its PIN, fingerprint or face when asked.
- **CLI:** `varlatch login --server <url>` and approve the sign-in in the
  browser with such a passkey. The CLI explains the refusal and exits 77.
- **A passkey you added from the dashboard** must be confirmed first: on
  your account's Security page, confirm it with one of your trusted
  passkeys. The sign-in you made with it then counts, without signing in
  again.
- **A security key without a PIN** cannot verify you. Set a PIN on the key
  (with its vendor's tool or your browser's security key settings), or use
  a passkey that unlocks with your device's PIN or biometric.

Sign-in itself still asks for user verification as `preferred`, as
before: turning this control on changes nothing about how people sign in
to the installation or to other organizations.

### What it does not do

- **It trusts the authenticator's report.** Whether the person was
  verified is what the authenticator signed.
- **A stolen credential is still a stolen credential.** The evidence
  describes the sign-in that created the session or credential; whoever
  holds that credential later is accepted.
- **It hides nothing from members that membership does not.** A member's
  stolen unverified credential is refused, but can still tell
  `PASSKEY_VERIFICATION_REQUIRED` apart from "not found" for the names
  that member could see anyway, such as which projects, environments,
  grants or values exist.
- **It cannot refuse before what only decryption or an outside call
  reveals.** A value whose stored reference cannot be expanded, or a
  platform that answers that a credential is wrong, is found out only by
  decrypting or calling out, which a refused request never does: such a
  request is refused, never told.
- **A request already under way finishes under the mode it read** (see
  [When it decides](#when-it-decides)). A Convex token minted before the
  control was enforced stays valid until it expires, at most 10 minutes;
  it carries metadata, never values.
- **Whoever controls the host or the deployment can turn it off** with
  the [host operator's reset](#the-way-back-the-host-operators-reset).

### The way back

Turning the control down (to `report` or `off`) is loosening: it needs
your approval with a trusted passkey that verifies you, and so does any
request to the organization while it is enforced. If nobody in the
organization can sign in with such a passkey:

- whoever runs the server can send a person a link that enrolls a trusted
  passkey: `varlatch admin reenroll --identity <identity id>`. Enroll a
  passkey that can verify you (set a PIN on a security key first), sign in
  with it, and continue;
- or they can turn the control off: `varlatch admin security reset --org
  <slug> --control passkey-verification`.

## Admin step-up

`admin-step-up` is about the changes that hand out or take away
authority, or send data out of Varlatch: machine identities and their
credentials, grants, roles, groups and teams, admins and members,
integrations, deletion, and `.env` export. Without it, anyone holding an
admin's sign-in (a stolen CLI credential or dashboard session, for
example) can make any of them from anywhere. Each is audited, but nothing
stops it.

Turn it on from the Security page, or:

```sh
varlatch security set admin-step-up report     # see first what it would ask for
varlatch security set admin-step-up enforce
```

Turning it on is tightening: it needs no approval. Turning it down again
(to `report` or `off`) needs your approval, like any loosening. Look at
report mode first: every change it counts would then need an approval,
and every one it counts with the reason `machine-credential` would be
refused, so automation that makes such changes with a machine credential
stops.

### What it guarantees

With `admin-step-up` at `enforce`, each of the 40 operations below:

- **needs the approval of the person asking**, with a trusted passkey that
  verifies them (PIN, fingerprint or face), for exactly that request:
  the operation, its target, what the request asks for and, where the
  target has one, its version. An approval for one request never fits
  another; a target that changed in between needs a new approval. See
  [Approvals](#approvals);
- **is refused for a machine credential**, which can never give an
  approval: `PERMISSION_DENIED` with the reason `machine-credential`, and
  no approval is created. Role changes, removals and scheduling the
  organization's deletion need a live admin of the organization, which a
  machine never is: those are refused by that check first, as before;
- **asks on every route that performs it.** A team reached through a
  `/groups/` route asks for the `team.*` operation; both shapes of a new
  connection ask; registering a GitHub App asks on the callback and on
  the attachment;
- **reads the mode inside the change**, after the organization is locked:
  a change either completes before the control changes, or sees the new
  mode. The approval is used once, together with the change; a change
  that fails leaves it usable until it expires;
- **rechecks your authority after the approval is used**, in the same
  transaction: if you lost the action meanwhile, the change is refused,
  the approval stays unused, and the audit log records one
  `authorization.denied`, as for any other refused request.

Removing a trusted passkey also needs an approval for everyone with a
live membership in the organization (see [Removing a
passkey](#removing-a-passkey)).

Report mode counts the same requests without refusing them.

These operations, and what an approval for each covers. Machine
identities:

| Operation | What the approval covers |
| --- | --- |
| `identity.create` | The name and kind, the credential lifetime and use budget asked for, and the lifetime the credential gets (with `credential-lifetime` enforced, its default when none was asked for). The summary says which: "as requested", "the organization's default, since none was requested", or that it never expires because none was requested. One approval covers both controls. |
| `credential.issue` | The machine, the credential's name, the lifetime and use budget asked for, and the lifetime it gets, said the same way. |
| `identity.reactivate` | The machine. Reactivating a machine that is already active changes nothing and needs no approval. |
| `oidc_binding.create` | The machine, the issuer, audience and subject, and the required claims (none and `{}` are the same). |
| `oidc_binding.delete` | The machine and the binding. During an incident freeze, removing a binding is still allowed and still asks. |

An agent-run credential minted by a broker, retiring or renaming a machine,
and revoking a credential never ask. Report mode already counts all five
operations.

Grants, roles, groups and teams, their members, and the projects a team
owns:

| Operation | What the approval covers |
| --- | --- |
| `grant.create` | Who gets it (a machine, a person or a group), the scope, and the actions or the role. Actions and environments are compared as sets: their order does not matter. |
| `grant.replace` | The Grant replaced and the complete new declaration. A replacement identical to the old Grant changes no access and needs no approval. |
| `grant.revoke` | The Grant. During an incident freeze, revoking a Grant is still allowed and still asks. |
| `role.create` | The name and the set of actions. |
| `role.update` | The role, its resulting name and set of actions, and the version you edited. Reordering its actions, or keeping its name and actions, needs no approval. |
| `role.delete` | The role, at the version the server read: a role changed since needs a new approval. |
| `group.create`, `team.create` | The name. |
| `group.update`, `team.update` | The new name and the version you edited. Keeping the name needs no approval. |
| `group.delete`, `team.delete` | The group or team, at the version the server read. |
| `group.member_add`, `team.member_add` | The group or team and the identity. Adding a current member changes nothing and needs no approval. |
| `group.member_remove`, `team.member_remove` | The group or team and the identity. |
| `team.project_add`, `team.project_remove` | The team and the project. Adding a project the team already owns needs no approval. |

A team is always a team: one reached through a `/groups/` route asks for
the `team.*` operation.

What you approve never shows text that is not in quotes: every name,
action, tag, issuer, subject or other value appears in quotes, lists in
brackets (`["config.value.read", "project.read"]`) and claims as
`{"ref": "main"}`, with every character you could not see (a zero-width
space, a direction override, a no-break space) written as `\u{XXXX}`.
Everything that already exists is named with its id, for example
`"Bob" (idn_...)`, a Grant, an OIDC binding or a Tailnet Requirement by its
id. Two different requests never read the same. Report mode counts these operations, except
requests that change nothing (a current member, an owned project, an
identical Grant, a role whose actions only change order).

People: inviting an admin, promoting a member, demoting an admin and
removing someone:

| Operation | What the approval covers |
| --- | --- |
| `member.invite_admin` | The organization, the invitee's name and the admin role. The invitation link is created when the approved request runs, and is not part of the approval. Inviting a member never asks. |
| `member.promote` | The person, the admin role, and the version of their membership the server read. Making an admin an admin again needs no approval. |
| `member.demote` | The person, the member role, and the version of their membership. Demoting yourself asks too. During an incident freeze, demoting an admin is still allowed and still asks. |
| `member.remove` | The person, at the version of their membership the server read: a person whose role changed since needs a new approval. During an incident freeze, removing someone is still allowed and still asks. Leaving an organization yourself never asks. |

The last admin of an organization still cannot be demoted, removed or
leave. That refusal comes before any approval, so nobody is asked to
approve a change that cannot happen, and it is checked again when the
approval is used: an approval to demote yourself, given while another
admin existed, is refused once you are the last one, and stays unused.
Role changes and removals need a live admin of the organization, which a
machine credential never is; an admin invitation by a machine credential
that holds `identity.manage` is refused.

Integrations: webhooks, connections and the GitHub App:

| Operation | What the approval covers |
| --- | --- |
| `webhook.create` | The full address and the set of event types (every event when none is given). The signing secret is created when the approved request runs, and is not part of the approval. |
| `webhook.update` | The webhook, its resulting address and set of event types, and the version you edited. Leaving a field out and sending its current value mean the same; `null` event types means every event. Reordering the event types, or keeping both, needs no approval. |
| `webhook.delete` | The webhook, at the version the server read. Not allowed during an incident freeze. |
| `connection.create` | A token connection: the platform, the base identity as Varlatch normalizes it, the name and the credential. A GitHub App connection: the App, the installation and the name. |
| `connection.replace_credential` | The connection, the new credential and the version you edited. Every Sync Target on it must still pass its disclosure check, as before. |
| `connection.delete` | The connection, at the version the server read: a connection whose credential was replaced since needs a new approval. During an incident freeze, revoking a connection is still allowed and still asks. |
| `github_app.register` | The registration and the App GitHub handed over: its id, slug, client id and owner. |
| `github_app.import` | The App id and the private key. |
| `github_app.replace_key` | The App, the new private key and the version you edited. |
| `github_app.remove` | The App, at the version the server read. |

**Secrets in an approval.** A webhook address (it may carry a token), a
connection's credential and a GitHub App's private key are part of what an
approval covers, so an approval given for one value never works for
another. The approval stores only a keyed hash of the request, never the
value. The summary you approve says that a credential or key is set or
replaced, and shows a webhook address with its path and query hidden, as
the audit log does.

**Nothing goes to GitHub before the approval.** Importing an App, replacing
its key and connecting one of its installations ask GitHub something first.
Each runs as one transaction that holds the organization from its checks
until the change is saved. Under enforce, Varlatch sends nothing to GitHub
until it has found your approval for exactly that request; the approval is
used only after GitHub answered, when the change is saved. If GitHub then
refuses the key or the installation, nothing changes and the approval stays
usable until it expires.

**Registering a GitHub App** runs in stages. GitHub creates the App when you
submit its manifest, before Varlatch is involved, and hands it over when it
sends you back. With no approval needed, the App is attached in the same
step, as before. When one is needed, Varlatch keeps what GitHub handed over
as pending for one hour, with the private key encrypted. Under enforce, the dashboard asks for your
approval and then attaches it; if you close the approval, the page offers
**Approve and attach** and **Discard**. Only the person who started the
registration can attach or discard it. A pending App that is discarded,
not attached within the hour, or refused (the organization got another
App meanwhile, or another organization uses this one) loses its key, and
the audit log records `sync.github_app_registration_abandoned` or
`sync.github_app_registration_refused`. The App stays on GitHub; the
dashboard links to where its owner deletes it.

Checking a credential or listing destinations before saving a connection
never asks.

Deletion and export:

| Operation | What the approval covers |
| --- | --- |
| `project.delete` | The project. It is deleted at once, in the request that uses the approval. |
| `organization.delete` | The organization and the waiting period in days (7 when you leave it out). The deletion is scheduled when the approved request runs, and the waiting period starts then, in full. With more than one admin, another admin must still approve the scheduled deletion; their approval needs no passkey step-up of its own, and yours does not stand in for it. Approving and cancelling a scheduled deletion never ask. |
| `secret.export` | The project, the environment, whether you asked for named Secrets or for every Secret you may reveal, the names you asked for, and the exact set of Secret names the file will contain. A Secret added since, or a new Grant that lets you see one more, changes that set: the dashboard then asks for a new approval. |

An export (the dashboard's `.env` download) is read in one step and its
approval is used in a second, before any value is decrypted. If a value
changed in between (a new value, a rotation started or completed, a
retiring value past its deadline, a value set or removed in a derived
environment over its parent's, or a new Contract revision), the server
answers `STATE_CHANGED`, discloses nothing and leaves the approval unused;
the dashboard repeats the export with it, which reads the values again.
Other Secret disclosures, `varlatch run`, and the non-secret values of the
same file never ask. An export through the tailnet endpoint asks the same
way.

All three are refused while the organization is frozen for an incident,
before any approval is asked for. Deleting a project is refused while the
organization's deletion is pending; an export is not, since reading stays
possible then.

**During an incident freeze**, an approval can be asked for only for the
operations that take authority away: removing an OIDC binding, revoking a
Grant, demoting an admin, removing a member and revoking a connection.
Every other operation is refused with `ORGANIZATION_FROZEN`, and no
approval is created (see [Incident freeze](incident-freeze.md)).

### With the other controls

The controls meet in one place, in this order. A request refused at any
step is refused there, and only the last step creates an approval:

1. the route's own checks: who you are, whether you hold the action, and
   whether what you named exists. While the organization is frozen, its
   members and machines are refused here (`ORGANIZATION_FROZEN`);
2. the request's validation (`VALIDATION_FAILED`);
3. an organization being deleted (`ORGANIZATION_DELETING`) or frozen;
4. `credential-lifetime` at `enforce`, for `identity.create` and
   `credential.issue`: a lifetime above the maximum is refused
   (`CREDENTIAL_LIFETIME_EXCEEDED`), for people and machines alike, and
   one left out gets the default, which the approval covers;
5. the operation's own not-found, such as a role that does not exist;
6. `passkey-verification` at `enforce`: a person's sign-in that was not
   made with a trusted passkey that verified them is refused
   (`PASSKEY_VERIFICATION_REQUIRED`) and audited once; machine credentials
   are not affected;
7. the operation's refusals that do not depend on an approval, such as
   the last-admin rule or a GitHub App the organization already has;
8. a machine credential, when a control at `enforce` would ask it for an
   approval (`PERMISSION_DENIED`, reason `machine-credential`);
9. `STEP_UP_REQUIRED` with the approval to give, or the approval used.

`requirement-protection` asks for approvals on its own two operations, which
`admin-step-up` never covers; a host reset of one closes only its own open
approvals. With `admin-step-up` in `report`, its operations run and are
counted while `requirement-protection` at `enforce` still asks for its own.

### What it does not do

- **It is not a second person.** The approval comes from the person who
  asked. Someone who has both their sign-in and one of their trusted
  passkeys can still make these changes.
- **It covers these 40 operations, not every write.** Value writes and
  rotations, creating projects and environments, Sync Targets (ADR-0031's
  disclosure check still applies), Capabilities, invitations of members,
  retiring and renaming machines, and revoking credentials never ask.
  Neither do value reads: `varlatch run`, Secret disclosures other than
  an export, Capability exercise, sync, OIDC exchange and a broker's
  agent-run credentials. Whoever holds the reveal action can still read
  what an export would contain, by those paths.
- **It does not replace the second admin.** Scheduling the organization's
  deletion still waits its full period, and with more than one admin,
  another admin must still approve it.
- **Coding agents stop.** A coding agent cannot approve; in assisted mode
  the CLI prints the address and exits 75 (see [Coding
  agents](#coding-agents)).
- **What GitHub already did stays done.** A GitHub App created by its
  manifest exists on GitHub before Varlatch asks for an approval; a
  refused or discarded registration leaves it there.
- **Whoever controls the host or the deployment can turn it off** with
  the [host operator's reset](#the-way-back-the-host-operators-reset).
- What was changed before you turned it on stays changed.

### The way back

Turning the control down (to `report` or `off`) is loosening: it needs
your approval with a trusted passkey that verifies you. If nobody can give
one, for example after losing every trusted passkey:

- whoever runs the server can send a person a link that enrolls a trusted
  passkey: `varlatch admin reenroll --identity <identity id>`. Then
  approve as usual;
- or they can turn the control off: `varlatch admin security reset --org
  <slug> --control admin-step-up`. This also closes the open approvals of
  all 40 operations. It does not touch a pending GitHub App registration,
  which still ends after its hour.

## Removing a passkey

Removing a trusted passkey needs an approval while you are a member of an
organization with any control at `enforce`. Approve it with a trusted passkey, which may be
the one you are removing. When none of your organizations enforces a
control, removing a passkey works as before. Removing an unconfirmed
passkey never needs one. Better Auth's own passkey removal endpoint is
turned off: the dashboard removes passkeys through Varlatch's
`DELETE /v1/me/passkeys/{id}`.

If you are left with unconfirmed passkeys only, you cannot approve
anything, including removing them or turning a control down; whoever runs
the server can enroll a trusted one for you with `varlatch admin reenroll
--identity <your identity id>`.

## The way back: the host operator's reset

Whoever runs the server can set controls back to off from the host,
without the API and without anyone's passkey:

```sh
varlatch admin security reset --org acme --control admin-step-up
varlatch admin security reset --org acme --all
# or inside the container:
docker compose exec varlatchd node dist/cli.js admin security reset --org acme --all
```

`varlatch admin security reset` runs the command in the varlatchd
container of the Compose installation in the current directory; pass
`--dir <compose-directory>` to name another one. `--org` takes the
organization's slug or id, and `--json` prints the outcome as JSON.

It sets the named controls (or all four) to off, closes their open
approvals, and records `security_control.reset` in the audit log for each.
It changes only the mode: `credential-lifetime` keeps its lifetimes, so
turning it on again reuses them, and lengthening or clearing them later
still needs an approval. It does not touch an organization's deletion,
suspended machine identities, passkeys or grants. Use it when nobody can
give an approval, for example after a lost passkey.

It also means that whoever controls the host or the deployment can bypass
every control. See the [threat model](../THREAT-MODEL.md).

The reset never lifts an [incident freeze](incident-freeze.md); it says
when the organization is still frozen.

## Controls and the incident freeze

The [incident freeze](incident-freeze.md) is not a security control: it
has no mode and works whatever the controls are set to. Where the two
meet:

- **Freezing** needs an admin's sign-in and no approval. It closes every
  open approval of the organization, so nothing approved before the freeze
  is used after it.
- **Lifting** always needs an admin's approval with a trusted passkey,
  even with every control off. The host operator lifts it with `admin
  unfreeze`; the [reset](#the-way-back-the-host-operators-reset) never
  does.
- **Changing a control stays possible while frozen.** Tightening needs no
  approval; loosening still needs one.
- **While frozen**, editing or removing a Tailnet Requirement and issuing
  a machine credential are refused with `ORGANIZATION_FROZEN` before any
  approval is asked for or any lifetime is looked at. Of `admin-step-up`'s
  40 operations, only the five that take authority away can be asked for
  and made: removing an OIDC binding, revoking a Grant, demoting an admin,
  removing a member and revoking a connection. Adding a Requirement still
  works.

## When an approved request is refused after all

An approval is checked once more when it is used: inside the request's
transaction, after the organization is locked, Varlatch checks again that
the person asking still holds the action. If they lost it meanwhile (an
admin demoted them, for example), the request is refused with
`PERMISSION_DENIED`, or not found when they are no longer a member at
all; nothing changes, and the approval stays unused until
it expires. What the audit log records:

- **An operation a control protects** (any of `admin-step-up`'s 40, and
  `requirement-protection`'s two): one `authorization.denied`, the same
  event an ordinary refusal records, written after the refused
  transaction rolled back. Only a request that used an approval gets this
  far, so this happens only while a control asks for approvals.
- **Freezing, lifting a freeze, changing a control, and the audit
  export's writes** (creating, checking, changing, replacing the key of
  and removing an [audit export](audit-export.md)) run this check
  whatever the controls are set to. The refusal is recorded once, the same
  way, only while at least one control of the organization is at `report`
  or `enforce`. That is read under the same organization lock, so it is
  the state the decision was made on; for a control change, the state
  before the change. Turning a control from `off` to `report` with every
  control off records nothing; turning the last one from `report` to `off`
  records the refusal. With every control off, these refusals record
  nothing, as before the controls existed. If the controls cannot be read
  at that point, the request is refused the same way and nothing is
  recorded.

## API

- `GET /v1/organizations/{org}/security/controls`: the controls, each
  with the modes this server accepts for it (`availableModes`, with
  `enforce` only where it can enforce that control), and the modes every
  control accepts (`availableModes`).
- `PATCH /v1/organizations/{org}/security/controls/{control}` with
  `{ "mode", "config", "expectedVersion" }`: `config` is the lifetimes
  object, `null` to clear it, or absent to keep it.
- A loosening change without an approval, and any of `admin-step-up`'s or
  `requirement-protection`'s operations while it is enforced, answers
  `403` with `STEP_UP_REQUIRED` and the approval in
  `error.details.approval`. Repeat
  the identical request with the header `Varlatch-Approval: <id>` once it
  is approved.
- `GET /v1/me/approvals/{id}`, `POST /v1/me/approvals/{id}/options`,
  `POST /v1/me/approvals/{id}/approve`, `POST /v1/me/approvals/{id}/cancel`.

- `GET /v1/organizations/{org}/security/control-report?days=<1-30>`:
  what report mode counted (see [How counts appear](#how-counts-appear)).
- `GET /v1/organizations/{org}/me/permissions`: your role and which
  organization-level actions (`organization.read`, `organization.manage`,
  `project.read`, `project.manage`, `identity.read`, `identity.manage`,
  `policy.read`, `policy.manage`, `audit.read`) your role and
  organization-wide grants allow here. Readable by every member; it says
  nothing else. Capability `organizations.permissions`.
- `GET /v1/organizations/{org}/security/credential-review`: the machine
  credential review (see [The Security page](#the-security-page)). Needs
  `identity.manage`.
- `GET /v1/organizations/{org}/security/approval-keys`: per admin, the
  number of trusted and unconfirmed passkeys, when one was last
  confirmed, and each passkey's name, provenance and dates. Never a
  credential id, public key or passkey id. Needs `organization.manage`.
- `GET /v1/organizations/{org}/security/refused-destinations`: the
  webhooks, Connections and OIDC issuers this installation's outbound
  policy refuses, with kind, name, host, port, reason and the earliest
  refusal recorded in the last 30 days, and how many destinations could
  not be checked. Never a resolved address or the host's allow list.
  Needs `organization.manage`. See
  [Outbound policy](outbound-policy.md).

The capabilities are `security.controls`, `security.report`,
`security.approval-keys`, `security.credential-review`,
`security.refused-destinations` and `organizations.permissions`, and `security.enforce.<control>` for each
control this server can enforce (`security.enforce.requirement-protection`,
`security.enforce.credential-lifetime`,
`security.enforce.passkey-verification`,
`security.enforce.admin-step-up`).

Every route of an operation that can ask for an approval documents the
`403 STEP_UP_REQUIRED` answer and the `Varlatch-Approval` header in the
[OpenAPI description](../../packages/protocol/openapi.yaml)
(`components.responses.StepUpRequired`).
