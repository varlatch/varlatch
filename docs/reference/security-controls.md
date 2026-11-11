# Security controls and approvals

Security controls are optional protections an organization can turn on.
They all start **off**, on new and upgraded installations alike: with every
control off, Varlatch works exactly as it did before they existed.

This page covers the controls, their modes, how a change is approved with
your passkey, and the way back for whoever runs the server.

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
- **`enforce`**: the control applies. **This release does not offer
  `enforce` yet**: the server refuses it with `CONTROL_MODE_UNAVAILABLE`,
  and the dashboard shows it as not available.

A control's state has a version that goes up by one with every change. A
control nobody has changed is off at version 0.

## Seeing and changing them

In the dashboard, open the organization's **Security** page (see [The
Security page](#the-security-page)). With the CLI:

```sh
varlatch security controls            # each control, its mode, lifetimes, version, last change
varlatch security set admin-step-up report
varlatch security set credential-lifetime report --default-ttl 86400 --max-ttl 2592000
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
a while, then decide. Every control is off until an admin changes it,
and `enforce` is shown as coming in a later release.

It has five parts:

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
- **Tailnet Requirements.** How many there are, with a link to their
  editor (**Access**, **Advanced**) and the mode of
  `requirement-protection`, which protects them.
- **Checklist.** A few things worth doing whatever the controls say, each
  linked to its page in these docs: report mode (this page), trusted
  passkeys ([Your passkeys](../getting-started.md#your-passkeys)),
  finding copies of secrets ([`varlatch scan
  --find-files`](secret-scanning.md#finding-copies-of-secrets)), backups
  the host cannot erase ([Object
  Lock](../operations/backup.md#scoping-destination-credentials-per-provider)),
  and the [threat model](../THREAT-MODEL.md).

Who sees what: every member sees the controls and their modes
(`organization.read`). The counts and the approval keys need
`organization.manage`, the credential review `identity.manage`, and the
requirements `policy.read`; organization admins hold all of them, and a
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
per control; `--json` has all of them). For machine credentials it gives
two separate lines: the use and expiry policy (never used, unused for 30
days, no expiry) and the expiry warnings (expiring within 7 days or
expired), so a credential that already expired is never hidden behind
"nothing to review". `varlatch security report` starts with the same two
lines. Like the page, `security status` asks the server which parts you
may read first, and does not ask for the others. A part you cannot read, or that
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

- `no-approval`: a person did it without an approval. No operation asks
  for one yet; with `enforce`, these would need one.
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

## Approvals

An approval is your passkey, with your PIN, fingerprint or face, saying yes
to one exact change that you asked for.

1. You ask for a loosening change. The server keeps a pending approval for
   exactly that request (the control, the new state, the version it
   expects, and the sign-in that asked) and answers `STEP_UP_REQUIRED`
   with its address, `https://<your server>/approve/<id>`.
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
- **Limits:** at most 5 open approvals per sign-in, and 30 per person in 10
  minutes. The CLI checks every 5 seconds; checking faster is slowed down,
  as for a CLI sign-in.

### Trusted passkeys only

Only a **trusted** passkey can approve (see [Your
passkeys](../getting-started.md#your-passkeys)). A passkey you added in the
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

## Removing a passkey

Removing a trusted passkey will need an approval while you are a member of
an organization with any control at `enforce`. Until `enforce` is offered,
removing a passkey works as before. Removing an unconfirmed passkey never
needs one.

## The way back: the host operator's reset

Whoever runs the server can set controls back to off from the host,
without the API and without anyone's passkey:

```sh
varlatch admin security reset --org acme --control admin-step-up
varlatch admin security reset --org acme --all
# or inside the container:
docker compose exec varlatchd node dist/cli.js admin security reset --org acme --all
```

It sets the named controls (or all four) to off, closes their open
approvals, and records `security_control.reset` in the audit log for each.
It does not touch an organization's deletion, suspended machine
identities, passkeys or grants. Use it when nobody can give an approval,
for example after a lost passkey.

It also means that whoever controls the host or the deployment can bypass
every control. See the [threat model](../THREAT-MODEL.md).

## API

- `GET /v1/organizations/{org}/security/controls`: the controls and
  `availableModes`.
- `PATCH /v1/organizations/{org}/security/controls/{control}` with
  `{ "mode", "config", "expectedVersion" }`: `config` is the lifetimes
  object, `null` to clear it, or absent to keep it.
- A loosening change without an approval answers `403` with
  `STEP_UP_REQUIRED` and the approval in `error.details.approval`. Repeat
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
- `GET /v1/organizations/{org}/security/approval-keys`: per admin, the
  number of trusted and unconfirmed passkeys, when one was last
  confirmed, and each passkey's name, provenance and dates. Never a
  credential id, public key or passkey id. Needs `organization.manage`.

The capabilities are `security.controls`, `security.report`,
`security.approval-keys` and `organizations.permissions`.
