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
  do before you decide.
- **`enforce`**: the control applies. **This release does not offer
  `enforce` yet**: the server refuses it with `CONTROL_MODE_UNAVAILABLE`,
  and the dashboard shows it as not available.

A control's state has a version that goes up by one with every change. A
control nobody has changed is off at version 0.

## Seeing and changing them

In the dashboard, open the organization's **Settings**, then **Security
controls**. With the CLI:

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
  session or another CLI sign-in cannot use it. Anything else is refused with
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

The capability is `security.controls`.
