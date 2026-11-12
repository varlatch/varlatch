# Incident freeze

During an incident (a stolen admin session, a leaked machine credential, a
compromised CI runner) you can freeze an organization: one action that
stops all access to it at once, reads included. The audit log keeps
flowing, and you keep a narrow path to clean up and come back.

A freeze is not a security control: it has no mode, and it works whatever
the controls are set to.

## Before you rely on it: keep a break-glass credential

Freezing stops every runner, CI job and deploy that fetches credentials from
the organization. **If your deploy or rollback credentials come from
Varlatch, keep a break-glass credential outside it before you use the
freeze**: a token that can deploy and roll back your applications,
Varlatch included, stored somewhere Varlatch does not serve or push, scoped
as narrowly as your platform allows, and rotated after each use. Otherwise
a freeze can stop the deploy that fixes the incident, or the rollback of
Varlatch itself. Try it once on a test installation: freeze, deploy or roll
back with that credential, and lift.

## What stops

While an organization is frozen, every request of its members and of its
machine identities is refused with `ORGANIZATION_FROZEN` (HTTP 409, with
`Retry-After: 300`), except the ones listed under "What keeps working".
That includes:

- every value read: effective configuration, disclosures, `varlatch run`,
  `.env` export, validation and Capability exercise;
- every other change: values and rotations, Contracts, Projects and
  environments, creating or changing grants, roles, groups and teams,
  editing or revoking a Requirement, new machine identities, credentials and
  Capabilities (a broker's agent-run credentials included), invitations,
  OIDC exchange, GitHub App changes, Sync Target changes and pushes,
  connection checks and destination listings;
- webhook configuration, revocation included, so a stolen admin credential
  cannot cut the audit stream;
- scheduling or approving the organization's deletion.

Sync Targets stop pushing: none takes a new run, and a run in progress
stops before its next request. They keep their state, so lifting the
freeze resumes them without a deliberate resume.

Values cannot be written while frozen. The order of an incident is: rotate
the compromised credentials at their providers, revoke the compromised
authority in Varlatch, lift the freeze, then write the replacement values.

People who are not members of the organization get the same answers as
before: they learn nothing about the freeze.

## What keeps working

- **Signing in, and the lift itself.** Passkey sign-in, device sign-in, the
  CLI's browser sign-in, the dashboard's session, and approvals: a person
  with no session can sign in and lift the freeze.
- **The audit log.** Every event is still recorded; members with
  `audit.read` can read and export it; webhooks keep delivering it.
- **Reading what you need to find what to revoke**, never a value: the
  organization and its freeze; Projects and environments (names, tiers,
  which Contract revision is active), never a Contract's items, defaults or
  values; members and invitations; machine identities, their credentials,
  OIDC bindings and reach; grants, roles, groups, teams and Requirements;
  Capabilities, Sync Targets, Connections and webhooks as lists; the
  Security page.
- **Taking authority away**: revoking a credential, a Capability, a grant,
  an OIDC binding or an invitation; retiring a machine identity; removing
  a member or making an admin a member; pausing a Sync Target; revoking a
  Connection; adding a Tailnet Requirement (it only restricts); changing a
  security control (loosening one still needs its approval); cancelling a
  pending deletion.

None of these changes who may do what: each still needs its own
permission and any approval it asks for.

In the dashboard, every page of a frozen organization shows a banner. The
Security, Access, Audit, Settings and Connections pages keep working for
what is still allowed; Connections lists and revokes, without the GitHub
App, new connections or credential changes. The other pages show only the
banner.

## What was already running

A freeze takes effect for every request that starts after it:

- a change in progress commits first; changes that come later are refused;
- a retrieval that already started finishes and returns its values;
- a Sync Target request that passed its check before the freeze may still
  be sent, nothing after it;
- processes that already hold values (a `varlatch run` child, a deployed
  application, a CI job past its fetch) keep them: Varlatch does not reach
  back;
- the Convex token a browser already holds stays valid for up to 10
  minutes; it carries metadata only, and new tokens leave the frozen
  organization out;
- credentials and Capabilities are not revoked, and their expiry keeps
  running.

## Freezing

Freezing needs an admin's dashboard or CLI sign-in (`organization.manage`),
and no approval: it only takes access away. Machine credentials can never
freeze. Give a reason, up to 200 characters: members see it; the audit log
records that one was given, never its text.

- **Dashboard**: the organization's Security page, "Freeze organization".
  Type the organization's slug to confirm.
- **CLI**:

  ```sh
  varlatch org freeze acme --reason "Leaked CI token, rotating" --confirm acme
  ```

  In assisted mode, a coding agent cannot freeze without `--confirm`: it
  prints the command for you to run.

Freezing closes every open approval of the organization, so nothing
approved before the freeze can be used after it. It is recorded as
`organization.frozen`.

## Lifting

Lifting always needs an admin's approval with a trusted passkey, whatever
the security controls are set to. Any admin may lift, not only the one who
froze; no second admin is needed. Lifting undoes nothing done during the
freeze: a credential revoked while frozen stays revoked.

- **Dashboard**: the Security page shows who froze the organization, when
  and why, and "Lift freeze". The confirmation lists the Sync Targets that
  will resume pushing (to people who may manage Sync Targets; others see
  that they resume, not which); then approve with your passkey.
- **CLI**:

  ```sh
  varlatch org unfreeze acme
  ```

  It lists the Sync Targets that will resume, prints the approval address,
  and waits while you approve in the dashboard.

The approval names the freeze: it can never lift a later one. Lifting is
recorded as `organization.unfrozen`, with the method and how long the
freeze lasted.

### When nobody can approve

Whoever runs the server can lift a freeze from the host, without the API
and without anyone's passkey, for example when every admin lost their
trusted passkeys, or when a deploy must go out now:

```sh
varlatch admin unfreeze --org acme --confirm acme
# or inside the container:
docker compose exec varlatchd node dist/cli.js admin unfreeze --org acme --confirm acme
```

It closes the open approvals for a lift and records `organization.unfrozen`
with no actor. It adds no power: whoever controls the host can already
bypass everything here. `varlatch admin security reset` does not lift a
freeze; it says when the organization is still frozen.

## With a pending deletion

- You can freeze an organization that is being deleted. Both apply, and
  reads stop too.
- While frozen, a deletion cannot be scheduled or approved, and the
  deletion never runs: it runs after the lift, if it is still due.
- Cancelling a pending deletion still works.
- Lifting the freeze leaves a pending deletion in place.

## Backups

The freeze is part of the database. Restoring a backup taken before the
freeze brings the organization back unfrozen: freeze it again right after
the restore.

## For runners and CI

`ORGANIZATION_FROZEN` is final for the request. The CLI, the SDK and
`varlatch run` never retry it; the CLI exits with status 77. Runners and CI
jobs should back off too: each refused request is recorded in the audit log
(`authorization.denied` with the reason `organization_frozen`), and the
credentials that keep trying are evidence.

## API

- `GET /v1/organizations/{org}/incident-freeze`: the open freeze or `null`,
  the Sync Targets that resume on the lift (`null` without
  `config.sync.manage`), and the last freezes. Readable with
  `organization.read`.
- `POST /v1/organizations/{org}/incident-freeze` with `{ "reason" }`.
- `POST /v1/organizations/{org}/incident-freeze/{freeze}/lift`: answers
  `403` with `STEP_UP_REQUIRED` and the approval in
  `error.details.approval`; repeat it with the header
  `Varlatch-Approval: <id>` once it is approved.
- `GET /v1/organizations/{org}` includes `incidentFreeze`.
