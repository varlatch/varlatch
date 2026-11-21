# Gate G1 Browser Walkthrough Evidence (TEMPLATE)

> **TEMPLATE ONLY (NOT CANDIDATE EVIDENCE)**
>
> Do **not** pass this template file to `--walkthrough` for a G1 or G2 gate
> run. Copy this file to `docs/evidence/g1-walkthrough-v0.50.0.md` (or the
> target release candidate identifier), complete the walkthrough against the
> release candidate's `varlatchd`, remove this notice, and sign off below.

## 1. Candidate and Environment Metadata

| Field | Value |
| --- | --- |
| Release / candidate | `v0.50.0-rc.X` (replace) |
| Commit SHA (full 40-char) | `<commit-sha>` |
| Target mode | `go-binary` / `go-container` |
| `varlatchd` SHA-256 (or OCI digest) | `<sha256>` |
| `varlatch` CLI version & SHA-256 | `<version / sha256>` |
| Browser & version | `<e.g. Chromium 13x / Firefox 13x / Safari 18.x>` |
| Operating system | `<e.g. Linux / macOS>` |
| Passkey authenticator | `<e.g. hardware security key / platform authenticator / virtual>` |
| Walkthrough mode | `Manual hands-on` / `Scripted capture + owner review + interactive checks` |
| Date (UTC) | `YYYY-MM-DD HH:MM UTC` |
| Reviewer / owner | `<name / handle>` |
| Companion CI conformance run | `<GitHub Actions run URL / ID>` |
| Verdict | `PENDING` (set to `PASS` or `FAIL`) |

## 2. Acceptance Criteria

Every checked page, tab, dialog, drawer, menu, and confirmation must satisfy
all of the following:

- **Terminal state reached:** expected data (or expected access denial for a
  non-admin member) is rendered and every loading skeleton or spinner settles
  and stays absent.
- **No dashboard error state:** no unexpected "could not be loaded",
  "status is unavailable", or React error boundary appears.
- **Zero unexpected console errors:** browser DevTools console shows no
  uncaught exceptions or unexpected errors.
- **Zero unexpected network failures:** no unexpected `4xx`, `5xx`, or
  network failures. Expected status codes only:
  - `401` on signed-out routes before sign-in;
  - `403` for resources the `member` role is not granted;
  - `404` for an Organization's GitHub App when none is configured;
  - `503` during an active isolating maintenance window;
  - `0` responses with `429` (rate limit).
- **Live updates over SSE:** the dashboard receives real-time updates via
  `realtime.sse` on `varlatchd` without requiring Convex.

## 3. Setup and Execution Notes

Describe how the candidate `varlatchd` was started and seeded (fresh data
directory, Root KEK, backup key, fake or live external services, and roles).
If using a scripted capture plus owner review, note the capture command,
artifact archive location, and confirm every contact sheet and recording was
reviewed by hand.

```text
Seed summary (replace with actual details):
- Organizations: primary org (full data), frozen org, scheduled-deletion org, empty org (no GitHub App)
- Projects: one git-authority project (dev/staging/prod, active + pending Contract revisions, rotating secret), one managed-authority project
- Access: owner (installation admin), enrolled member, pending invitation, machines (OIDC, expiring credential, workload, agent, retired), custom role, group, team, grants, tailnet Requirement
- Security & Audit: Security Controls configured, fresh pending step-up approval, webhooks, audit export configured
- Sync & Installation: platform connections, sync targets, GitHub App + installation target, backup archive, pending device sign-in, isolating maintenance window tested last
```

## 4. Route and Screen Checklist

Covers every route defined in `apps/web/src/app.tsx` plus the server's
`/enroll` page, across `anonymous`, `owner`, and `member` roles. Mark each
row `[x]` when verified, or `[ ]` with an explanation in Section 6.

### 4.1 Anonymous, Enrollment, and Empty-Org States

| # | Done | Role | Screen / State | Route | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | [ ] | anonymous | Signed-out sign-in screen (route preserved after sign-in) | `/o/<org>/projects` | |
| 2 | [ ] | anonymous | Enrollment page (no token / invalid token state) | `/enroll` | |
| 3 | [ ] | anonymous | Maintenance screen (signed out during maintenance window) | `/o/<org>/projects` | |
| 4 | [ ] | owner | Welcome screen (signed-in user belonging to no Organization) | `/` | |

### 4.2 Owner: Redirects, Shell, and Projects

| # | Done | Screen | Route | Dialogs, drawers, menus, and confirmations | Notes |
| --- | --- | --- | --- | --- | --- |
| 5 | [ ] | Root lands in remembered or first Organization | `/` | (none) | |
| 6 | [ ] | Org index redirects to Projects | `/o/<org>` | (none) | |
| 7 | [ ] | Legacy `/credentials` redirects to `/account/sessions` | `/credentials` | (none) | |
| 8 | [ ] | Legacy `/profile` redirects to `/account` | `/profile` | (none) | |
| 9 | [ ] | Projects list | `/o/<org>/projects` | New project; Project row menu; Organization switcher; New organization; Command palette (`Ctrl+K` / `Cmd+K`) + item search; Keyboard shortcuts (`?`) | |

### 4.3 Owner: Projects and Environments (Git-Authority and Managed-Authority)

| # | Done | Screen | Route | Dialogs, drawers, menus, and confirmations | Notes |
| --- | --- | --- | --- | --- | --- |
| 10 | [ ] | Project Values (matrix, git-authority) | `/o/<org>/p/<git-proj>` | Project menu; New environment; Rename project; Delete project; Export `.env` menu & dialog; Reveal secrets menu; Cell menu (rotating secret); Import dialog; Review changes (draft) | |
| 11 | [ ] | Project Contract (git-authority, active + pending revision) | `/o/<org>/p/<git-proj>/contract` | Revision menu | |
| 12 | [ ] | Project Integrations | `/o/<org>/p/<git-proj>/integrations` | Sync Target menu | |
| 13 | [ ] | Project Activity (audit) | `/o/<org>/p/<git-proj>/activity` | Audit event detail; Actor filter | |
| 14 | [ ] | Environment production (values, rotating secret, tailnet badge) | `/o/<org>/p/<git-proj>/e/production` | Item panel (rotation & targets); Rotate dialog; Environment menu | |
| 15 | [ ] | Environment development (values) | `/o/<org>/p/<git-proj>/e/development` | Item panel; Delete environment confirmation; Import dialog | |
| 16 | [ ] | Environment production integrations | `/o/<org>/p/<git-proj>/e/production/integrations` | Add integration dialog | |
| 17 | [ ] | Environment staging integrations (GitHub App Target) | `/o/<org>/p/<git-proj>/e/staging/integrations` | (none) | |
| 18 | [ ] | Environment production activity | `/o/<org>/p/<git-proj>/e/production/activity` | (none) | |
| 19 | [ ] | Project Values (managed-authority) | `/o/<org>/p/<managed-proj>` | (none) | |
| 20 | [ ] | Project Contract editor (managed-authority) | `/o/<org>/p/<managed-proj>/contract` | Draft diff; Publish confirmation (security-relevant change) | |

### 4.4 Owner: Access Control

| # | Done | Screen | Route | Dialogs, drawers, menus, and confirmations | Notes |
| --- | --- | --- | --- | --- | --- |
| 21 | [ ] | Access: People | `/o/<org>/access` | How access works; Invite dialog; Member menu; Exposure ("What they received") dialog; Make admin dialog; Remove member dialog | |
| 22 | [ ] | Access: Machines | `/o/<org>/access?tab=machines` | Machine expanded (expiring credential warning); Issue credential dialog; Machine menu; OIDC binding view; Retired machines toggle; New machine dialog | |
| 23 | [ ] | Access: Roles & teams | `/o/<org>/access?tab=roles` | Custom role view; Group expanded; Team expanded; New group; New team; New role | |
| 24 | [ ] | Access: Grants | `/o/<org>/access?tab=grants` | Edit grant dialog | |
| 25 | [ ] | Access: Advanced (Requirements & capabilities) | `/o/<org>/access?tab=advanced` | Requirement editor; New requirement dialog | |

### 4.5 Owner: Connections, Audit, Security, Settings, Freeze, and Deletion

| # | Done | Screen | Route | Dialogs, drawers, menus, and confirmations | Notes |
| --- | --- | --- | --- | --- | --- |
| 26 | [ ] | Connections (tokens & configured GitHub App) | `/o/<org>/connections` | New connection; Connection menu; Replace credential; GitHub App menu; Rotate GitHub App key; Connect an installation | |
| 27 | [ ] | Connections (org without GitHub App) | `/o/<empty-org>/connections` | Register a GitHub App; Import a GitHub App | |
| 28 | [ ] | GitHub App callback (no registration in progress) | `/o/<org>/connections/github-app` | (none) | |
| 29 | [ ] | Audit (log, live updates, webhooks) | `/o/<org>/audit` | Audit event detail; Project filter; Revoke webhook confirmation; Edit webhook | |
| 30 | [ ] | Security (freeze, controls, audit export, approval keys, credentials) | `/o/<org>/security` | Freeze organization; Security control mode picker; Audit export: Change; Audit export: Replace key | |
| 31 | [ ] | Settings (organization, server, appearance, danger zone) | `/o/<org>/settings` | Server capabilities list; Delete organization | |
| 32 | [ ] | Frozen Organization: Projects (freeze banner) | `/o/<frozen-org>/projects` | (none) | |
| 33 | [ ] | Frozen Organization: Security | `/o/<frozen-org>/security` | Lift freeze dialog | |
| 34 | [ ] | Frozen Organization: Access (readable while frozen) | `/o/<frozen-org>/access` | (none) | |
| 35 | [ ] | Scheduled-deletion Organization: Settings | `/o/<sunset-org>/settings` | Cancel deletion dialog | |
| 36 | [ ] | Scheduled-deletion Organization: Projects (deletion banner) | `/o/<sunset-org>/projects` | (none) | |

### 4.6 Owner: Account, Installation, Device Sign-In, Step-Up Approval, and Maintenance

| # | Done | Screen | Route | Dialogs, drawers, menus, and confirmations | Notes |
| --- | --- | --- | --- | --- | --- |
| 37 | [ ] | Account: Profile | `/account` | (none) | |
| 38 | [ ] | Account: Security (passkeys) | `/account/security` | Passkey menu | |
| 39 | [ ] | Account: Sessions and credentials | `/account/sessions` | Sign out everywhere else confirmation | |
| 40 | [ ] | Installation: Backups (with archive on record) | `/installation/settings` | How to create an archive; How to run a restore drill | |
| 41 | [ ] | Installation: Tailnet | `/installation/settings?tab=tailnet` | (none) | |
| 42 | [ ] | Installation: Release | `/installation/settings?tab=release` | (none) | |
| 43 | [ ] | Installation: Outbound policy | `/installation/settings?tab=outbound` | (none) | |
| 44 | [ ] | Device sign-in: code entry & confirmation | `/device` | Pending device sign-in confirmation screen | |
| 45 | [ ] | Step-up approval page (pending approval) | `/approve/:id` | (none) | |
| 46 | [ ] | Maintenance banner (signed in during isolating maintenance window) | `/o/<org>/projects` | (none) | |

### 4.7 Member Role (Least-Privilege and Denial States)

| # | Done | Screen | Route | Expected state | Notes |
| --- | --- | --- | --- | --- | --- |
| 47 | [ ] | Member: Projects | `/o/<org>/projects` | Permitted projects visible | |
| 48 | [ ] | Member: Managed project values | `/o/<org>/p/<managed-proj>` | Permitted values visible | |
| 49 | [ ] | Member: Managed project contract | `/o/<org>/p/<managed-proj>/contract` | Contract visible | |
| 50 | [ ] | Member: Managed project production environment | `/o/<org>/p/<managed-proj>/e/production` | Environment visible | |
| 51 | [ ] | Member: Managed project activity | `/o/<org>/p/<managed-proj>/activity` | Project activity visible | |
| 52 | [ ] | Member: Git project (built-in member reach, no extra Grant) | `/o/<org>/p/<git-proj>` | Built-in reach respected | |
| 53 | [ ] | Member: Access | `/o/<org>/access` | Admin mutations hidden/refused | |
| 54 | [ ] | Member: Connections | `/o/<org>/connections` | Connections & GitHub App refused cleanly (403) | |
| 55 | [ ] | Member: Audit | `/o/<org>/audit` | Denial settles with no refetch loop or recurring skeleton | |
| 56 | [ ] | Member: Security | `/o/<org>/security` | Admin controls refused cleanly | |
| 57 | [ ] | Member: Settings | `/o/<org>/settings` | Read-only / admin actions restricted | |
| 58 | [ ] | Member: Account Profile | `/account` | Profile loads cleanly | |
| 59 | [ ] | Member: Account Sessions | `/account/sessions` | Loads cleanly; no empty-slug `GET /v1/organizations//identities` 404 | |
| 60 | [ ] | Member: Installation settings | `/installation/settings` | Non-admin refusal rendered cleanly | |

## 5. Interactive End-to-End Flows (Hands-On Checks)

These flows submit real state changes and must be verified interactively in
a browser (they are not covered by a read-only screenshot capture):

| # | Done | Flow | Verification criteria | Notes |
| --- | --- | --- | --- | --- |
| 1 | [ ] | Enrollment & passkey sign-in | Enroll via `/enroll?token=...` with a passkey, sign out, sign back in via `/o/<org>/projects` and confirm redirect back to original route | |
| 2 | [ ] | Create Organization from Welcome screen | Signed-in user with no Organization sees Welcome screen at `/`, creates an Organization, lands on `/o/<new-org>/projects` | |
| 3 | [ ] | Write, reveal, copy, and rotate a secret | Set a secret value, verify it is masked by default, reveal it via imperative action, start rotation, and complete rotation | |
| 4 | [ ] | Publish a managed Contract change | Edit a managed Contract, inspect draft diff, publish through confirmation dialog, verify active revision updates | |
| 5 | [ ] | Live updates via SSE (`realtime.sse`) | Keep `/o/<org>/audit` or a project page open while modifying a value from another tab or `varlatch` CLI; confirm UI updates without manual refresh | |
| 6 | [ ] | Device sign-in end-to-end | Run `varlatch login`, enter/confirm code on `/device`, verify CLI receives a valid session and can list projects | |
| 7 | [ ] | Step-up approval end-to-end | Trigger a step-up protected action, open `/approve/:id`, approve with passkey, verify the action completes and is audited | |
| 8 | [ ] | Freeze / lift freeze & schedule / cancel deletion | Freeze an Organization, verify freeze banner & write refusal, lift freeze; schedule deletion, verify banner, cancel deletion | |
| 9 | [ ] | Backup archive visibility | Run `varlatchd admin backup run` (with `backup_key_file` set) and verify the new archive appears on `/installation/settings` | |
| 10 | [ ] | Live tailnet browser access (or cite separate live record) | Access via tailnet and confirm tailnet-gated production values are reachable (or mark `N/A` and cite the separate tailnet live check) | |
| 11 | [ ] | GitHub App manifest registration round trip (or cite separate live record) | Complete registration callback through `github.com` (or mark `N/A` and cite separate live check) | |

## 6. Findings and Exceptions

Record any defects, expected differences, browser warnings, retries, or
follow-up issues found during the walkthrough. Write "None." if clean.

- (replace with findings or "None.")

## 7. Owner Sign-Off

- **Owner:** `<name / handle>`
- **Date (UTC):** `YYYY-MM-DD HH:MM UTC`
- **Candidate commit:** `<full-40-char-sha>`
- **`varlatchd` SHA-256:** `<sha256>`
- **Verdict:** `PASS` / `FAIL`
- **Notes:** `<summary of sign-off>`
