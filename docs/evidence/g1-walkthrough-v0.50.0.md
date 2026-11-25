# Gate G1 Browser Walkthrough Evidence: v0.50.0

Prepared for the owner: every row below is the owner's to tick, and the
verdict is the owner's. Base address: http://localhost:18750. Commands run in the kit's
directory (`./g1`, the owner's one-page instruction). Follow the order in
Section 3.

## 1. Candidate and Environment Metadata

| Field | Value |
| --- | --- |
| Release / candidate | `v0.50.0` |
| Commit SHA (full 40-char) | `ff7f191fc2182625a6371ec936a28950d19916a1` |
| Target mode | `go-binary` |
| `varlatchd` SHA-256 (or OCI digest) | `d3bc13908d02471ee679829058eedc8f09691dfa605d5ae618a81979e8f93625` (varlatchd 0.50.0; built from the commit with `-tags conformance`, as the G1 gate job builds its target, and the release's flags) |
| `varlatch` CLI version & SHA-256 | varlatch 0.50.0, `8c6b311df899feab561f8ff5fc3972b81cf6fd7e2995f845d1cd662666f65bca` |
| Browser & version | Chromium 155.0.0.0 |
| Operating system | Linux x86_64 (Arch based) |
| Passkey authenticator | The owner's phone (hybrid: QR code and Bluetooth); a virtual authenticator in the capture |
| Walkthrough mode | `Scripted capture + owner review + interactive checks` |
| Date (UTC) | `2026-11-25 16:05 UTC` |
| Reviewer / owner | Jeremy Deceuster |
| CI run on the commit | https://github.com/varlatch/varlatch/actions/runs/45631256639 |
| Go run on the commit | https://github.com/varlatch/varlatch/actions/runs/45631262395 |
| Companion CI conformance run | https://github.com/varlatch/varlatch/actions/runs/45631262395 |
| Verdict | `PASS` |

## 2. Acceptance Criteria

Every checked page, tab, dialog, drawer, menu and confirmation must satisfy
all of these:

- **Terminal state reached:** the expected data (or the expected denial, for
  the member) is shown, and every loading bar or spinner is gone.
- **No dashboard error state:** no unexpected "could not be loaded", "status
  is unavailable" or React error page.
- **No unexpected console error** (DevTools, Console).
- **No unexpected failed request** (DevTools, Network). Expected only: 401
  signed out before sign-in; 403 for what the member may not do, and once
  each time a step-up approval is asked for; 404 for an Organization's
  GitHub App when it has none, and on rows 5 and 6; 409 for the refused
  write in flow 9; 503 during maintenance. Never 429. `./g1 errors` counts
  what the server answered.
- **Live updates over SSE:** `realtime.sse`, without Convex.

## 3. Setup and Execution Notes

A throwaway `varlatchd` of the candidate on this workstation's loopback
address, started by the kit through the conformance harness's go-binary
adapter: a fresh data directory, Root KEK and backup key; the harness's fake
platforms (GitHub with a GitHub App, Coolify, Convex), webhook receiver,
OIDC issuer and S3 object store. Nothing reaches production or the internet.
The kit seeds through `/v1` once the owner has created Acme by hand.

The capture: the kit's `capture.mjs` on a second throwaway server of the same
binary and seed, with a headless Chromium. 62 of 62 pages and 76 of 76 dialogs, drawers and
menus settled, showed what the seed requires, and gave no unexpected console
error or failed request. It is kept with the release's records
(`results.json` SHA-256 `dcf2c57dd0f1825fc9dde24d7de4d238e4ce9d443e684c7cb8d9d2019f8a0989`).
The owner reviewed its pictures row by row, and did by hand, on the server
below, every flow of Section 5 except 13 and 14 (cited), and rows 2 to 4, 46,
47 and 48. Rows 7 to 11 were also done by hand on the previous candidate.

Seed:

- Organizations: Acme (everything), Frozen Co (frozen, INC-42), Sunset Ltd
  (deletion in 30 days), Globex (empty, no GitHub App).
- Projects in Acme: `api` (git authority; development, staging, production;
  a 6-item Contract active and a 7-item one not active; `STRIPE_SECRET`
  rotating), `web` (managed authority; development, production).
- Access: the owner (installation admin, shown as Installation Admin),
  Morgan Member (enrolled in the second window), Robin (pending), machines
  ci-deployer, billing-worker, deploy-bot, review-agent and the retired
  old-cron, role Deployer, group Backend services, team Platform, 4 Grants,
  a tailnet Requirement on production.
- Security and audit: four Security Controls at Report, two webhooks, the
  audit export.
- Sync and installation: 3 token Connections and one through a GitHub App, 4
  Sync Targets, one backup archive, a newer release on record (the fake
  0.99.0).

Order and time (about 3 h; with the real-Tailscale step 3 h 15 min):

| Part | Rows | Minutes |
| --- | --- | --- |
| A. Start: enroll, Welcome, create Acme, enroll Morgan | flows 1 (first half) and 3, row 4 | 8 |
| B. Owner pages | 5 to 11 | 12 |
| C. Projects and Environments | 12 to 22 | 30 |
| D. Access | 23 to 27 | 20 |
| E. Connections to deletion | 28 to 38 | 25 |
| F. Account and Installation | 39 to 45 | 13 |
| G. Flows 7, 6, 8 (rows 46, 47), 4, 5, 1 (second half), 2 | flows | 25 |
| H. Member, anonymous | 49 to 62, 1, 2, 6 | 15 |
| I. Flows 9 to 12, 15, 16 | flows | 20 |
| J. Maintenance, last | 3, 48 | 4 |
| T. The real-Tailscale step (flow 13), its own server: done earlier, only cited here | Section 5.1 | 12 |
| K. Flows 13 and 14, findings, sign-off | Sections 6 and 7 | 8 |

## 4. Route and Screen Checklist

Mark a row `[x]` when it passes. A dialog is opened and closed, never
submitted, unless the row says so.

### 4.1 Anonymous, Enrollment, Empty-Org, and Unknown-Route States (about 8 minutes)

| # | Done | Role | Page | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | [x] | anonymous | [`/o/acme/projects`](http://localhost:18750/o/acme/projects) | Open it in the anonymous window | "Sign in to Varlatch", `localhost:18750`, button "Continue with passkey"; the address keeps `/o/acme/projects` (its return after sign-in is flow 1) |  capture reviewed |
| 2 | [x] | anonymous | [`/enroll`](http://localhost:18750/enroll) and [`/enroll#not-a-token`](http://localhost:18750/enroll#not-a-token) | Open both; on the second type any name and press "Create passkey" | First: sign-in card, no name field. Second: "Enrollment failed: Setup token is invalid, consumed, or expired" |   |
| 3 | [x] | anonymous | [`/o/acme/projects`](http://localhost:18750/o/acme/projects) | Do last, with row 48: run `./g1 maintenance`, then reload the anonymous window | "Varlatch is under maintenance", "Reconnecting by itself"; after the window it returns to the sign-in screen without a click |   |
| 4 | [x] | owner | [`/`](http://localhost:18750/) | Done at the start (flow 1): right after enrolling, before any Organization exists | "Welcome to Varlatch" and "Create an organization" |   |
| 5 | [x] | owner | [`/nope`](http://localhost:18750/nope) and [`/o/acme/nope`](http://localhost:18750/o/acme/nope) | Open both | "Page not found", with the navigation; "Go to the start page" on the first, "Go to Projects" on the second, and both work. (Stop and report if it says "Unexpected Application Error") |  capture reviewed |
| 6 | [x] | owner, then member | [`/o/does-not-exist/projects`](http://localhost:18750/o/does-not-exist/projects) | Open it in both windows; in the member's window also open [`/o/globex/projects`](http://localhost:18750/o/globex/projects) | "Projects could not be loaded" and "Organization not found"; it settles, no loop |  capture reviewed |

### 4.2 Owner: Redirects, Shell, and Projects (about 8 minutes)

| # | Done | Role | Page | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 7 | [x] | owner | [`/`](http://localhost:18750/) | Open it | Lands on the Projects of the last Organization visited |  capture reviewed |
| 8 | [x] | owner | [`/o/acme`](http://localhost:18750/o/acme) | Open it | Becomes `/o/acme/projects`; `api` and `web` listed |  capture reviewed |
| 9 | [x] | owner | [`/credentials`](http://localhost:18750/credentials) | Open it | Becomes `/account/sessions` |  capture reviewed |
| 10 | [x] | owner | [`/profile`](http://localhost:18750/profile) | Open it | Becomes `/account` |  capture reviewed |
| 11 | [x] | owner | [`/o/acme/projects`](http://localhost:18750/o/acme/projects) | Open and close (Escape) each: New project; the `...` menu of a row; Organization switcher; New organization; Ctrl+K and type `DATABASE`; press `?` | `api` (API, git) and `web` (Web, managed); switcher lists Acme, Frozen Co, Sunset Ltd, Globex; search finds `DATABASE_URL`; the shortcuts list opens |  capture reviewed |

### 4.3 Owner: Projects and Environments (about 30 minutes)

| # | Done | Role | Page | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 12 | [x] | owner | [`/o/acme/p/api`](http://localhost:18750/o/acme/p/api) | Open and close each: project menu, New environment, Rename, Delete; Export .env menu, then development; Reveal secrets menu; the menu of the `STRIPE_SECRET` production cell; paste two lines `A=1` and `B=2` into the add row (Import); add `WALKTHROUGH_DRAFT` = `x`, press Review, then discard | 6 items; `STRIPE_SECRET` "rotating" and "tailnet only" in production; PORT 3000 (development) and 8080 (staging); "git contract"; Import lists A and B; Review lists `WALKTHROUGH_DRAFT`; nothing saved |  capture reviewed |
| 13 | [x] | owner | [`/o/acme/p/api/contract`](http://localhost:18750/o/acme/p/api/contract) | Open the menu of a revision | 6 items; two revisions: 6 items (active) and 7 items (not active); "varlatch contract push" named |  capture reviewed |
| 14 | [x] | owner | [`/o/acme/p/api/integrations`](http://localhost:18750/o/acme/p/api/integrations) | Open the menu of the GitHub target | Targets `api-walkthrough` (GitHub), `app-conformance` (Coolify), `convex.conformance.test` (paused, "Resume") and `web-walkthrough` (staging) |  capture reviewed |
| 15 | [x] | owner | [`/o/acme/p/api/activity`](http://localhost:18750/o/acme/p/api/activity) | Expand the first event; open the Actor filter | Events by Installation Admin; the detail shows actor and request; the filter offers "anyone" |  capture reviewed |
| 16 | [x] | owner | [`/o/acme/p/api/e/production`](http://localhost:18750/o/acme/p/api/e/production) | Click `STRIPE_SECRET`; click `API_KEY`, then Rotate, then Cancel; open the `...` menu | `STRIPE_SECRET` rotating, "Grace window open"; a tailnet notice in place of Reveal; the menu offers "Delete environment" |  capture reviewed |
| 17 | [x] | owner | [`/o/acme/p/api/e/development`](http://localhost:18750/o/acme/p/api/e/development) | Click `PORT`; `...` then Delete environment, Cancel; paste `A=1` and `B=2` lines into the add row, close | PORT 3000, PUBLIC_URL `http://localhost:3000`; the delete dialog names development; Import lists A |  capture reviewed |
| 18 | [x] | owner | [`/o/acme/p/api/e/production/integrations`](http://localhost:18750/o/acme/p/api/e/production/integrations) | Press Add integration, then Cancel | Three targets; the dialog offers GitHub, Coolify and Convex |  capture reviewed |
| 19 | [x] | owner | [`/o/acme/p/api/e/staging/integrations`](http://localhost:18750/o/acme/p/api/e/staging/integrations) | Look | One target `acme/web-walkthrough` through "acme (GitHub App)" |  capture reviewed |
| 20 | [x] | owner | [`/o/acme/p/api/e/production/activity`](http://localhost:18750/o/acme/p/api/e/production/activity) | Look | Events about `STRIPE_SECRET` and `API_KEY`, the rotation among them |  capture reviewed |
| 21 | [x] | owner | [`/o/acme/p/web`](http://localhost:18750/o/acme/p/web) | Look | `NEXT_PUBLIC_API` (development `http://localhost:3000`) and `SESSION_SECRET` (masked); production "tailnet only" |  capture reviewed |
| 22 | [x] | owner | [`/o/acme/p/web/contract`](http://localhost:18750/o/acme/p/web/contract) | Add `WALKTHROUGH_ITEM`, View diff, Close, Publish revision, Back to editing, Discard (publishing is flow 5) | The diff shows `WALKTHROUGH_ITEM` added; the publish dialog says "Publish this revision?" with a checkbox to acknowledge |  capture reviewed |

### 4.4 Owner: Access Control (about 20 minutes)

| # | Done | Role | Page | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 23 | [x] | owner | [`/o/acme/access`](http://localhost:18750/o/acme/access) | Expand "How access works"; Invite; the menu of Morgan Member: What they received, Make admin, Remove (Cancel each) | Installation Admin, Morgan Member, Robin (pending) |  capture reviewed |
| 24 | [x] | owner | [`/o/acme/access?tab=machines`](http://localhost:18750/o/acme/access?tab=machines) | Expand `billing-worker`, Issue credential (Cancel); its menu; the menu of `ci-deployer`, Reach, credentials and sign-in; Show retired; New machine (Cancel) | ci-deployer, billing-worker (`billing-prod` expires in 2 to 3 days, with a warning), deploy-bot, review-agent; ci-deployer's binding `repo:acme/api:*`; `old-cron` only after Show retired |  capture reviewed |
| 25 | [x] | owner | [`/o/acme/access?tab=roles`](http://localhost:18750/o/acme/access?tab=roles) | Open Deployer; expand Backend services and Platform; New group, New team, New role (Cancel each) | Deployer lists its actions; Backend services has billing-worker; Platform has project api and Morgan Member |  capture reviewed |
| 26 | [x] | owner | [`/o/acme/access?tab=grants`](http://localhost:18750/o/acme/access?tab=grants) | Edit the first Grant, Cancel | Grants for ci-deployer (Deployer), Backend services, review-agent, Morgan Member |  capture reviewed |
| 27 | [x] | owner | [`/o/acme/access?tab=advanced`](http://localhost:18750/o/acme/access?tab=advanced) | Edit the Requirement, Cancel; New requirement, Cancel | production: tailnet `example-corp.ts.net`, `tag:ci`, `tag:prod` |  capture reviewed |

### 4.5 Owner: Connections, Audit, Security, Settings, Freeze, and Deletion (about 25 minutes)

| # | Done | Role | Page | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 28 | [x] | owner | [`/o/acme/connections`](http://localhost:18750/o/acme/connections) | New connection; the menu of GitHub (acme); Replace credential of Coolify (prod); the GitHub App menu, Rotate key; Connect an installation (Cancel each) | GitHub (acme) "Token expires Jan 1, 2031", Coolify (prod), Convex (prod) "All targets paused", App `varlatch-walkthrough`, acme (GitHub App) |  capture reviewed |
| 29 | [x] | owner | [`/o/globex/connections`](http://localhost:18750/o/globex/connections) | Register an App, Cancel; Import an App, Cancel | Both dialogs open; Import asks for App ID and private key |  capture reviewed |
| 30 | [x] | owner | [`/o/acme/connections/github-app`](http://localhost:18750/o/acme/connections/github-app) | Open it | "Nothing to finish here" and "Back to Connections" |  capture reviewed |
| 31 | [x] | owner | [`/o/acme/audit`](http://localhost:18750/o/acme/audit) | Expand the first event; Project filter; Revoke the first webhook (Cancel); Edit a webhook (Cancel) | "Live"; webhooks `.../walkthrough/all` and `.../walkthrough/values`; "Export NDJSON"; the filter offers api and web |  capture reviewed |
| 32 | [x] | owner | [`/o/acme/security`](http://localhost:18750/o/acme/security) | Type a reason, Freeze organization, Cancel; the mode list of Admin step-up (Escape); Audit export: Change, Cancel; Replace key, Cancel | Controls at Report; the list offers Off, Report, Enforce; audit export to bucket `audit-walkthrough`, governance |  capture reviewed |
| 33 | [x] | owner | [`/o/acme/settings`](http://localhost:18750/o/acme/settings) | Show the server capabilities; Delete organization, Cancel | Acme / acme; `realtime.sse` among the capabilities; the delete dialog asks for `acme` |  capture reviewed |
| 34 | [x] | owner | [`/o/frozen-co/projects`](http://localhost:18750/o/frozen-co/projects) | Look | Banner "This organization is frozen for an incident", reason INC-42; "This page is not available while the organization is frozen" |  capture reviewed |
| 35 | [x] | owner | [`/o/frozen-co/security`](http://localhost:18750/o/frozen-co/security) | Lift freeze, Cancel | INC-42, "Lift freeze" |  capture reviewed |
| 36 | [x] | owner | [`/o/frozen-co/access`](http://localhost:18750/o/frozen-co/access) | Look | People readable: Installation Admin |  capture reviewed |
| 37 | [x] | owner | [`/o/sunset/settings`](http://localhost:18750/o/sunset/settings) | Cancel deletion, then Keep it scheduled | Sunset Ltd, "This organization is being deleted" (in 29 or 30 days), "Cancel deletion" |  capture reviewed |
| 38 | [x] | owner | [`/o/sunset/projects`](http://localhost:18750/o/sunset/projects) | Look | Banner "This organization is being deleted"; project legacy |  capture reviewed |

### 4.6 Owner: Account, Installation, Device Sign-In, Step-Up Approval, and Maintenance (about 14 minutes)

| # | Done | Role | Page | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 39 | [x] | owner | [`/account`](http://localhost:18750/account) | Look | Profile; the name is Installation Admin (expected: the first admin is always named so) |  capture reviewed |
| 40 | [x] | owner | [`/account/security`](http://localhost:18750/account/security) | Open the passkey's menu | Your passkey, "Add passkey" |  capture reviewed |
| 41 | [x] | owner | [`/account/sessions`](http://localhost:18750/account/sessions) | Sign out everywhere else, Cancel | "This browser" and one CLI credential, "recovery credential" (the kit's) |  capture reviewed |
| 42 | [x] | owner | [`/installation/settings`](http://localhost:18750/installation/settings) | Create an archive (how to): press "in a container", then "as a service", close; Run a restore drill (how to), close | Archives on record 1 (2 after flow 10), verified, with a Newest archive id ("has not been delivered to a destination" is right: no bucket here). The first says `sudo varlatch admin backup run`, or `docker exec ... varlatch admin backup run`; the second `sudo varlatch setup --restore`. Nowhere `--dir`, Compose or `.env`; no warning about a remote copy |  capture reviewed |
| 43 | [x] | owner | [`/installation/settings?tab=tailnet`](http://localhost:18750/installation/settings?tab=tailnet) | Press "in a container", then "as a service" | Not configured, with the lines for `varlatchd.conf`: `tailnet = on` to `tailnet_https_port = 8688`; the key file's path and the restart follow the choice. No sidecar, no Coolify variables |  capture reviewed |
| 44 | [x] | owner | [`/o/acme/projects`](http://localhost:18750/o/acme/projects) | Open the Organization switcher: press the dot at Installation settings; then the dot in [`/o/acme/settings`](http://localhost:18750/o/acme/settings). On the Release tab press "in a container", then "as a service" | Both lead to the Release tab: `sudo varlatch upgrade`, or deploying the image by its digest; "0.99.0 is available", "This installation runs 0.50.0". (0.99.0 is the kit's fake: its GitHub link does not exist, do not follow it) |  capture reviewed |
| 45 | [x] | owner | [`/installation/settings?tab=outbound`](http://localhost:18750/installation/settings?tab=outbound) | Look | The allow list: entries of `127.0.0.1/32`; it is set as `outbound_allow` in `varlatchd.conf` |  capture reviewed |
| 46 | [x] | owner | [`/device`](http://localhost:18750/device) | With flow 7: the code entry, then the confirmation | "Approve this sign-in?", Installation Admin, the code, "Approve with passkey" and Deny |   |
| 47 | [x] | owner | `/approve/...` | With flow 8, or run `./g1 approval` and open the address | "Turn off the admin-step-up security control of Acme", Acme, report to off, a countdown, "Approve with passkey" and Deny |   |
| 48 | [x] | owner | [`/o/acme/projects`](http://localhost:18750/o/acme/projects) | Last, with row 3: keep the page open, run `./g1 maintenance`, then click Access, Audit, Settings (do not reload: a reload shows the full maintenance screen instead) | "Maintenance in progress" banner on top; it goes away by itself after 2 minutes |   |

### 4.7 Member Role (about 12 minutes)

| # | Done | Role | Page | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 49 | [x] | member | [`/o/acme/projects`](http://localhost:18750/o/acme/projects) | Look | `web` and `api` listed (New project shows; the server refuses it) |  capture reviewed |
| 50 | [x] | member | [`/o/acme/p/web`](http://localhost:18750/o/acme/p/web) | Look | `NEXT_PUBLIC_API`, `SESSION_SECRET` (masked) |  capture reviewed |
| 51 | [x] | member | [`/o/acme/p/web/contract`](http://localhost:18750/o/acme/p/web/contract) | Look | Readable; `NEXT_PUBLIC_API` |  capture reviewed |
| 52 | [x] | member | [`/o/acme/p/web/e/production`](http://localhost:18750/o/acme/p/web/e/production) | Look | `NEXT_PUBLIC_API` listed, "tailnet only" |  capture reviewed |
| 53 | [x] | member | [`/o/acme/p/web/activity`](http://localhost:18750/o/acme/p/web/activity) | Look | "You cannot read the audit log", in words (audit.read is organization-wide; a Grant on a project does not open it, as on 0.23.0) |  capture reviewed |
| 54 | [x] | member | [`/o/acme/p/api`](http://localhost:18750/o/acme/p/api) | Look | Items with PORT 3000 and 8080; Secrets stay masked |  capture reviewed |
| 55 | [x] | member | [`/o/acme/access`](http://localhost:18750/o/acme/access) | Look for Invite | "You do not have access to see members"; no Invite, no "No members yet" |  capture reviewed |
| 56 | [x] | member | [`/o/acme/connections`](http://localhost:18750/o/acme/connections) | Look | "Could not load the GitHub App", "Not authorized for this action", "No connections yet" (they are there, the member may not read them) |  capture reviewed |
| 57 | [x] | member | [`/o/acme/audit`](http://localhost:18750/o/acme/audit) | Watch it for 20 seconds | "You cannot read the audit log", "Reading it needs the audit.read permission"; stays still (no loading bars coming back) |  capture reviewed |
| 58 | [x] | member | [`/o/acme/security`](http://localhost:18750/o/acme/security) | Look | Incident freeze, Controls, Checklist; no Freeze button ("Only an admin of this organization can freeze it") and no mode lists |  capture reviewed |
| 59 | [x] | member | [`/o/acme/settings`](http://localhost:18750/o/acme/settings) | Look | Acme, read; no delete button ("Only an admin of this organization can delete it") |  capture reviewed |
| 60 | [x] | member | [`/account`](http://localhost:18750/account) | Look | Profile of Morgan Member |  capture reviewed |
| 61 | [x] | member | [`/account/sessions`](http://localhost:18750/account/sessions) | Reload it twice with the Network tab open | Sessions; no request to `/v1/organizations//identities` |  capture reviewed |
| 62 | [x] | member | [`/installation/settings`](http://localhost:18750/installation/settings) | Look | "Backup status is unavailable", "Installation Admin authority is required" |  capture reviewed |

## 5. Interactive End-to-End Flows (about 45 minutes)

| # | Done | Flow | Do | Pass when | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | [x] | Enrollment and passkey sign-in | At the start: open the Owner link of `./g1 status`, type a name, Create passkey. Later, on [`/o/acme/projects`](http://localhost:18750/o/acme/projects), press the sign-out icon, then Continue with passkey | Enrolled; signed out to "Sign in to Varlatch" with the address unchanged; signed in back on `/o/acme/projects` |   |
| 2 | [x] | Passkey cancel recovery | Sign out, Continue with passkey, cancel the browser's prompt, then try again and complete it | "Sign-in failed: ..." in plain words, the button works again, no uncaught error in the console |   |
| 3 | [x] | Create an Organization from Welcome | At the start: Create an organization, name `Acme` (slug `acme`), Create organization | Lands on `/o/acme/projects`; about 5 seconds later `./g1 status` says READY (reload) |   |
| 4 | [x] | Write, reveal, copy, rotate | [`/o/acme/p/api/e/development`](http://localhost:18750/o/acme/p/api/e/development): edit `API_KEY`, type `walkthrough value A`, Enter, Review, Save changes. Click `API_KEY`: Reveal, Copy, Rotate, `walkthrough value B`, Start rotation, Finish rotation | Masked before Reveal; Reveal shows A; Copy pastes A; the rotation shows its grace time, then finishes; Reveal shows B |   |
| 5 | [x] | Publish a managed Contract | [`/o/acme/p/web/contract`](http://localhost:18750/o/acme/p/web/contract): add `WALKTHROUGH_ITEM`, View diff, Close, Publish revision, tick the box, Publish revision | The diff shows it added; afterwards 3 items and a new active revision |   |
| 6 | [x] | Live updates over SSE | Keep [`/o/acme/audit`](http://localhost:18750/o/acme/audit) open; in the terminal: `./g1 cli values set PUBLIC_URL http://localhost:3001 --replace PUBLIC_URL -e development` | A new first row "changed PUBLIC_URL in api / development" within a few seconds, without a reload (do flow 7 first: it signs this CLI in) |   |
| 7 | [x] | Device sign-in | `./g1 cli login --server http://localhost:18750 --start`; enter its code on [`/device`](http://localhost:18750/device), Approve with passkey; `./g1 cli login --server http://localhost:18750 --wait`; `./g1 cli project list` | "Sign-in approved"; "Logged in"; the list says `api  (API, git)` and `web  (Web, managed)` |   |
| 8 | [x] | Step-up approval | `./g1 cli security set admin-step-up off --org acme`; open the address it prints; Approve with passkey. Then put it back: `./g1 cli security set admin-step-up report --org acme` | The page names the change; the CLI says "Approved" and finishes by itself; Audit lists "changed security control admin-step-up from report to off" |   |
| 9 | [x] | Freeze and lift; schedule and cancel deletion | [`/o/globex/security`](http://localhost:18750/o/globex/security): reason `G1`, Freeze organization, type `globex`. Look at [`/o/globex/projects`](http://localhost:18750/o/globex/projects); run `./g1 cli project create frozen-test --org globex --server http://localhost:18750`. Lift freeze with the passkey. [`/o/globex/settings`](http://localhost:18750/o/globex/settings): Delete organization, type `globex`, Schedule deletion; look at Projects; Cancel deletion | Banner "This organization is frozen for an incident", Projects not available, the CLI answers `ORGANIZATION_FROZEN`; after the lift no banner. "Live updates reconnecting" may show for a few seconds at the freeze: the live stream closes and opens again without Globex. It goes away by itself, and does not come back. Banner "This organization is being deleted"; after Cancel no banner |   |
| 10 | [x] | Backup archive visibility | `./g1 backup`, then reload [`/installation/settings`](http://localhost:18750/installation/settings) | "Archive created"; Archives on record 2, the new one newest |   |
| 11 | [x] | Theme and narrow viewport | [`/o/acme/settings`](http://localhost:18750/o/acme/settings): Light, Dark, System. Then device mode (Ctrl+Shift+M) at 390 px: Projects, [`/o/acme/p/api`](http://localhost:18750/o/acme/p/api), Access, Audit, Settings; open one dialog | Readable in both themes; usable at 390 px, and none of these pages scrolls sideways |   |
| 12 | [x] | Keyboard only | From Projects without the mouse: Tab through the shell and a page's tabs, Ctrl+K, `?`, open and Escape a dialog | Focus always visible; Escape closes; focus returns |   |
| 13 | [x] | Live tailnet browser access | The real-Tailscale step, Section 5.1 (about 12 minutes), done before this commit was chosen: cite its record in Section 6. Without it: N/A on this server, tick and cite, see Section 6 | Every line of Section 5.1 as it says; or the cited record accepted by the owner |   |
| 14 | [x] | GitHub App registration round trip | N/A here (the kit's GitHub is a fake): tick and cite, see Section 6 | Cited record accepted by the owner |   |
| 15 | [x] | Help texts | `./g1 cli --help`, `./g1 cli upgrade --help`, `./g1 cli tailnet --help`, `./g1 cli agents guide self-hosting` | The host commands of an installation as a service: `setup`, `upgrade` (with `--rollback` in its own help), `admin backup run`, `migrate`, `tailnet repin`. A Compose installation is named only to point to `varlatch-ts` or `varlatch migrate`; no `adopt` and no `--dir` to type |   |
| 16 | [x] | The host commands' view (read only) | `./g1 host` | `held` is false (this server was not restored from an archive), and the help names `admin restore` |   |

### 5.1 The real-Tailscale step (flow 13, about 12 minutes)

On its own throwaway server, in a container on this workstation, whose node joins
the owner's throwaway tailnet; a second container is the browser's node there, and
the workstation joins nothing (`TAILSCALE.md` of the kit: the tailnet, the phone,
`./g1 handoff credentials`). It proves `varlatch setup` with a tailnet and the
browser endpoint, not a handoff between two nodes. The dashboard stays at its
localhost address; what goes over the tailnet is the protected value.

1. `./g1 tailnet start`; in a second terminal `./g1 tailnet browser`, the window
   for all of it; then `./g1 tailnet setup`, and answer as it says. It must ask for
   the address, for the key's file, and "Let the dashboard read tailnet-protected
   values, over HTTPS on the tailnet (port 8688)?", and show the link. Open the
   link in that window, create the passkey (your phone), paste the two keys back.
   It ends with `varlatch doctor`, whose `tailnet.pin` may say that the node has
   not joined yet.
2. `./g1 tailnet seed`, then reload the dashboard: Acme, project `web`,
   environment `test`.
3. Installation settings, Tailnet: the node `varlatch-g1` and its tag, your
   tailnet, the port 8687 and the browser endpoint on 8688, its certificate,
   every check passing.
4. Acme, Access, Advanced, New requirement: environment `test` of `web`,
   Connect to tailnet, Add this device (`varlatch-g1-client`), create it. If the
   first Connect fails, allow the browser's local network prompt and press it
   again; write it in Notes.
5. `web`, `test`: Reveal shows `read over the tailnet`. Export .env with
   "Include 1 secret" ticked (or as many as it counts): the file has it too
   (delete the file). The browser's console (F12) has no line about the Content
   Security Policy.
6. `./g1 tailnet off`, reload, Reveal: refused, in words. `./g1 tailnet on`: it
   works again.
7. `./g1 tailnet check`: every line says PASS. (`varlatch doctor` lists
   backups as an advisory: no bucket here.)
8. `./g1 tailnet stop`. Delete the devices `varlatch-g1` and `varlatch-g1-client`.

## 6. Findings and Exceptions

The owner's findings:

None.

From the pre-review of the pictures, cosmetic or not new, planned after
0.50.0: the tailnet notice doubles the word "tag"; an open grace window shows
no remaining time; one Convex audit event ends after "convex:"; some labels
are cut off; "1 grant follow this role"; two audit events show raw names; the
Organization delete dialog is taller than a 900 px window and scrolls; a
member with `audit.read` on one project sees the refusal on its Activity tab,
because reading the log is organization-wide, as on 0.23.0.

Notes:

- Flow 13: done as Section 5.1 on 2026-11-25, on 0.50.0-rc.4 (526fac1b),
  before this commit was chosen: `./g1 tailnet check` passed on every line and
  the owner did every step in a browser. Record: internal
  `docs/evidence/2026-11-25-tailscale-run/`.
- Flow 14, N/A on this server: the only live registration round trip on
  record is the TypeScript server's (internal
  `docs/evidence/adr-0047-github-app-spike/REAL-CHECK.md`, 2026-10-09). On
  the Go server the round trip is covered by the conformance sync suite
  against a fake GitHub in the companion CI run. The owner decides whether
  that is enough.
- Not walked here, because it is the host's and has no page: `varlatch
  setup` on systemd, `varlatch upgrade` and its `--rollback`, and the hold
  after a restore. What shows them: `upgrade-systemd.yml` at this commit
  (https://github.com/varlatch/varlatch/actions/runs/45631268871), `go/install/test-setup.sh` in CI, and
  flow 16's one line. An upgrade that holds the server shows people the
  maintenance screen of rows 3 and 48.
- The first admin is shown as Installation Admin whatever name is typed at
  enrollment, as on the TypeScript server.
- An open page shows the maintenance banner from its next request on; a full
  reload shows the maintenance screen instead.

## 7. Owner Sign-Off

- **Owner:** Jeremy Deceuster
- **Date (UTC):** `2026-11-25 16:05 UTC`
- **Candidate commit:** `ff7f191fc2182625a6371ec936a28950d19916a1`
- **`varlatchd` SHA-256:** `d3bc13908d02471ee679829058eedc8f09691dfa605d5ae618a81979e8f93625`
- **Verdict:** `PASS`
- **Notes:** Scripted capture reviewed, interactive flows done by hand.
