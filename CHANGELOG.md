# Changelog

Notable changes to Varlatch, newest first. Varlatch is before 1.0: a minor
release may change the `/v1` API, the CLI, configuration, or the database
schema, and its entry says what to do. Only the latest release receives
fixes.

## Unreleased (0.11.0)

### Contracts

- `.env.schema` conditions name your Varlatch environments directly:
  `@required=env(production, staging)` requires an item in those
  environments, and `@required=tier(production)` in every environment of a
  tier. Names are resolved to environment IDs when you push, and an unknown
  name fails the push and lists the environments that exist. A pushed
  revision keeps the IDs: renaming or deleting an environment later never
  changes it. A later push resolves the names again, so if a name was reused
  by a new environment, that push selects the new one.
- `forEnv(...)` is no longer accepted in `.env.schema`. The parse error names
  the replacement: `@required=forEnv(prod)` becomes
  `@required=env(production)`, using the project's environment names, or
  `@required=tier(production)`.
- A comment after a value is now a comment: `PORT=8080 # listen port` gives
  the default `8080`. Before, the comment became part of the default. A
  decorator after a value, text after a quoted value, and an unterminated
  quote are now errors instead of being read into the default. A `#` with no
  whitespace before it, or inside quotes, is still part of the value.
- The environment-name mapping is removed. It only translated `forEnv(...)`
  names, which schemas no longer use. Removed with it:
  - the `varlatch varlock-mapping` command;
  - the mapping card on the dashboard's contract page;
  - the `GET`, `PUT`, and `DELETE` endpoints under
    `/v1/organizations/{org}/projects/{project}/varlock-mapping`, which now
    answer `404`;
  - the SDK methods `getVarlockMapping`, `setVarlockMapping`, and
    `removeVarlockMapping`.

  Deleting an environment is no longer blocked by a mapping entry. It is
  still blocked while the active contract references the environment.
- Contract revisions record their Contract Semantics version: the rules for
  requiredness, validation, and conversion they are evaluated with. Every
  existing revision is version 1 and keeps its content hash. A new project's
  first revision gets version 2, which adds conversion to typed values and
  bounds numbers: a number whose magnitude exceeds 9007199254740991
  (2^53 - 1) is invalid. A push or edit keeps the active revision's version,
  and `varlatch contract push --semantics latest` moves to the newest.
  Contract revisions in the API carry `semanticsVersion`, and `/v1/meta`
  lists `semanticsVersions`. See
  [Contract Semantics](docs/reference/contract-semantics.md).
- The dashboard's type help now matches the rules. It said booleans accept
  `yes` and `no`, which validation never accepted.
- Validation checks values as `varlatch run` delivers them, with `${NAME}`
  references expanded. Before, it checked the stored text: `${BASE}0` was
  reported as an invalid number although it is delivered as `8080`, and a
  value whose reference stays literal when delivered passed. Such a value
  is now reported as `unresolved`, and `varlatch validate` exits 1, or 2
  when only the caller's missing read access to non-sensitive values keeps
  it literal. Values read only to expand a reference are audited before
  they are decrypted.

### Security

- Every retrieval (effective configuration, disclosure, validation, and
  Capability exercise) reads everything from one read-only database
  snapshot: the organization, project, and environment, authorization
  inputs, the active contract revision, values, and the ciphertext it may
  decrypt. A write, rotation, contract activation, or Grant change that
  commits while a request is in flight is invisible to that request, never
  half-applied.
- Each decryption follows an audit commit that names its exact version, and
  a failed commit stops the request. Values decrypted only to expand
  `${NAME}` references used to be audited after they were decrypted. They
  are now audited before, one reference level at a time.
- Authorization is effective at the snapshot boundary: a revocation that
  commits after a request's snapshot began does not affect that request.
  The next request sees it.

### Retrieval

- Strict retrieval: `POST
  /v1/organizations/{org}/projects/{project}/environments/{environment}/retrievals`
  with `{"mode": "strict"}` returns, from one snapshot and in one request,
  every value the caller may receive, the state manifest and its
  `stateDigest`, the caller view, the active contract (with
  `contract.read`), and the validation of exactly the values returned. Each
  class of value is authorized separately: without `secret.reveal`, the
  non-sensitive values still arrive and the Secrets are reported as
  withheld. A failure after the snapshot returns an error and no values.
  SDK: `strictRetrieval()`. `/v1/meta` lists `retrieval.strict`.
- Effective configuration responses, and disclosure responses for callers
  who can read metadata, carry the state manifest, `stateDigest`, and a
  caller view (`retrieval.manifest`). The manifest lists the environment,
  the active contract revision and its semantics version, and every item's
  source and version IDs. It holds identifiers only, never values or
  anything derived from them, and its digest is the same for every caller
  looking at the same state. The caller view lists what this caller was not
  given and which references stayed literal for it.

### CLI

- `varlatch run --strict` starts the command only if the environment it
  would receive satisfies the active Contract. It retrieves everything in
  one request, applies Contract defaults only to items with no stored value
  (never to withheld ones), takes values from your shell only for names
  given with `--allow-inherited NAME`, and validates every value exactly as
  the command will receive it. Any violation (missing, withheld,
  parent-only, invalid, or a `${NAME}` reference left literal, and also no
  active Contract, no `contract.read`, or an unsupported semantics version)
  starts nothing and exits 78, listing every violation by name, never by
  value. The command receives `VARLATCH_RUN_CONTEXT`, which records what the
  server did and how each item was delivered. See
  [Strict startup](docs/reference/strict-startup.md). `--strict` cannot yet
  be combined with `--agent-safe`.

### Upgrading

- Every `varlatch run`, including a default one, now removes a
  `VARLATCH_RUN_CONTEXT` inherited from an outer run. This is the one change
  to a default run. The name is reserved: the server refuses a Contract item
  or a stored value called `VARLATCH_RUN_CONTEXT`.

- A disclosure or Capability exercise whose references are nested now
  records one `value.disclosed` event with `mode: "reference-expansion"` per
  reference level, instead of one for all levels.
- The upgrade drops existing environment-name mapping entries (a new schema
  migration). Contract revisions are unchanged: they store environment IDs,
  not names. Audit history keeps its `contract.varlock_mapping_set` and
  `contract.varlock_mapping_removed` events. Backups taken with 0.10.0 or
  0.10.1 restore into this release and are migrated forward.
- Existing projects keep version 1 rules. To adopt version 2, push with
  `varlatch contract push --semantics latest` and review the activation,
  which shows the version change.
- Validation results can change for values that contain references: they
  are now checked as delivered, and a reference that stays literal makes the
  report invalid. The validation report gains an `unresolved` list.
- A `.env.schema` with comments after values gives different defaults when
  pushed with this release's CLI. Review the activation's changes before
  activating. A file that uses `forEnv(...)` must switch to `env(...)` or
  `tier(...)` first.

## 0.10.1 (2026-09-25)

### Fixed

- A restore now leaves the whole installation running. Before, it started
  only the database, varlatchd, and Convex, so after restoring onto a stopped
  or new host the dashboard and the ingress proxy stayed down until you ran
  `docker compose up -d`, and `varlatch doctor --gate` failed. When restore
  finishes it now points you to `varlatch doctor` and a fresh archive.
- Installations that use the tailnet ingress with secrets in files no longer
  print `The "VARLATCH_RUNTIME_PASSWORD" variable is not set` on every
  Compose command.
- `varlatch upgrade --release-dir` no longer says it is fetching the release
  from GitHub. It reads only the files in that directory.

### Upgrading

No database migration: 0.10.1 uses migration 20, like 0.10.0.

- From 0.10.0: download `varlatch-cli-0.10.1.cjs` from the `v0.10.1`
  release, check it against `SHA256SUMS`, and run `node
  varlatch-cli-0.10.1.cjs upgrade 0.10.1 --dir /YOUR/COMPOSE/DIRECTORY
  --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`. Then replace the host CLI
  with `varlatch-cli-0.10.1.cjs`.
- From 0.8.0 or 0.9.0: follow the 0.10.0 instructions below with the 0.10.1
  CLI and version.
- 0.10.1 restores everything 0.10.0 restores, and archives from 0.10.0.

## 0.10.0 (2026-09-25)

**Before upgrading:** validation changed. `varlatch validate` and the
dashboard now evaluate only the items the caller may read, and report the
rest as not evaluated. The CLI then prints `INCOMPLETE` and exits with a new
code, `2`, where it used to report a verdict. CI jobs that validate with an
identity lacking `secret.reveal` or `config.value.read` need those actions
granted, or must treat exit code `2` as incomplete. See Security and
Upgrading below.

### Project

- Varlatch is open source: AGPL-3.0-or-later for the secret store daemon, the
  dashboard, and the dashboard backend functions, and Apache-2.0 for
  everything else. See [`LICENSE`](LICENSE).
- Vulnerabilities are reported privately, as [`SECURITY.md`](SECURITY.md)
  describes.

### Security

- Validation no longer reveals anything about values you cannot read. Before,
  anyone who could see an environment could validate it and learn whether
  each value, Secrets included, passed its contract checks. Now each check
  needs the right to read what it describes: `secret.reveal` for Secrets
  (including any Tailnet Requirement), `config.value.read` for other values,
  and `config.metadata.read` to report missing items. `secret.use` alone is
  not enough.
- Items you cannot read are listed as not evaluated, with the permission they
  need, and an environment is reported as valid only when every item was
  checked. `varlatch validate` prints `INCOMPLETE` and exits with a new code,
  `2`, in that case; `1` still means invalid. The dashboard shows
  valid, invalid, or incomplete.
- Every decryption for validation is recorded in the audit log first
  (`secret.validated` and `value.validated`, naming the item versions). The
  results themselves are never logged.

### Self-hosting

- `varlatch setup` creates an installation interactively or from flags:
  generated secrets kept in files rather than environment variables, an
  escrow of the root key, and a choice of access. **Public** gets HTTPS
  certificates automatically, **tailnet** serves HTTPS on your Tailscale
  network only, and **external** sits behind your own proxy.
- `varlatch adopt` brings an existing installation under the same
  management, step by step and reversibly.
- `varlatch doctor` checks an installation's health without changing
  anything. `varlatch upgrade` completes only when the new release passes its
  health gate, and refreshes the access overlays the installation uses.
- The dashboard reaches its live backend on the same origin (`/convex`), so an
  installation needs one public address. The dashboard and the API keep
  working while the live backend is down, and fail fast instead of hanging.
- The Coolify deployment is generated from the canonical Compose files, and
  each service receives only its own secrets.

### Backups

- Backups no longer pause the service: the secret store keeps serving while a
  consistent snapshot is taken.
- Archives hold the secret store only. The dashboard backend is rebuilt on
  restore instead of restored, which makes archives smaller and restores
  simpler.
- API clients, the CLI, and the dashboard wait out maintenance windows and
  say so, instead of failing.

### Releases

- Images for linux/amd64 and linux/arm64, each with a provenance attestation
  and an SBOM. Releases from the public repository sign the images and
  `SHA256SUMS`; [verifying a release](docs/operations/verify-release.md)
  explains how to check.
- `THIRD-PARTY-NOTICES.md` lists every third-party component with its
  license, in each image and release.
- Smaller images: the daemon image no longer ships test tooling, and the
  deploy image installs only runtime dependencies.
- `pnpm dev:up` runs the whole stack from a checkout, with synthetic data.

### Fixed

- The values editor commits against the versions you reviewed. Before, when
  another client changed a value while the review dialog was open, the
  dashboard's live update made your commit overwrite that change without a
  conflict. Now it is rejected as changed since review, and your draft is
  kept.

### Upgrading

Releases now come from `varlatch/varlatch` on GitHub. Database schema:
migration 20.

- From 0.8.0 or 0.9.0: download `varlatch-cli-0.10.0.cjs` from the `v0.10.0`
  release, check it against `SHA256SUMS`, and run `node
  varlatch-cli-0.10.0.cjs upgrade 0.10.0 --dir /YOUR/COMPOSE/DIRECTORY
  --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`. The upgrade captures and
  verifies an archive before applying migration 20, and completes only once
  the new release passes its health gate. That archive is still taken the
  old way, with the installation briefly paused, because online capture
  needs 0.10.0 to be running; plan a short maintenance window.
- From the published 0.7.0: the offline path described under 0.8.0 still
  applies with this CLI.
- Then replace the host CLI with `varlatch-cli-0.10.0.cjs`.
- Installations set up by hand keep working as they are. `varlatch doctor`
  lists them as not adopted, and `varlatch adopt` moves them to managed
  configuration one reversible step at a time.
- 0.10.0 restores archives from 0.7.0 (migrations 16 and 18), 0.8.0
  (migrations 18 and 19), 0.9.0 (migration 19), and builds made between
  0.9.0 and 0.10.0 (migration 20).

CI jobs that run `varlatch validate` with an identity that lacks
`secret.reveal` or `config.value.read` on the environment now get exit code
`2` (incomplete) instead of a verdict. Grant the identity those actions if it
should validate every item.

## 0.9.0 (2026-09-23)

### Machine identities

- Revoke individual service and OIDC credentials of a machine identity,
  including your own, and list credential metadata.
- Retire an identity, revoking all of its credentials in one transaction,
  and reactivate it later; its credentials stay revoked. Identities are never
  deleted.
- Rename identities; the audit log records the old and the new name.
- Last-used times for credentials and identities.
- CLI: `varlatch identity list|rename|retire|reactivate` (retiring requires
  `--confirm <name>`) and `varlatch credential list|revoke`. The dashboard's
  Machines tab has the same actions.

Database schema: migration 19.

### Backup operations

- The operator CLI is a release asset, `varlatch-cli-0.9.0.cjs`: one file,
  Node 22 or newer, no checkout or build. The varlatchd image carries the same
  file at `/opt/varlatch/varlatch.cjs`.
- The reference host job verifies every archive right after capture, and a
  failed check fails the run.
- The remote-copy warning appears only when the latest remote check failed
  or none passed within 30 days.
- Reference systemd tooling (`infra/host-backup`) takes its scripts and CLI
  from the running release, so upgrades need no host step.
  `verify-remote.sh` verifies the remote copy periodically.
- The SDK retries `503 MAINTENANCE` responses and honors `Retry-After`.
- PostgreSQL's healthcheck probes over TCP, closing a first-boot race, and
  the dashboard and Tailscale containers gained healthchecks.

### Upgrading

- From 0.8.0: download `varlatch-cli-0.9.0.cjs`, check it against
  `SHA256SUMS`, and run `node varlatch-cli-0.9.0.cjs upgrade 0.9.0 --dir
  /YOUR/COMPOSE/DIRECTORY --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`.
  The upgrade captures and verifies an archive before applying migration 19.
- From 0.7.0: the offline path described under 0.8.0 applies unchanged with
  this CLI.
- Then replace the host CLI with `varlatch-cli-0.9.0.cjs`. With the reference
  host tooling, reinstall `run.sh` and `verify-remote.sh` from this release
  once; later releases update them automatically.
- 0.9.0 restores archives from 0.7.0 (migrations 16 and 18) and 0.8.0
  (migration 18).

## 0.8.0 (2026-09-22)

### Installation backup and recovery

- Encrypted backups that only the operator can create, standalone
  verification, delivery to S3-compatible storage, and restore onto a fresh
  host.
- A restore stays isolated through daemon failures and host restarts, and an
  interrupted restore can be retried.
- The Installation settings page shows delivery and verification for each
  archive.
- Verification checks integrity, compatibility, and that the keys match. It
  does not load the dumps, so it is no substitute for a restore rehearsal
  against your own storage.

### Upgrading

- Keep the root key and a separate backup encryption key off the host.
  Recovery needs both keys, the archive, and a compatible release.
- Upgrade with the 0.8.0 CLI. From the published 0.7.0 (migration 16), the
  upgrade takes an offline capture: services stay stopped until it succeeds,
  so plan downtime. A source-built 0.7.0 at migration 18 takes an ordinary
  capture. Other versions are refused. The target schema is migration 18, on
  PostgreSQL 17.
- Both Compose variants need the shared `varlatch-state` volume and the
  Convex supervisor file.
- Turn off automatic deployments that change the schema, for example in
  Coolify. The old unencrypted `pg_dumpall` job is removed; existing dump
  volumes are kept.
- To retry a failed upgrade, restore the original archive. Never run older
  binaries against a database that has been migrated forward.

See [backups and recovery](docs/operations/backup.md) and the
[first-time B2 setup](docs/operations/backup-b2.md).

## 0.7.0 (2026-09-17)

- **Sync Targets.** varlatchd pushes an environment's configuration to other
  platforms, so a rotation reaches every place that uses the value. A
  platform connection authenticates once per account; a sync target binds one
  environment to one destination as an explicit, audited disclosure, allowed
  only for someone who may read those values.
- Pushes converge on the destination's state, deletions are opt-in, and a
  periodic repair pass fixes drift.
- Adapters for GitHub Actions (encrypted secrets), Coolify (host-pinned, with
  optional redeploy), and Convex. There is deliberately no generic
  push-to-URL.
- Sync is opt-in at every level. `VARLATCH_SYNC=off` disables it for an
  installation, and `varlatch sync push` pushes from the CLI where the server
  may not reach out.
- Dashboard: integrations per environment with delivery state per value, and
  connections per organization.

## 0.6.0 (2026-09-16)

- Roles, groups, teams, requirements, and audit webhooks can be edited in
  place, protected against concurrent edits, with the old and new values in
  the audit log. Editing a role updates every grant that uses it.
- Changing a grant replaces it atomically, and authorization audit events
  record the facts each decision used.
- Search configuration item names across projects. Search matches names only,
  never values, and only in environments you may read.

## 0.5.0 (2026-09-16)

- **Rotation without downtime.** A rotated secret keeps its previous value
  available alongside the new one for a grace period.
- **Custom roles, groups, and teams.** A role is a named set of actions, a
  group a set of identities, and a team a group that owns projects. All of
  them resolve to plain grants, so access stays default-deny.

## 0.4.0 (2026-09-16)

- OIDC sign-in for CI, with GitHub Actions supported out of the box.
- Time limits and use budgets for service credentials.
- Signed audit webhooks.
- Value references (`${NAME}`), expanded on the server.
- Escrow for the root key: a passphrase-protected export, or k-of-n shares.
- An MCP server, `@varlatch/mcp-server`, read-only by default.
- The dashboard updates live from the audit stream.

## 0.3.1 (2026-09-09)

- `varlatch run --agent-metadata`: the broker gives an agent a read-only
  credential, valid for at most an hour, to read configuration metadata,
  revoked when the run ends.

## 0.3.0 (2026-09-09)

- **The credential broker.** `varlatch run --agent-safe` starts an agent with
  placeholders and no Varlatch credential. A local broker substitutes the real
  values only in requests to allowed destinations, and varlatchd authorizes
  and audits every use before decrypting anything.
- The dashboard lists and revokes the capabilities agents hold.

## 0.2.0 (2026-09-09)

- The complete dashboard: changes applied as one set, explicit disclosure of
  secrets, a matrix of values per environment, access management for people
  and machines, the audit timeline, the contract editor, a command palette,
  passkey management, and a getting-started checklist.
- Grants scoped to a single environment.

## 0.1.0 (2026-09-08)

The first release:

- The encrypted secret store, with `kek verify` for the root key.
- Passkey-only sign-in, with bootstrap, recovery, and invitations as
  enrollment links.
- Grants and requirements, including retrieval restricted to your Tailscale
  network.
- Configuration contracts, managed in the dashboard or kept in the
  repository, with validation.
- The append-only audit log with NDJSON export.
- The `/v1` API, the SDK, and the CLI, including sign-in through the browser.
- The dashboard, with its live backend on Convex.
- Deployment with Docker Compose or Coolify, and digest-pinned release images.
