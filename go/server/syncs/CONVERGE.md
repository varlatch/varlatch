# The converge engine's transaction map

Feature-parity decision 7 (ADR-0059 amendment 4): before the engine is
ported, every commit the TypeScript engine makes, in order, on every path.
The source is `services/varlatchd/src/domain/syncdelivery.ts` at v0.22.0
(unchanged since; line numbers are that file's). For each commit:
- the statement;
- the row it guards on: the Target's generation, and the lock the
  TypeScript transaction takes on it;
- what comes before and after it: a provider call (P), a decryption (D),
  or another commit (C).

**The Go engine** (`converge.go`) makes each of these commits as one write
job (`write.Writer.Job`), in the same order, under the same guard, and
merges none. A merge needs the proof decision 7 describes, and comes in a
later pull request with its crash and fence tests, if one is worth it.

In Go there are no row locks. A write job runs alone on the single writer,
so its guard read and its writes are atomic with respect to every other
job. That gives what `FOR SHARE`, `FOR NO KEY UPDATE` and `FOR UPDATE` give
the TypeScript transactions: a pause, revoke or re-point that fences a run
either commits before the job (which then sees the new generation and
writes nothing) or after it.

The clock: where TypeScript reads `now()`, the database's clock, Go reads
the engine's clock once in the job.

## A pass (`runSyncOnce`, `RunOnce`)

| # | TypeScript | Statement | Guard | Before / after |
|---|---|---|---|---|
| T1 | `scanSyncTriggers` :140 | `INSERT INTO sync_cursor … ON CONFLICT DO NOTHING` | none | first; then reads |
| T2 | `scanSyncTriggers` :174-188 | mark due Targets `needs_sync` (the environments named by non-`sync.*` events, their derived children, Projects of `contract.*` events) | the Targets locked `FOR UPDATE` in id order | after the event read; then T3 |
| T3 | `scanSyncTriggers` :191 | advance `sync_cursor` to the last event read | none | after T2 |
| T4 | `runSyncOnce` :208 | `DELETE FROM sync_runs WHERE deadline <= now()` | none | then the due Targets' read, then each Target in turn |

T1 happens only while the cursor row is missing in Go (once per
installation), and T4 only while an expired run row exists. On PostgreSQL
the no-op statements commit nothing either.

## A Target's run (`reconcileTarget`, `reconcileUnderLease`)

| # | TypeScript | Statement | Guard | Before / after |
|---|---|---|---|---|
| C1 lease | :255-273 | `generation + 1`, the lease, `needs_sync = false`, `last_attempt_at`; the `sync_runs` row with its deadline (one statement) | `revoked_at IS NULL`, `state = 'active'`, no live lease, Organization not frozen | first; then the Connection read |
| C2 failure | `recordFailure` :322 | Connection revoked or gone: `failure_count + 1`, backoff, `needs_sync`; disabled at 10, with `sync.target_disabled` | generation, `FOR UPDATE` | after the Connection read; then C25, C26 |
| C3 failure | `recordFailure` :326 | adapter not allowed on the installation (no backoff budget spent toward disabling) | generation, `FOR UPDATE` | the same |
| C4 cycle-open | :342 | `repair_cycle_started_at = COALESCE(…, now())` | generation (no lock: one statement) | forced runs only; then the reads of `reconcileUnderLease` |
| C5 values-decrypted | :531-544, :1016 | the `sync.values_decrypted` event naming every version about to be decrypted | **none** (it records a decryption, not a delivery) | after the project, environment and resolved items; then D, the decryption |
| — | :547 | the ledger read | | then **P1** `inspectUsage` (Coolify services; ungated), then **P2** `readRemote` / `readValues` (forced runs on read-back platforms; ungated) |
| C6 adopt (× each) | :713-717 | ledger `written` for a name read back as current but not owned; in Go, with the redeploy debt of an earlier run's unconfirmed write (defect 9) | generation, `FOR SHARE` | after P2; a fence ends the run (lease lost) |
| C7 credit | :718, :1287 | `repaired_at = now()` for names read back as current | generation, `FOR SHARE` | after C6 |
| — | :720-731 | nothing to write or delete: the owed redeploy only (C16's path) | | |
| C9 drift | :757, :1212 | the Target's `last_drift_*` and the `sync.drift_detected` event | generation, `FOR NO KEY UPDATE` | forced runs with drift; after C7 |
| C10 push-attempted | :772 | the `sync.push_attempted` event | generation, `FOR SHARE` | before any value leaves; a fence ends the run |
| C11 intent-write (× each) | :791-795 | ledger `intent-write` per name, one commit each | generation, `FOR SHARE` | after C10; a fence ends the run before **P4** |
| — | :797 | **P4** `writeValues`: one call, one request per name, each after the send check | | the send check (`SEND_CHECK_SQL`) reads generation, deadline and freeze before each request |
| C12 write-outcome (× each) | :798-818 | ledger `written` or `failed-write`, one commit each; a confirmed change on a Target that redeploys also `redeploy_owed + 1` | generation, `FOR NO KEY UPDATE` with the debt, `FOR SHARE` otherwise; a fenced one is a no-op | after P4; fewer outcomes than names (the send check stopped the batch) ends the run |
| C13 intent-delete (× each) | :827-831 | ledger `intent-delete` | generation, `FOR SHARE` | a fence ends the run before **P5** |
| — | :832 | **P5** `deleteNames`, each request after the send check | | |
| C14 delete-outcome (× each) | :833-845 | ledger `tombstone` or `failed-delete`, with the debt as C12 | as C12 | after P5; a cut-short batch ends the run |
| C15 push-result | :862 | the `sync.push_result` event | generation, `FOR SHARE` | after C14; a fence ends the run, and no redeploy follows |
| — | :1263 | the redeploy debt read | generation | then **P6** `triggerRedeploy` (gated by the send check) |
| C16 redeploy-paid | :1279 | `redeploy_paid = GREATEST(…, owed read)` | generation (one statement) | after P6 accepted; an aborted P6 ends the run |
| C17 expiry | :360, `recordCredentialExpiry` | `credential_expires_at`, `credential_expiry_seen_at` on the Connection | the Connection's version as read, not revoked (no generation) | after the run's provider calls, even when it threw |
| — | :378 | lease lost: the generation, the run's deadline and the freeze read | | |
| C18 yield | :400 | `needs_sync = true` (out of budget, or frozen) | generation (one statement) | then C25, C26 |
| C19 interrupted | :405 | `recordFailure("interrupted mid-run; retrying")` | generation, `FOR UPDATE`; the Connection's version `FOR SHARE` | when the generation did not move |
| C20 refusal | `recordRefusal` :1319 | `outbound_refused: …`, `needs_sync`, longest backoff, notes | generation, not revoked (one statement) | then C21 |
| C21 refusal-audit | :1325 | the outbound policy's refusal event, within its rate bound | none | after C20 |
| C22 cycle-close | :424 | `last_repair_at`, `repair_cycle_started_at = NULL` | generation (one statement) | forced runs whose eligible work is done |
| C23 result | :431 | `failure_count = 0`, `next_attempt_at = NULL`, `last_result`, notes | generation (one statement) | a run that succeeded |
| C24 failure | `recordFailure` :441, :451 | as C2, with the run's result and notes; not counted when the Connection's credential was replaced since the run read it | the Connection's version `FOR SHARE`, then generation `FOR UPDATE` | a run that failed or threw |
| C25 lease-release | :461 | `lease_expires_at = NULL` | generation (one statement) | always, last but one |
| C26 run-row | :469 | `DELETE FROM sync_runs` for this run | none | always, last |

(C8 is unused: the redeploy path without writes is C16's.)

## The order on the paths

- **Nothing to do** (converged): C1, [C4], C5, [C6…, C7], [P6, C16],
  [C22], C23, C25, C26.
- **A push**: C1, [C4], C5, P1?, P2?, [C6…, C7], [C9], C10, C11 × n, P4,
  C12 × n, C13 × m, P5, C14 × m, C15, [P6, C16], [C17], [C22], C23 or C24,
  C25, C26.
- **Fenced** (the generation moved: pause, revoke, re-point, a new
  destination): the run stops at its first guarded commit or send check
  after the fence. It records nothing more under its generation, and C18,
  C19 are skipped (the successor owns the work). C25 is a no-op; C26 still
  runs.
- **Out of budget or frozen mid-run**: the send check refuses, then C18,
  C25, C26.

## Not changed in Go (decision 7)

- One `writeValues` and one `deleteNames` per run, with the items
  TypeScript sends.
- The generation guard on every commit above that has one.
- The send check before every gated request inside a batch, so a fence
  mid-batch stops further requests.
- The order of audit events within a run: C5, C9, C10, C15, then a
  disable's or a refusal's.

## TypeScript defect 8, fixed in Go

`scanSyncTriggers` (:146-151) selects `event_order::text AS event_order`
and orders by `event_order`, which PostgreSQL resolves to the text column.
So a scan's batch is the 500 events after the cursor that come first as
text ("10" before "9"), and the cursor moves to the last of those as text,
not to the highest it read. With more than 500 events waiting, a scan can
move the cursor past events it never read; the Targets those events would
have marked wait for their repair pass (at most 6 hours). A scan whose
batch spans a change in the number of digits ("99", "100") leaves the
cursor below events it read, and the next scan reads them again.

Go orders the scan by number (`TriggerEvents`), so no event is skipped
or read twice (`TestTriggerScanSkipsNoEvent`). This is a deliberate
divergence: the TypeScript line takes security fixes only, and keeps the
text order until it is retired (feature-parity.md, defect 8). The converge
fixture is built so that none of its scans meets a batch where the two
orders disagree: its build moves the cursor past the setup's events, and
the fixture test checks that every tick leaves the cursor at the highest
event it read.

## TypeScript defect 9, fixed in Go

A forced run that reads back a name it has an earlier run's `intent-write`
for, and finds the value it wants, adopts the name (C6) with no redeploy
debt (:713-717). If that earlier run's write reached the platform and the
run died before its outcome (C12), the write's redeploy was never owed, so
it is never paid: the application keeps running its old value until
something else redeploys it. Go's C6 records the debt for such a name
(an ambiguous one) on a Target that redeploys, in the same commit, and the
run then pays it (P6, C16). TypeScript keeps the defect (security fixes
only); feature-parity.md, defect 9. `TestInterruptedWriteKeepsItsRedeploy`
and the G7 crash test's provider points hold it.

## Go's differences

- **GitHub App Connections.** Minting an installation token for a push is
  step 4.10's (`githubmint.ts`). Until then a Target on an App Connection
  is not selected, so it keeps `needs_sync` and nothing is recorded, rather
  than failing toward its failure budget.
- **The ledger's order.** TypeScript reads a Target's ledger without an
  order, so the order of its deletions and of the notes for kept names is
  the table's row order, unspecified. On PostgreSQL that is, for a small
  table, the order of each row's last write. Go reads the ledger in that
  order explicitly (`updated_at`, then the name).
- **The per-run report.** Every run reports its commits, its time queued
  for the writer, its time in jobs and its duration. WAL bytes per run come
  with the G9a smoke on this engine.
