# G9a storage benchmark harness

The harness for ADR-0059's gate G9a (Acceptance): open-loop secret
retrievals with their audit writes, a converge run a minute for 20 Sync
Targets, paced backup snapshots, and the writer and checkpoint policy of
Decision 2, on a 1 vCPU, 1 GB VPS, against varlatchd (Order step 3).

The server is varlatchd built with the `g9a` build tag (AGPL,
`go/server/daemon/bench_g9a.go`): `varlatchd g9a -plan p -data d -out o`
serves the run with the production serve path (the same storage engine
and settings, HTTP layer, request window and read path of values) on a
fresh installation, and adds workload drivers and instrumentation only: the
W1 seed in the production tables, the converge simulation, the plan's
paced backups on its own storage instance, and the run's event log and
control routes, which come from this package's `Runner`. This package
(Apache-2.0) drives that binary as a process and imports nothing from
`go/server` (`go/licensing_test.go`).

## Run

```sh
bench/g9a/run.sh OUT [plan.json]
```

`run.sh` builds `g9a` and varlatchd with the `g9a` tag (or takes
`G9A_BIN` and `G9A_VARLATCHD`), starts `varlatchd g9a`, waits while it
seeds workload W1 (5,000 secret versions, 50 identities, 20 Sync Targets)
and probes the idle disk, runs k6 (on `PATH`, or the pinned `grafana/k6`
image), stops the server and writes `OUT/report.md` and
`OUT/verdict.json`. Exit status: 0 pass, 1 fail, 2 inconclusive, 3 the
harness failed.

### What varlatchd serves

- **W1**, in the production tables: one Organization; 4 Projects with an
  active Contract of 125 Secrets; 20 environments, each with every Secret
  in two versions (5,000 versions, sealed under the Organization's KEK);
  50 identities: 30 people (members, with an Organization Grant) and 20
  service identities (each with a Grant on one environment), every one
  with a credential; 4 Platform Connections and 20 Sync Targets, one per
  environment.
- **The load**: `POST …/disclosures` of one Secret, the read path of
  values with its audit event committed before the value is decrypted.
  k6 sends it from 20 loopback source addresses (127.0.0.2 to
  127.0.0.21, `--local-ips`), and each address uses one identity's
  credential (`manifest.json`: alternately a person's and a service
  identity's), with varlatchd's request window (600 requests per address
  and minute) in force. At 50/s that is about 150 a minute per address.
- **The converge simulation**, every period for every Target in turn:
  reconcileTarget's successful path (`domain/syncdelivery.ts`), with k
  changed destinations per run (`changesPerRun`, 5 by default): the
  lease and the `sync_runs` row (one job); the reads, outside any write;
  `sync.values_decrypted`, committed before the values are decrypted
  (one job); the guarded `sync.push_attempted` (one job); k
  `intent-write` ledger entries (k jobs); a simulated provider call of
  200 ms outside any transaction; k `written` entries (k jobs); the
  guarded `sync.push_result` (one job); the result columns (one job); the
  lease released and the run's row deleted (two jobs): 2k + 7 commits per
  Target and run, each a job of the single writer. No deletions, repair
  cycle, redeploy debt or credential-expiry bookkeeping, which add writes
  in production.
- **Its effective storage settings**, read back from its connections at
  start (pragmas, WAL bound, batch size, checkpoint period, snapshot
  pacing), compared with a production build's, and recorded in
  `system.json` with the binary's version, build tags and SHA-256. A
  test (`go test -tags g9a ./server/daemon`) checks they are the
  production build's; a plan may set only the WAL bound, which the report
  shows. `varlatchd serve` logs the same settings at start.

Without a plan the G9a profile runs: one minute of warm-up at 10/s, then
10/s for 15 minutes with a backup at 7 minutes, 30/s for 5 minutes, and
50/s for 15 minutes with a backup started from the WAL's size (36 minutes
of load). A smoke run scales it (`g9a plan -scale 0.05 -wal-bound 524288
-backup-step-pages 256`; CI runs that, see `.github/workflows/go.yml`).
Any plan but the profile is a diagnostic run: the report judges it by the
same criteria but never calls it a pass. The one exception is the
WAL-triggered backup's fraction, below.

### Backups started from the WAL's size

A backup in the plan starts either at an offset into its phase or from the
WAL's size (ADR-0059 amendment 4):

```json
{"phase": "p10", "atSeconds": 420},
{"phase": "p50", "atSeconds": 0, "walTriggered": {"fraction": 0.95, "maxAttempts": 5}}
```

While its phase runs, the server samples the WAL file's size every 100 ms
and starts a paced backup when the size crosses `fraction` of the bound
from below (a sample under it, then one at or over it). A WAL already over
it when the phase starts has not crossed it. After each attempt the
snapshot's `TRUNCATE` resets the WAL, and the next crossing starts the next
attempt, until one attempt has held a size-triggered `TRUNCATE` off (the
checkpointer deferred one while it ran), up to `maxAttempts` in the phase.
One backup runs at a time: the timed and the WAL-triggered ones take the
same slot before they start. A crossing while another backup holds it is
logged (`wal_crossing`) and skipped; a timed backup that comes due while
another runs logs `backup_wait` and waits for it, then starts, and its
window notes the delay. It waits only until its phase ends or the run
stops: then it logs `backup_missed` with the reason and never starts, so
no backup starts outside the phase it names. A WAL-triggered attempt
likewise starts only inside its phase. An attempt keeps the slot until its deferrals are
counted, so it never takes credit for another backup's. 100 ms, not the once a second the WAL is logged: on the VPS
the last 5 % of the 64 MiB bound filled in about 3 s, and a one-second
sample would start the backup up to a third of that margin late.

`g9a plan -wal-fraction f -wal-attempts n` sets both. The validation
refuses a fraction outside (0, 1], fewer than one attempt, an offset on a
WAL-triggered backup, and two of them in one phase. `-scale` leaves them
as they are. A run that differs from the profile only in the fraction
still counts for the gate: when no attempt held a `TRUNCATE` off, ADR-0059
lets another run raise the fraction, recorded in its plan; the report
names it.

On the benchmark host, run the server in a cgroup of its own with G9's
limits, so the memory criterion is measured and judged:

```sh
G9A_DATA=/var/lib/g9a \
G9A_SCOPE='systemd-run --scope --quiet -p MemoryMax=1G -p MemorySwapMax=0' \
  bench/g9a/run.sh /root/g9a-$(date -u +%Y%m%dT%H%M%S)
```

`G9A_DATA` is the directory whose disk is measured; the verdict holds for
that class of disk only. Runs on shared infrastructure need the owner's
approval first, with the load agreed (the profile above), as for every
load test.

## What it records

- `varlatchd.conf` and `access.log`: the configuration the run served
  with, and varlatchd's access log, from which the report counts each
  client address's requests in each request window.
- `requests.log`: every retrieval, from k6 (`k6/g9a.js`): phase, scheduled
  start, latency counted from the scheduled start, service time, status,
  error (`busy` for `SQLITE_BUSY`), varlatchd's request id and the
  identity whose credential it carried. k6's dropped iterations (requests
  it could not send on time) are in `k6-summary.json`.
- `events.jsonl`: from the server: every checkpoint with its mode, why it
  ran (`interval`, `size`, `snapshot`, `close`), start, duration, busy
  result, frames in the log and checkpointed, and the WAL size before and
  after, plus every size trigger a backup deferred; the WAL size every
  second; the cgroup's `anon` memory and the RSS every 5 seconds; the
  cgroup's `cpu.stat` (usage, periods, throttled periods, throttled time)
  with every memory and WAL sample; backups (`backup_start` and
  `backup_end`, numbered, with the WAL size at the start, and the phase and
  attempt of a WAL-triggered one) and converge runs; for every
  WAL-triggered attempt, `wal_backup` (its start, the WAL size that
  started it, whether it held a `TRUNCATE` off) and for every crossing that
  started none, `wal_crossing`; `backup_wait` when a timed backup waits
  for a running one (its `backup_start` then carries `waitUs`) and
  `backup_missed` when one never started (its phase ended or the run
  stopped first); every fsync probe sample, idle and under load.
- `system.json`: the target and its build (version, tags, SHA-256), its
  effective storage settings and whether they are the production build's,
  the load's source addresses, the disk (mount, filesystem, options, block
  device, device mapper and the devices under it, model, rotational), the
  cgroup's limits (`memory.max`, `memory.swap.max`, and `cpu.max` read
  once), the idle fsync summary.
- `stages.json` (step 4 decision 7, to diagnose G9a's slower baseline):
  where each disclosure's time goes inside varlatchd, one sample per
  disclosure and stage (a stage met several times in one request, such as
  its authorization decisions, summed), as count, mean, p50, p95, p99 and
  maximum (log buckets, within 2 %): admission (the body limit, the request
  window, routing), authentication, the read snapshot (authorization's
  reads included), authorization, the audit job's wait for the writer, the
  commit of its batch, decryption and encoding (`go/server/stages`).
  varlatchd writes it when the run ends; `GET /run/stages` shows it during
  the run. The report shows it as a table; no criterion reads it.
- `cpu.pprof`, with `G9A_PROFILE=<seconds>` (`varlatchd g9a -profile`): a
  CPU profile of varlatchd from the load's start (`POST /run/start`, which
  k6 sends once it is initialized) for that long or until the run ends,
  for `go tool pprof`, with `cpu-window.json` saying when it ran; the
  report sets that window against the load's requests and says whether
  they overlap (`profile` in `verdict.json`). `GET /run/profile?seconds=N`
  takes one on demand.

## What the report judges

A run **fails** when any of these is broken:

- in every judged phase, every scheduled request present (k6 starts
  rate × duration of them, or one more), none failed or dropped, p95 at
  most 100 ms;
- every request accounted for alike by the log, k6 and the server;
- no `SQLITE_BUSY` seen by a client or the server;
- every size or snapshot `TRUNCATE` completed (not busy, every frame
  checkpointed, the WAL reset), and the WAL peak under twice the bound;
- in every `TRUNCATE` and backup window (plus one second either side), p95
  at most 100 ms and no failure; a WAL-triggered backup's window is judged
  like any other;
- no more WAL-triggered attempts than the plan allows, and none after one
  that held a `TRUNCATE` off;
- in the server's own cgroup, `anon` at most 300 MiB after the first
  minute and no `memory.events` high, max or OOM (`memory.current` and the
  RSS are reported);
- no backup, converge run or checkpoint failed;
- no client address came within 20 % of the request window: in each
  window that admitted its requests (varlatchd records it in `access.log`
  at admission as `windowOpened`, so the order answers complete in does not
  matter), fewer than 480 of the 600 requests;
- the g9a build's storage settings are the production build's (the plan's
  WAL bound aside).

It is **inconclusive** when it did not show what G9a requires: the size
trigger firing under load; every planned converge run, over all targets;
a backup overlapping the bound (a deferred trigger) followed by its
`TRUNCATE`; every timed backup, started inside the phase it names (one
logged as `backup_missed`, or started elsewhere, did not run for the
plan, though its window is still judged); for each WAL-triggered backup,
an attempt, started inside its phase, that held a size-triggered
`TRUNCATE` off, whatever the timed backups did (the reason names its
fraction and how many attempts ran); memory
measured under `memory.max` 1 GiB and `memory.swap.max` 0; the fsync
distribution idle and under load; the filesystem.

A deferred size trigger, or a backup's own `TRUNCATE`, belongs to the
backup that was running when it started, by that backup's interval from
`backup_start` to `backup_end` (which holds the snapshot's own). Backups
never overlap, so each belongs to one backup at most; a deferral outside
every interval is noted. The one-second padding of the windows is for
their latency and CPU only. It is also inconclusive when the target was not varlatchd; when which
credential each address carried is not shown: an answered request without
a request id or an identity in `requests.log`, a request id twice there, an
answered request with no access log record or with more than one, or an
address with no identity or more than one; when the load did not come from
every address; without an access log, or one without `windowOpened`; or
when the plan was not the profile. If the shipped bound is never reached,
either a separate run at that bound raises the write rate until the
trigger fires, or the bound is lowered to one that was shown and
Decision 2 is updated to it (ADR-0059, G9a).

The report also has, without a threshold:

- **WAL-triggered backups**: for each, its fraction and threshold in
  bytes, and every attempt (start, WAL size at the start, duration, size
  triggers deferred), with the attempt that held a `TRUNCATE` off, if any
  (`walTriggeredBackups` in `verdict.json`);
- **CPU**: the cgroup's `cpu.max` and its throttling over the run (periods,
  throttled periods, throttled time), and beside each `TRUNCATE` and backup
  window the throttled periods and time between the `cpu.stat` samples
  that bracket it (one a second, so the span shown is at most a second
  wider on each side). Without the cpu controller the counters are absent
  and the report says so; `cpu.max` reading `max` is no limit.

## Smoke runs

CI (`.github/workflows/go.yml`) runs the harness at 5 % of the profile's
length against this commit's varlatchd: a smoke run, reported as such and
never counted for the gate. The full run is on the gate's VPS, with the
owner's approval.
