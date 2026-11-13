# G9a storage benchmark harness

The harness for ADR-0059's gate G9a (Acceptance): open-loop secret
retrievals with their audit writes, a converge run a minute for 20 Sync
Targets, paced backup snapshots, and the writer and checkpoint policy of
Decision 2, on a 1 vCPU, 1 GB VPS. G9a is passed in Order step 3, against
varlatchd. Until then the load is served by a stand-in workload on
`lib/storage` (amendment 2's groundwork), and every report says the run is
inconclusive for that reason: "a harness run against the groundwork's
storage engine alone does not pass it".

## Run

```sh
bench/g9a/run.sh OUT [plan.json]
```

`run.sh` builds `g9a` (or takes `G9A_BIN`), starts `g9a serve`, waits
while it seeds workload W1 (5,000 secret versions, 50 identities, 20 Sync
Targets) and probes the idle disk, runs k6 (on `PATH`, or the pinned
`grafana/k6` image), stops the server and writes `OUT/report.md` and
`OUT/verdict.json`. Exit status: 0 pass, 1 fail, 2 inconclusive, 3 the
harness failed.

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
another runs logs `backup_wait`, waits for it and then starts, and its
window notes the delay. An attempt keeps the slot until its deferrals are
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

- `requests.log`: every retrieval, from k6 (`k6/g9a.js`): phase, scheduled
  start, latency counted from the scheduled start, service time, status,
  error (`busy` for `SQLITE_BUSY`). k6's dropped iterations (requests it
  could not send on time) are in `k6-summary.json`.
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
  for a running one (its `backup_start` then carries `waitUs`); every
  fsync probe sample, idle and under load.
- `system.json`: the target, the disk (mount, filesystem, options, block
  device, device mapper and the devices under it, model, rotational), the
  cgroup's limits (`memory.max`, `memory.swap.max`, and `cpu.max` read
  once), the idle fsync summary.

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
- no backup, converge run or checkpoint failed.

It is **inconclusive** when it did not show what G9a requires: the size
trigger firing under load; every planned converge run, over all targets;
a backup overlapping the bound (a deferred trigger) followed by its
`TRUNCATE`; every timed backup; for each WAL-triggered backup, an attempt
that held a size-triggered `TRUNCATE` off, whatever the timed backups did
(the reason names its fraction and how many attempts ran); memory
measured under `memory.max` 1 GiB and `memory.swap.max` 0; the fsync
distribution idle and under load; the filesystem.

A deferred size trigger, or a backup's own `TRUNCATE`, belongs to the
backup that was running when it started, by that backup's interval from
`backup_start` to `backup_end` (which holds the snapshot's own). Backups
never overlap, so each belongs to one backup at most; a deferral outside
every interval is noted. The one-second padding of the windows is for
their latency and CPU only. It is also inconclusive when the target was the stand-in
or the plan was not the profile. If the shipped bound is never reached,
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

## Against varlatchd (step 3)

The harness stays; the target changes. varlatchd needs, in a benchmark
mode that is off in production:

- the retrieval route k6 calls (`k6/g9a.js`, one line to change) and a
  manifest of tokens and secrets after seeding W1;
- `GET /run/plan` and `GET /run/manifest` (for a k6 on another host),
  `POST /run/start` and `POST /run/stop`, the converge and backup schedule
  of the plan (WAL-triggered backups as `walbackup.go` starts them), and
  the event log, written as `serve.go` writes it (the checkpoint events
  come from `storage.Options.OnCheckpoint`);
- `system.json` with `"target": "varlatchd"`.
