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
50/s for 15 minutes with a backup in its middle (36 minutes of load). A
smoke run scales it (`g9a plan -scale 0.05 -wal-bound 524288
-backup-step-pages 256`; CI runs that, see `.github/workflows/go.yml`).
Any plan but the profile is a diagnostic run: the report judges it by the
same criteria but never calls it a pass.

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
  second; the cgroup's `anon` memory and the RSS every 5 seconds; backups
  and converge runs; every fsync probe sample, idle and under load.
- `system.json`: the target, the disk (mount, filesystem, options, block
  device, device mapper and the devices under it, model, rotational), the
  cgroup's limits, the idle fsync summary.

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
  at most 100 ms and no failure;
- in the server's own cgroup, `anon` at most 300 MiB after the first
  minute and no `memory.events` high, max or OOM (`memory.current` and the
  RSS are reported);
- no backup, converge run or checkpoint failed.

It is **inconclusive** when it did not show what G9a requires: the size
trigger firing under load; every planned converge run, over all targets;
a backup overlapping the bound (a deferred trigger) followed by its
`TRUNCATE`; every planned backup; memory measured under `memory.max`
1 GiB and `memory.swap.max` 0; the fsync distribution idle and under load;
the filesystem. It is also inconclusive when the target was the stand-in
or the plan was not the profile. If the shipped bound is never reached,
either a separate run at that bound raises the write rate until the
trigger fires, or the bound is lowered to one that was shown and
Decision 2 is updated to it (ADR-0059, G9a).

## Against varlatchd (step 3)

The harness stays; the target changes. varlatchd needs, in a benchmark
mode that is off in production:

- the retrieval route k6 calls (`k6/g9a.js`, one line to change) and a
  manifest of tokens and secrets after seeding W1;
- `GET /run/plan` and `GET /run/manifest` (for a k6 on another host),
  `POST /run/start` and `POST /run/stop`, the converge and backup schedule
  of the plan, and the event log, written as `serve.go` writes it (the
  checkpoint events come from `storage.Options.OnCheckpoint`);
- `system.json` with `"target": "varlatchd"`.
