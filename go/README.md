# Go rewrite

The Go rewrite of `varlatchd` and the `varlatch` CLI (ADR-0059). The
groundwork ADR-0059 amendment 2 allowed was built on the `rewrite/go`
branch and merged into `main` after the TypeScript release v0.22.0, as the
start of step 1 (ADR-0059 "Order"). Nothing here ships until the first Go
release. CI routes by path: `.github/workflows/go.yml` checks `go/`, and
`scripts/ci-changes.sh` keeps a Go-only change out of the TypeScript tests.

- `cmd/varlatchd/`, `server/`: the server, AGPL-3.0-or-later.
- `lib/storage/`: the SQLite storage engine (Decision 2): the single
  writer with group commit, the checkpointer that bounds the WAL, paced
  snapshots, metrics.
- `lib/diskprobe/`: the fsync probe (Decision 2's disk requirement, p99
  under 10 ms) that setup, `varlatch doctor` and the G9a harness run.
- `lib/envelope/`: the encryption envelope (ADR-0011, unchanged by
  Decision 2): AES-256-GCM, canonical-JSON associated data, the purposes
  in use (`context.go`, including ADR-0056's audit export credential and
  its drain copy since 0.22.0), Root KEK parsing and the canary.
  `testdata/` holds fixtures the TypeScript server's own code sealed
  (opened by the Go tests) and fixtures Go sealed (opened by that code in
  CI, `tsfixtures.mjs`). `ts-v0.22.0.json` comes from v0.22.0 and supplies
  the vectors; `ts-v0.21.0.json` stays, since what 0.21.0 sealed must still
  open. A TypeScript release that adds a purpose gets a fixture of its own
  (`node tsfixtures.mjs generate --ref v<release> ts-v<release>.json`,
  listed in `tsFixtures` in `envelope_test.go`).
- `lib/release/`: the embedded release verifier (Decision 8): a release's
  SHA256SUMS must be signed by the release workflow for its tag (Sigstore,
  pinned identity and issuer; cosign's earlier bundle format and the newer
  Sigstore bundle both read), and every asset must match it.
- `install/install.sh`: the installer of Decision 8 (CLI for the current
  user, or `--server` as root), and its tests: every prefix under sh, dash
  and bash runs nothing or the whole script (G8), and end-to-end runs
  against a local HTTPS server. The downloaded CLI checks the signature
  (`varlatch verify-release`) before anything is put in place.
- `install/install.ps1`: the Windows installer (CLI for the current user,
  in `%LOCALAPPDATA%\Programs\Varlatch`, added to the user `PATH`), with
  the same checks as `install.sh` and its G8 tests under PowerShell 5.1 and
  7 (the prefix runner is `install/testdata/ps1prefix.ps1`; the Windows CI
  job runs the end-to-end install).
- `install/varlatchd.service`: the systemd unit (data in
  `/var/lib/varlatch`, configuration in `/etc/varlatch/varlatchd.conf`, the
  Root KEK and BEK as systemd credentials, user `varlatch`, a strict
  sandbox). CI checks it with `systemd-analyze verify` and `security`, and
  runs `install/unitprobe` under it (`install/test-unit.sh`).
- `bench/g9a/`: the G9a storage benchmark harness (`run.sh`, the k6
  script, the `g9a` command): G9a's load profile, every checkpoint and the
  WAL size logged, paced backups, converge runs, the disk record, and a
  report that judges a run by G9a's criteria. Until step 3 builds
  varlatchd it serves the load from a stand-in workload on `lib/storage`,
  whose runs are inconclusive by design; see `bench/g9a/README.md`.
- `cmd/varlatch/`, `lib/` and everything else: Apache-2.0. No Apache-2.0
  package may depend on an AGPL-3.0-or-later one; `licensing_test.go`
  enforces it.

Checks (Go 1.27, `CGO_ENABLED=0`), as `.github/workflows/go.yml` runs them:

```sh
cd go
gofmt -l .
go mod tidy -diff
go vet ./...
go test ./...
CGO_ENABLED=1 go test -race ./...
```

## Before the first Go release

- When varlatchd itself is written: configuration errors that a retry
  cannot fix (an unparsable file, a missing key, conflicting options;
  nothing touching DNS, network, disk or the database) exit 78, and the
  unit gets `RestartPreventExitStatus=78`, pinned in `unit_test.go`;
  varlatchd sets `PR_SET_DUMPABLE` to 0.
- The Go release workflow: binaries named `varlatch-<version>-<os>-<arch>`
  (`.exe` on Windows) and `varlatchd-<version>-linux-<arch>`, plus
  `varlatchd.service`, all in `SHA256SUMS`; `install.sh` attached with
  `@VARLATCH_VERSION@` replaced by the version; varlatch.com serving the
  latest one with a `Content-Length`.
- Step 3 points the G9a harness at varlatchd (`bench/g9a/README.md`,
  "Against varlatchd") before G9a is run as the gate.
- List the Go module's dependencies (`go list -m all`, modernc.org/sqlite
  and its own) in THIRD-PARTY-NOTICES.md and its generator.
