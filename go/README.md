# Go rewrite

The Go rewrite of `varlatchd` and the `varlatch` CLI (ADR-0059). The
groundwork ADR-0059 amendment 2 allowed was built on the `rewrite/go`
branch and merged into `main` after the TypeScript release v0.22.0, as the
start of step 1 (ADR-0059 "Order"). Nothing here ships until the first Go
release. CI routes by path: `.github/workflows/go.yml` checks `go/`, and
`scripts/ci-changes.sh` keeps a Go-only change out of the TypeScript tests.

- `cmd/varlatchd/`, `server/`: the server, AGPL-3.0-or-later.
- `server/api/`: the `/v1` contract in Go (Decision 3, spec-first
  OpenAPI), generated from `packages/protocol/openapi.yaml`: the request
  and response types, `StrictServerInterface` (one method per operation)
  and its `net/http` wiring on a `ServeMux`. See "The OpenAPI document"
  below.
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
- `internal/spdxheader/`: puts the SPDX line on generated files.
- `cmd/varlatch/`, `lib/` and everything else: Apache-2.0. No Apache-2.0
  package may depend on an AGPL-3.0-or-later one; `licensing_test.go`
  enforces it.

Checks (Go 1.27, `CGO_ENABLED=0`), as `.github/workflows/go.yml` runs them:

```sh
cd go
gofmt -l .
go mod tidy -diff
go generate ./...   # then: git diff --exit-code
go vet ./...
go test ./...
CGO_ENABLED=1 go test -race ./...
```

## The OpenAPI document

The `/v1` contract is `packages/protocol/openapi.yaml` (OpenAPI 3.1),
derived from `packages/protocol` (ADR-0059 Order, step 1). It stays there
while the TypeScript server and dashboard use it; the TypeScript types are
generated from it with openapi-typescript (`pnpm --filter
@varlatch/protocol generate`), and ci.yml fails when they are stale.

- **Go**: `go generate ./server/api` runs oapi-codegen, pinned by the
  `tool` directive in `go.mod` (v2.8.1, `go tool oapi-codegen`), with
  `server/api/oapi-codegen.yaml`: models, the standard library server
  (`net/http` `ServeMux` patterns) and the strict server, whose methods
  take a typed request and return a typed response. v2.8.1 reads OpenAPI
  3.1 itself (`type: [T, "null"]` included), so the document is used as it
  is. Its option `resolve-type-name-collisions` names the parameters and
  headers that share a name with a schema (`ApprovalParameter`,
  `ApprovalHeader`, `EnvironmentParameter`, `ProjectParameter`).
  `internal/spdxheader` then adds the package's SPDX line, which the
  generator cannot write. Never edit `api.gen.go`; change the document and
  generate again.
- **Licensing**: the types and the server interface are one AGPL package.
  A models-only Apache package that the server imports does not work:
  the strict server's response types for `oneOf` bodies use the models'
  unexported fields, which only the same package can reach. The CLI (step
  5) will not import `server/api` (G12); it gets its own client and types,
  generated from the same document into an Apache package (for example
  `lib/apiclient`), so both sides follow one contract without sharing Go
  code.
- **CI** (`go.yml`, which runs when the document changes):
  - "Generated code is current" regenerates and fails on any difference
    (G12, stale output).
  - The `openapi` job compares the document of a pull request with its
    base using oasdiff (pinned image) and fails on a breaking change (G12).
    Before product 1.0 a breaking change may be made on purpose (ADR-0018):
    label the pull request `api-breaking`, add a CHANGELOG.md entry to it
    and re-run the job, which then reports the changes as warnings. Without
    a CHANGELOG.md change the label does not help.

Left for step 1: "checked against the TypeScript server". The spec
coverage test (`services/varlatchd/test/spec-coverage.test.ts`) already
fails when a served route and the document disagree; the TypeScript
server's responses are validated against the document in a pull request of
its own. Step 2 (the conformance harness) starts after that.

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
