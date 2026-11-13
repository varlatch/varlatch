# Go rewrite (groundwork)

The Go rewrite of `varlatchd` and the `varlatch` CLI (ADR-0059). This
directory lives on the `rewrite/go` branch until the next TypeScript
release is tagged; until then it holds only the groundwork ADR-0059
amendment 2 allows, and nothing here ships.

- `cmd/varlatchd/`, `server/`: the server, AGPL-3.0-or-later.
- `lib/storage/`: the SQLite storage engine (Decision 2): the single
  writer with group commit, the checkpointer that bounds the WAL, paced
  snapshots, metrics.
- `lib/diskprobe/`: the fsync probe (Decision 2's disk requirement, p99
  under 10 ms) that setup, `varlatch doctor` and the G9a harness run.
- `lib/envelope/`: the encryption envelope (ADR-0011, unchanged by
  Decision 2): AES-256-GCM, canonical-JSON associated data, the nine
  purposes in use, Root KEK parsing and the canary. `testdata/` holds
  fixtures the TypeScript server's own code sealed (opened by the Go tests)
  and fixtures Go sealed (opened by that code in CI, `tsfixtures.mjs`).
  Regenerate the TypeScript fixtures from the next release before step 3.
- `lib/release/`: the embedded release verifier (Decision 8): a release's
  SHA256SUMS must be signed by the release workflow for its tag (Sigstore,
  pinned identity and issuer; cosign's earlier bundle format and the newer
  Sigstore bundle both read), and every asset must match it.
- `install/install.sh`: the installer of Decision 8 (CLI for the current
  user, or `--server` as root), and its tests: every prefix under sh, dash
  and bash runs nothing or the whole script (G8), and end-to-end runs
  against a local HTTPS server. The downloaded CLI checks the signature
  (`varlatch verify-release`) before anything is put in place.
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

## Before `rewrite/go` merges into `main`

- `scripts/ci-changes.sh classify` counts a Go-only change as code with
  every TypeScript test (`code=true`, `tests=all`). Classify Go-only
  changes separately, keeping the checks for shared files, licenses and
  notices, and run the Go checks on `main` (go.yml's triggers).
- Drop the `rewrite/go` guard from ci.yml's `hosted-runner` job.
- Regenerate `lib/envelope/testdata/ts-*.json` from the next TypeScript
  release (`node tsfixtures.mjs generate --ref v<next> ts-v<next>.json`),
  including any envelope purpose it adds (ADR-0056's audit export).
- The Go release workflow: binaries named `varlatch-<version>-<os>-<arch>`
  (`.exe` on Windows) and `varlatchd-<version>-linux-<arch>`, plus
  `varlatchd.service`, all in `SHA256SUMS`; `install.sh` attached with
  `@VARLATCH_VERSION@` replaced by the version; varlatch.com serving the
  latest one with a `Content-Length`.
- List the Go module's dependencies (`go list -m all`, modernc.org/sqlite
  and its own) in THIRD-PARTY-NOTICES.md and its generator.
