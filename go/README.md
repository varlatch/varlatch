# Go rewrite (groundwork)

The Go rewrite of `varlatchd` and the `varlatch` CLI (ADR-0059). This
directory lives on the `rewrite/go` branch until the next TypeScript
release is tagged; until then it holds only the groundwork ADR-0059
amendment 2 allows, and nothing here ships.

- `cmd/varlatchd/`, `server/`: the server, AGPL-3.0-or-later.
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
```

## Before `rewrite/go` merges into `main`

- `scripts/ci-changes.sh classify` counts a Go-only change as code with
  every TypeScript test (`code=true`, `tests=all`). Classify Go-only
  changes separately, keeping the checks for shared files, licenses and
  notices, and run the Go checks on `main` (go.yml's triggers).
- Drop the `rewrite/go` guard from ci.yml's `hosted-runner` job.
