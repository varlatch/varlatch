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
