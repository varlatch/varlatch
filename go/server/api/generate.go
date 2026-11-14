// SPDX-License-Identifier: AGPL-3.0-or-later

package api

// api.gen.go is varlatchd's /v1 contract in Go (ADR-0059 Decision 3,
// spec-first OpenAPI): the request and response types, the
// StrictServerInterface varlatchd implements (one method per operation of
// packages/protocol/openapi.yaml), and its net/http wiring on a ServeMux.
// It is generated, never edited: change the OpenAPI document, then run
// `go generate ./server/api` in go/. CI fails when api.gen.go differs from
// what the document generates (gate G12). The generator is the tool
// directive in go.mod, so its version is go.mod's.
//
//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../packages/protocol/openapi.yaml
//go:generate go run ../../internal/spdxheader AGPL-3.0-or-later api.gen.go
