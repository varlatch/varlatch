// SPDX-License-Identifier: Apache-2.0

// Package v1 is the /v1 contract's request and response types for the Go
// CLI (ADR-0059 step 5; internal docs/design/go-cli.md, decision 15),
// generated from packages/protocol/openapi.yaml by oapi-codegen (models
// only). go/server/api is generated from the same document for the server;
// the CLI never imports it (go/licensing_test.go), so the two follow one
// contract without sharing Go code.
//
// types.gen.go is generated, never edited: change the OpenAPI document, then
// run `go generate ./...` in go/. go.yml's "Generated code is current" step
// fails when it is stale. The generator is the tool directive in go.mod.
//
// The CLI prints what the server answers as JavaScript would (decision 2),
// so anything it prints stays a lib/jsjson value; these types are for what
// it reads and sends.
//
//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../../../../packages/protocol/openapi.yaml
//go:generate go run ../../../../../internal/spdxheader Apache-2.0 types.gen.go
package v1
