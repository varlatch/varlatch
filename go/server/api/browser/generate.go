// SPDX-License-Identifier: AGPL-3.0-or-later

// Package browser is the browser session's endpoints in Go (ADR-0059
// Decision 6; varlatchd-core decision 1): the paths of
// packages/protocol/openapi.yaml tagged browser-session, which have their
// own servers entry (the server's root, not /v1). browser.gen.go holds
// their request and response types, the StrictServerInterface varlatchd
// implements and its net/http wiring, registered with an empty base URL.
// It is generated, never edited: change the OpenAPI document, then run
// `go generate ./server/api/...` in go/. CI fails on stale output (G12).
package browser

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../../packages/protocol/openapi.yaml
//go:generate go run ../../../internal/spdxheader AGPL-3.0-or-later browser.gen.go
