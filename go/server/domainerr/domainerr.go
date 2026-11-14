// SPDX-License-Identifier: AGPL-3.0-or-later

// Package domainerr is the TypeScript server's DomainError
// (domain/errors.ts): an error with a stable protocol code, a message and
// optional details, which the HTTP layer maps to a status and the error
// envelope.
package domainerr

import "github.com/varlatch/varlatch/go/server/jsvalue"

// Error is a DomainError.
type Error struct {
	Code    string
	Message string
	// Details, when not nil, is the envelope's details object.
	Details jsvalue.Object
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// New returns an Error without details.
func New(code, message string) *Error { return &Error{Code: code, Message: message} }

// NotFound is notFound(what): RESOURCE_NOT_FOUND, "<what> not found".
func NotFound(what string) *Error { return New("RESOURCE_NOT_FOUND", what+" not found") }
