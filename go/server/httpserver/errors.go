// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
)

// NotImplementedYet is the code of the shared stub's answer (ADR-0059 step
// 3, varlatchd-core decision 5): every /v1 operation, and every named
// browser operation, that this build does not have yet answers 501 with it.
// It is not part of the /v1 contract and exists only in builds before the
// first Go release; the conformance harness's stale-`lacks` probe requires
// exactly this answer from each operation a target declares it lacks.
const NotImplementedYet = "NOT_IMPLEMENTED_YET"

// newRequestID returns a request ID as the TypeScript server makes one
// (http/support.ts requestId): "req_" and a random UUID.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("req_%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type apiError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"requestId"`
	Details   map[string]any `json:"details,omitempty"`
}

// writeError answers with the error envelope, as the TypeScript server's
// errorBody does: {"error": {"code", "message", "requestId", "details"?}},
// Content-Type application/json (Hono's c.json).
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: message, RequestID: requestIDOf(r)}})
}

// writeJSON writes body as JSON.stringify would: no HTML escaping, no
// trailing newline.
func writeJSON(w http.ResponseWriter, status int, body any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// writeNotFound is the answer to a route that does not exist under the
// paths varlatchd serves (/v1 included): Hono's default, a plain-text
// "404 Not Found", not the error envelope. This is one of the two known
// differences from the error format that decision 4 keeps (the OpenAPI
// document describes it).
func writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 Not Found"))
}
