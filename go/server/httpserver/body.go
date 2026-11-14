// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/varlatch/varlatch/go/server/domainerr"
)

// Request bodies as the TypeScript server reads them. Every built
// operation with a body reads it with c.req.json().catch(() => ({})): a
// body that is not JSON at all counts as {}. Then, at the point the
// handler parses it, after its own checks (the credential's kind, device
// sign-in's availability, the approver), zod checks the value: anything but
// an object, a field of the wrong type (null included, for an optional
// field), a missing required field, or one out of range answers 422
// VALIDATION_FAILED with every issue, "<path>: <message>" joined by "; "
// (parseBody). The wrapper (builtOperation) checks the body against the
// operation's schema before the generated decoder sees it; a body that
// fails reaches the decoder as {} and the operation answers the issues
// where TypeScript would (bodyError).

// fieldKind is what a body field must be.
type fieldKind int

const (
	kindString fieldKind = iota
	kindInt
	kindRecord
	kindEnum
)

type bodyField struct {
	name     string
	kind     fieldKind
	required bool
	// min and max bound a string's length (UTF-16 units) or an integer.
	min, max float64
	options  []string
}

// bodySchemas are the built operations' zod schemas (http/app.ts).
var bodySchemas = map[string][]bodyField{
	"POST /v1/me/credentials/cli": {
		{name: "ttlSeconds", kind: kindInt, min: 60, max: 86_400},
		{name: "name", kind: kindString, min: 1, max: 200},
	},
	"POST /v1/auth/device": {
		{name: "ttlSeconds", kind: kindInt, min: 60, max: 86_400},
		{name: "name", kind: kindString, min: 1, max: 200},
	},
	"POST /v1/auth/device/token": {
		{name: "deviceCode", kind: kindString, required: true, min: 1, max: 200},
	},
	"POST /v1/auth/device/lookup": {
		{name: "userCode", kind: kindString, required: true, min: 1, max: 64},
	},
	"POST /v1/auth/device/approve": {
		{name: "userCode", kind: kindString, required: true, min: 1, max: 64},
		{name: "decision", kind: kindEnum, required: true, options: []string{"approve", "deny"}},
		{name: "assertion", kind: kindRecord},
	},
	"POST /v1/me/passkeys/{passkey}/confirmation": {
		{name: "assertion", kind: kindRecord, required: true},
	},
	"POST /v1/me/approvals/{approval}/approve": {
		{name: "assertion", kind: kindRecord, required: true},
	},
}

// jsType is a JSON value's type as zod names it in "received ...".
func jsType(raw json.RawMessage) string {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return "undefined"
	}
	switch t[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	}
	return "number"
}

// validateBody is zod's verdict on a parsed body: its issues, none when it
// fits the schema.
func validateBody(schema []bodyField, raw []byte) []string {
	if t := jsType(raw); t != "object" {
		return []string{"(root): Invalid input: expected object, received " + t}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return []string{"(root): Invalid input: expected object, received object"}
	}
	var issues []string
	for _, f := range schema {
		v, present := obj[f.name]
		if !present {
			if f.required {
				expected := map[fieldKind]string{kindString: "string", kindInt: "number", kindRecord: "record", kindEnum: "enum"}[f.kind]
				if f.kind == kindEnum {
					issues = append(issues, fmt.Sprintf("%s: Invalid option: expected one of %s", f.name, quoteOptions(f.options)))
				} else {
					issues = append(issues, fmt.Sprintf("%s: Invalid input: expected %s, received undefined", f.name, expected))
				}
			}
			continue
		}
		got := jsType(v)
		switch f.kind {
		case kindString:
			var s string
			if got != "string" || json.Unmarshal(v, &s) != nil {
				issues = append(issues, fmt.Sprintf("%s: Invalid input: expected string, received %s", f.name, got))
				continue
			}
			if n := float64(len(utf16(s))); n < f.min {
				issues = append(issues, fmt.Sprintf("%s: Too small: expected string to have >=%s characters", f.name, jsNumber(int64(f.min))))
			} else if n > f.max {
				issues = append(issues, fmt.Sprintf("%s: Too big: expected string to have <=%s characters", f.name, jsNumber(int64(f.max))))
			}
		case kindInt:
			var x float64
			if got != "number" || json.Unmarshal(v, &x) != nil {
				issues = append(issues, fmt.Sprintf("%s: Invalid input: expected number, received %s", f.name, got))
				continue
			}
			if x != math.Trunc(x) || math.Abs(x) > 1<<53-1 {
				issues = append(issues, fmt.Sprintf("%s: Invalid input: expected int, received number", f.name))
			} else if x < f.min {
				issues = append(issues, fmt.Sprintf("%s: Too small: expected number to be >=%s", f.name, jsNumber(int64(f.min))))
			} else if x > f.max {
				issues = append(issues, fmt.Sprintf("%s: Too big: expected number to be <=%s", f.name, jsNumber(int64(f.max))))
			}
		case kindRecord:
			if got != "object" {
				issues = append(issues, fmt.Sprintf("%s: Invalid input: expected record, received %s", f.name, got))
			}
		case kindEnum:
			var s string
			if got != "string" || json.Unmarshal(v, &s) != nil || !containsString(f.options, s) {
				issues = append(issues, fmt.Sprintf("%s: Invalid option: expected one of %s", f.name, quoteOptions(f.options)))
			}
		}
	}
	return issues
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func quoteOptions(options []string) string {
	q := make([]string, len(options))
	for i, o := range options {
		q[i] = `"` + o + `"`
	}
	return strings.Join(q, "|")
}

type bodyErrorKey struct{}

// readBody prepares a built operation's body (bodySchemas): not JSON at
// all is {}; JSON that does not fit the schema is {} too, with its issues
// kept for bodyError.
func readBody(r *http.Request, schema []bodyField) *http.Request {
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			raw = nil
		}
	}
	empty := io.NopCloser(strings.NewReader("{}"))
	if !json.Valid(raw) {
		r.Body = empty
		return r
	}
	if issues := validateBody(schema, raw); len(issues) > 0 {
		r.Body = empty
		return r.WithContext(context.WithValue(r.Context(), bodyErrorKey{}, domainerr.New("VALIDATION_FAILED", strings.Join(issues, "; "))))
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return r
}

// bodyError is the request body's VALIDATION_FAILED, for the operation to
// answer at the point TypeScript parses its body; nil when it fits.
func bodyError(ctx context.Context) error {
	if r := httpRequestOf(ctx); r != nil {
		if err, ok := r.Context().Value(bodyErrorKey{}).(error); ok {
			return err
		}
	}
	return nil
}
