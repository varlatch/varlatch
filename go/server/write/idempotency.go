// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Idempotency-Key support (ADR-0018 §8, the TypeScript withIdempotency in
// http/app.ts). The claim, the domain write and the stored response are
// one write job: a write that fails leaves no claim, as the TypeScript
// transaction rolls both back; a replay answers from the stored response
// before the write runs, whatever the Organization's state now, once the
// requester's passkey-verification checkpoint passes (a cached response is
// still access to the Organization).

// Response is a write's answer as a claim stores it.
type Response struct {
	Status int
	// Payload is the body, a JSON value (jsvalue).
	Payload any
}

// Claim names one Idempotency-Key claim.
type Claim struct {
	IdentityID string
	// Endpoint is the TypeScript server's endpoint string for the write
	// ("PUT values <environment>/<item>"), part of the key.
	Endpoint string
	// Key is the Idempotency-Key header; "" when the request has none.
	Key string
	// Digest is BodyHash of the parsed body.
	Digest string
}

// MaxKey is the longest Idempotency-Key accepted, in UTF-16 code units.
const MaxKey = 200

// CheckKey refuses a key longer than MaxKey, before anything else runs.
func CheckKey(key string) error {
	if len(utf16.Encode([]rune(key))) > MaxKey {
		return domainerr.New("VALIDATION_FAILED", "Idempotency-Key exceeds 200 characters")
	}
	return nil
}

// BodyHash is bodyHash (http/support.ts): HMAC-SHA256 under the Root KEK
// of a fixed label and the body as JSON.stringify writes it, so the stored
// digest says nothing about the body to someone without the key. body is
// the parsed body as the TypeScript route hands it on (zod's output), as a
// jsvalue; nil is JSON null.
func BodyHash(body any, rootKEK []byte) string {
	m := hmac.New(sha256.New, rootKEK)
	m.Write([]byte("varlatch:idempotency:v1\x00"))
	m.Write(jsvalue.Stringify(body))
	return "hmac-v1:" + hex.EncodeToString(m.Sum(nil))
}

// Idempotent runs write as one job under c. With no key, it is just the
// job. With a key: a stored claim with the same digest answers its stored
// response (replayed true), after replay passes (the requester's
// checkpoint: requireOrganizationAccess); one with another digest is
// IDEMPOTENCY_CONFLICT; otherwise write runs and its response is stored
// with the claim, in the same job. The caller takes its gates before (the
// claim is step 2.5 of the TypeScript order: after the Organization and
// the people).
func Idempotent(ctx context.Context, store *storage.DB, c Claim, replay func(tx *storage.Tx) error, write func(tx *storage.Tx) (Response, error)) (resp Response, replayed bool, err error) {
	if c.Key == "" {
		err = store.Write(ctx, func(tx *storage.Tx) error {
			var err error
			resp, err = write(tx)
			return err
		})
		return resp, false, err
	}
	if err := CheckKey(c.Key); err != nil {
		return Response{}, false, err
	}
	// The claim's INSERT is the TypeScript server's first statement with
	// the endpoint and the key, before the write: U+0000 in either (a path
	// id in the endpoint) fails it, so the request answers 500 before
	// anything the write would refuse.
	if strings.IndexByte(c.Endpoint, 0) >= 0 || strings.IndexByte(c.Key, 0) >= 0 {
		return Response{}, false, ErrPostgresText
	}
	err = store.Write(ctx, func(tx *storage.Tx) error {
		resp, replayed = Response{}, false
		q := query.New(tx)
		row, err := q.IdempotencyClaim(ctx, query.IdempotencyClaimParams{IdentityID: c.IdentityID, Endpoint: c.Endpoint, IdempotencyKey: c.Key})
		if err == nil {
			if row.BodyHash != c.Digest {
				return domainerr.New("IDEMPOTENCY_CONFLICT", "Idempotency key reused with a different request body")
			}
			if replay != nil {
				if err := replay(tx); err != nil {
					return err
				}
			}
			resp, err = storedResponse(row.Response)
			replayed = err == nil
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if resp, err = write(tx); err != nil {
			return err
		}
		// The response goes into a jsonb column: what jsonb refuses fails
		// the request, the write with it, as there.
		if err := jsvalue.JsonbRefuses(resp.Payload); err != nil {
			return err
		}
		return q.InsertIdempotencyClaim(ctx, query.InsertIdempotencyClaimParams{
			IdentityID: c.IdentityID, Endpoint: c.Endpoint, IdempotencyKey: c.Key, BodyHash: c.Digest,
			Response: string(jsvalue.Stringify(jsvalue.Jsonb(jsvalue.Object{{Key: "status", Value: resp.Status}, {Key: "payload", Value: resp.Payload}}))),
		})
	})
	return resp, replayed, err
}

// storedResponse reads a stored {status, payload} as the TypeScript server
// reads it back from jsonb: the payload's members in jsonb's order, as
// JSON.parse enumerates them. So a replay's body can differ in member
// order from the first answer's, there as here. The order is applied on
// reading, whatever order the stored text has: a claim copied from
// PostgreSQL (step 7) or written by an earlier Go build answers the same.
func storedResponse(text string) (Response, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return Response{}, err
	}
	o, ok := v.(jsvalue.Object)
	if !ok {
		return Response{}, errors.New("write: a stored idempotent response is not an object")
	}
	status, _ := o.Get("status")
	n, ok := status.(float64)
	if !ok {
		return Response{}, errors.New("write: a stored idempotent response has no status")
	}
	payload, _ := o.Get("payload")
	return Response{Status: int(n), Payload: jsvalue.JSOrder(jsvalue.Jsonb(payload))}, nil
}
