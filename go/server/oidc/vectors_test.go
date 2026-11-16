// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The TypeScript verifier's answers (services/varlatchd/test/
// go-oidc-vectors.test.ts).
type vectors struct {
	Verify []struct {
		Name      string `json:"name"`
		Issuer    string `json:"issuer"`
		Now       int64  `json:"now"`
		Token     string `json:"token"`
		Documents map[string]struct {
			Status int    `json:"status"`
			Body   string `json:"body"`
			Error  bool   `json:"error"`
		} `json:"documents"`
		Expect struct {
			Claims  any      `json:"claims"`
			Reason  string   `json:"reason"`
			Fetched []string `json:"fetched"`
		} `json:"expect"`
	} `json:"verify"`
	Bounds struct {
		Issuer string `json:"issuer"`
		JWKS   struct {
			OK      []any `json:"ok"`
			Rotated []any `json:"rotated"`
		} `json:"jwks"`
		Scenarios []struct {
			Name  string `json:"name"`
			Steps []struct {
				Advance int64  `json:"advance"`
				Mode    string `json:"mode"`
				Token   string `json:"token"`
				Expect  struct {
					Outcome   string `json:"outcome"`
					Discovery int    `json:"discovery"`
					JWKS      int    `json:"jwks"`
				} `json:"expect"`
			} `json:"steps"`
		} `json:"scenarios"`
	} `json:"bounds"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Verify) < 50 || len(v.Bounds.Scenarios) < 5 {
		t.Fatalf("%d cases, %d scenarios: the vectors are incomplete", len(v.Verify), len(v.Bounds.Scenarios))
	}
	return v
}

// plain is a value as encoding/json reads it, to compare with the file.
func plain(t *testing.T, v any) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(jsvalue.Stringify(v), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func reasonOf(err error) string {
	if r, ok := IsVerification(err); ok {
		return r
	}
	return "verification-error"
}

// The verifier: every case's claims or reason, and the URLs it fetched,
// are the TypeScript verifier's.
func TestTypeScriptVerifyVectors(t *testing.T) {
	for _, c := range readVectors(t).Verify {
		var fetched []string
		v := &Verifier{
			Now: func() time.Time { return time.UnixMilli(c.Now) },
			Fetch: func(_ context.Context, url string) (*Response, error) {
				fetched = append(fetched, url)
				d, ok := c.Documents[url]
				switch {
				case !ok:
					return &Response{Status: 404}, nil
				case d.Error:
					return nil, errors.New("fetch failed")
				}
				return &Response{Status: d.Status, Body: []byte(d.Body)}, nil
			},
		}
		claims, err := v.Verify(c.Token, c.Issuer)
		if err != nil {
			if got := reasonOf(err); got != c.Expect.Reason {
				t.Errorf("%s: reason %q, want %q", c.Name, got, c.Expect.Reason)
			}
		} else if c.Expect.Reason != "" {
			t.Errorf("%s: verified, want %q", c.Name, c.Expect.Reason)
		} else if got := plain(t, claims); !reflect.DeepEqual(got, c.Expect.Claims) {
			t.Errorf("%s: claims %v, want %v", c.Name, got, c.Expect.Claims)
		}
		if !reflect.DeepEqual(fetched, c.Expect.Fetched) && (len(fetched) > 0 || len(c.Expect.Fetched) > 0) {
			t.Errorf("%s: fetched %q, want %q", c.Name, fetched, c.Expect.Fetched)
		}
	}
}

// The bounds: each step's outcome and the fetch counts after it, on one
// cache with a moving clock, are the TypeScript verifier's.
func TestTypeScriptBoundsVectors(t *testing.T) {
	vs := readVectors(t)
	b := vs.Bounds
	for _, s := range b.Scenarios {
		now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
		mode := "ok"
		discovery, jwks := 0, 0
		v := &Verifier{
			Now: func() time.Time { return now },
			Fetch: func(_ context.Context, url string) (*Response, error) {
				if url == b.Issuer+"/.well-known/openid-configuration" {
					discovery++
					if mode == "discovery-fails" {
						return &Response{Status: 503}, nil
					}
					return &Response{Status: 200, Body: jsvalue.Stringify(jsvalue.Object{{Key: "issuer", Value: b.Issuer}, {Key: "jwks_uri", Value: b.Issuer + "/jwks"}})}, nil
				}
				jwks++
				if mode == "jwks-fails" {
					return &Response{Status: 500}, nil
				}
				keys := b.JWKS.OK
				if mode == "rotated" {
					keys = b.JWKS.Rotated
				}
				body, _ := json.Marshal(map[string]any{"keys": keys})
				return &Response{Status: 200, Body: body}, nil
			},
		}
		for i, st := range s.Steps {
			now = now.Add(time.Duration(st.Advance) * time.Millisecond)
			if st.Mode != "" {
				mode = st.Mode
			}
			outcome := "ok"
			if _, err := v.Verify(st.Token, b.Issuer); err != nil {
				outcome = reasonOf(err)
			}
			if outcome != st.Expect.Outcome || discovery != st.Expect.Discovery || jwks != st.Expect.JWKS {
				t.Errorf("%s, step %d: %q, %d discovery, %d JWKS; want %q, %d, %d", s.Name, i, outcome, discovery, jwks,
					st.Expect.Outcome, st.Expect.Discovery, st.Expect.JWKS)
			}
		}
	}
}
