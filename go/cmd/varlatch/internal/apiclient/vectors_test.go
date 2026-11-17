// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/transcript"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The API client vectors (../../testdata/vectors/apiclient.json), written by
// apps/cli/test/go-vectors-apiclient.test.ts from the SDK itself: what the
// client makes of each answer, and the maintenance retry's waits. Answers
// go through the real transport, from a local server.

const vectorsPath = "../../testdata/vectors/apiclient.json"

// VectorAnswer is one answer as the vectors give it.
type VectorAnswer struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
	Body    *string     `json:"body"`
	BodyHex *string     `json:"bodyHex"`
}

// Serve writes the answer.
func (a VectorAnswer) Serve(w http.ResponseWriter) {
	h := w.Header()
	for _, kv := range a.Headers {
		h.Add(kv[0], kv[1])
	}
	if len(a.Headers) == 0 || h.Get("Content-Type") == "" {
		// Response's own default for a string body.
		if a.Body != nil && a.Status != 204 {
			h["Content-Type"] = []string{"text/plain;charset=UTF-8"}
		} else {
			h["Content-Type"] = nil
		}
	}
	w.WriteHeader(a.Status)
	switch {
	case a.BodyHex != nil:
		b, _ := hex.DecodeString(*a.BodyHex)
		_, _ = w.Write(b)
	case a.Body != nil:
		_, _ = w.Write([]byte(*a.Body))
	}
}

// VectorFile is apiclient.json.
type VectorFile struct {
	Token   string `json:"token"`
	Held    string `json:"held"`
	Now     int64  `json:"now"`
	Answers []struct {
		Answer VectorAnswer    `json:"answer"`
		Result json.RawMessage `json:"result"`
		CLI    *struct {
			Stderr *string `json:"stderr"`
			Exit   int     `json:"exit"`
			Throws *string `json:"throws"`
		} `json:"cli"`
	} `json:"answers"`
	Maintenance []struct {
		Title   string         `json:"title"`
		Random  float64        `json:"random"`
		Calls   int            `json:"calls"`
		Answers []VectorAnswer `json:"answers"`
		Waits   []struct {
			RetryInMs   float64 `json:"retryInMs"`
			RemainingMs float64 `json:"remainingMs"`
		} `json:"waits"`
		Notice   string            `json:"notice"`
		Requests int               `json:"requests"`
		Results  []json.RawMessage `json:"results"`
	} `json:"maintenance"`
	EncodeURIComponent []struct {
		Text    string `json:"text"`
		Encoded string `json:"encoded"`
	} `json:"encodeURIComponent"`
}

// LoadVectors reads the vectors from a test in path's package.
func LoadVectors(t *testing.T, path string) *VectorFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f VectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// Outcome is a call's result as the vectors write it: {"value": ...},
// {"undefined": true} or {"error": {status, message, code?, requestId?,
// details?}}.
func Outcome(v any, err error) any {
	if err != nil {
		e, ok := err.(*APIError)
		if !ok {
			return jsjson.Object{{Key: "error", Value: jsjson.Object{{Key: "message", Value: err.Error()}}}}
		}
		fields := jsjson.Object{{Key: "status", Value: float64(e.Status)}, {Key: "message", Value: e.Message}}
		for _, f := range []jsjson.Member{{Key: "code", Value: e.Code}, {Key: "requestId", Value: e.RequestID}, {Key: "details", Value: e.Details}} {
			if f.Value != Undefined {
				fields = append(fields, f)
			}
		}
		return jsjson.Object{{Key: "error", Value: fields}}
	}
	if v == Undefined {
		return jsjson.Object{{Key: "undefined", Value: true}}
	}
	return jsjson.Object{{Key: "value", Value: v}}
}

func sameJSON(t *testing.T, want json.RawMessage, got any) bool {
	t.Helper()
	w, err := jsjson.Parse(want)
	if err != nil {
		t.Fatal(err)
	}
	return transcript.SameJSON(w, got)
}

func TestAnswerVectors(t *testing.T) {
	f := LoadVectors(t, vectorsPath)
	none := time.Duration(0)
	for i, c := range f.Answers {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { c.Answer.Serve(w) }))
		client := New(Options{Server: srv.URL, Token: f.Token, MaintenanceRetry: &none})
		v, err := client.Meta(context.Background())
		srv.Close()
		if got := Outcome(v, err); !sameJSON(t, c.Result, got) {
			t.Errorf("answer %d (%d): got %s, want %s", i, c.Answer.Status, jsjson.Stringify(got), c.Result)
		}
	}
}

func TestMaintenanceVectors(t *testing.T) {
	f := LoadVectors(t, vectorsPath)
	for _, s := range f.Maintenance {
		t.Run(s.Title, func(t *testing.T) {
			var mu sync.Mutex
			answers := append([]VectorAnswer(nil), s.Answers...)
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				requests++
				if len(answers) == 0 {
					mu.Unlock()
					w.WriteHeader(500)
					return
				}
				next := answers[0]
				answers = answers[1:]
				mu.Unlock()
				next.Serve(w)
			}))
			defer srv.Close()
			clock := time.UnixMilli(f.Now)
			var waits []MaintenanceWait
			client := New(Options{
				Server:        srv.URL,
				Token:         f.Token,
				Now:           func() time.Time { return clock },
				Sleep:         func(d time.Duration) { clock = clock.Add(d) },
				Random:        func() float64 { return s.Random },
				OnMaintenance: func(w MaintenanceWait) { waits = append(waits, w) },
			})
			calls := max(s.Calls, 1)
			for call := 0; call < calls; call++ {
				v, err := client.Meta(context.Background())
				if got := Outcome(v, err); !sameJSON(t, s.Results[call], got) {
					t.Errorf("call %d: got %s, want %s", call, jsjson.Stringify(got), s.Results[call])
				}
			}
			if len(waits) != len(s.Waits) {
				t.Fatalf("%d waits, want %d", len(waits), len(s.Waits))
			}
			for i, w := range s.Waits {
				if ms(waits[i].RetryIn) != w.RetryInMs || ms(waits[i].Remaining) != w.RemainingMs {
					t.Errorf("wait %d: %v and %v remaining, want %vms and %vms", i, waits[i].RetryIn, waits[i].Remaining, w.RetryInMs, w.RemainingMs)
				}
			}
			if requests != s.Requests {
				t.Errorf("%d requests, want %d", requests, s.Requests)
			}
		})
	}
}

func TestEncodeURIComponentVectors(t *testing.T) {
	for _, c := range LoadVectors(t, vectorsPath).EncodeURIComponent {
		if got := EncodeURIComponent(c.Text); got != c.Encoded {
			t.Errorf("EncodeURIComponent(%q) = %q, want %q", c.Text, got, c.Encoded)
		}
	}
}
