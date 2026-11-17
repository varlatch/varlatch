// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The API client vectors (../../testdata/vectors/apiclient.json) as the CLI
// uses the client: each error answer through main.ts's catch (the message
// on stderr and the exit status, or the TypeError it throws), the
// maintenance notice, and the expiry warnings.

const apiclientVectors = "../../testdata/vectors/apiclient.json"

type answerVector struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
	Body    *string     `json:"body"`
	BodyHex *string     `json:"bodyHex"`
}

type apiclientFile struct {
	Token   string  `json:"token"`
	Held    string  `json:"held"`
	Now     float64 `json:"now"`
	Answers []struct {
		Answer json.RawMessage `json:"answer"`
		CLI    *struct {
			Stderr *string `json:"stderr"`
			Exit   int     `json:"exit"`
			Throws *string `json:"throws"`
		} `json:"cli"`
	} `json:"answers"`
	Maintenance []struct {
		Title string `json:"title"`
		Waits []struct {
			RetryInMs   float64 `json:"retryInMs"`
			RemainingMs float64 `json:"remainingMs"`
		} `json:"waits"`
		Notice string `json:"notice"`
	} `json:"maintenance"`
	Expiry struct {
		Stored []struct {
			Credential json.RawMessage `json:"credential"`
			Warning    *string         `json:"warning"`
		} `json:"stored"`
		Header []struct {
			ExpiresAt string  `json:"expiresAt"`
			Warning   *string `json:"warning"`
		} `json:"header"`
	} `json:"expiry"`
}

func loadAPIClientVectors(t *testing.T) *apiclientFile {
	t.Helper()
	data, err := os.ReadFile(apiclientVectors)
	if err != nil {
		t.Fatal(err)
	}
	var f apiclientFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// serve writes an answer as the vectors' Response holds it.
func serve(w http.ResponseWriter, raw json.RawMessage) {
	var a answerVector
	_ = json.Unmarshal(raw, &a)
	h := w.Header()
	for _, kv := range a.Headers {
		h.Add(kv[0], kv[1])
	}
	if h.Get("Content-Type") == "" {
		if a.Body != nil && a.Status != 204 {
			h["Content-Type"] = []string{"text/plain;charset=UTF-8"}
		} else {
			h["Content-Type"] = nil
		}
	}
	w.WriteHeader(a.Status)
	if a.Body != nil {
		_, _ = w.Write([]byte(*a.Body))
	}
	if a.BodyHex != nil {
		b := make([]byte, len(*a.BodyHex)/2)
		for i := range b {
			var x byte
			for _, c := range []byte((*a.BodyHex)[2*i : 2*i+2]) {
				x <<= 4
				switch {
				case c >= 'a':
					x |= c - 'a' + 10
				default:
					x |= c - '0'
				}
			}
			b[i] = x
		}
		_, _ = w.Write(b)
	}
}

func TestAPIErrorVectors(t *testing.T) {
	f := loadAPIClientVectors(t)
	none := time.Duration(0)
	for i, c := range f.Answers {
		if c.CLI == nil {
			continue
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { serve(w, c.Answer) }))
		client := apiclient.New(apiclient.Options{Server: srv.URL, Token: f.Token, MaintenanceRetry: &none})
		_, err := client.Meta(context.Background())
		srv.Close()
		if err == nil {
			t.Fatalf("answer %d: no error", i)
		}
		r := &Run{Env: MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir()}, Secrets: &Secrets{}}
		r.Secrets.Remember(f.Token)
		r.Secrets.Remember(f.Held)
		mapped := r.mapClientError(err)
		var exit *exitError
		switch {
		case c.CLI.Throws != nil:
			var typeErr *clientctx.TypeError
			if !errors.As(mapped, &typeErr) || "TypeError: "+typeErr.Message != *c.CLI.Throws {
				t.Errorf("answer %d: %v, want it to throw %s", i, mapped, *c.CLI.Throws)
			}
		case !errors.As(mapped, &exit):
			t.Errorf("answer %d: %v is not a failure", i, mapped)
		case exit.message != *c.CLI.Stderr || exit.code != c.CLI.Exit:
			t.Errorf("answer %d: %q (%d), want %q (%d)", i, exit.message, exit.code, *c.CLI.Stderr, c.CLI.Exit)
		}
	}
}

func TestMaintenanceNoticeVectors(t *testing.T) {
	for _, s := range loadAPIClientVectors(t).Maintenance {
		var stderr bytes.Buffer
		r := &Run{IO: IO{Stderr: &stderr}}
		for _, w := range s.Waits {
			r.maintenanceNotice(apiclient.MaintenanceWait{RetryIn: time.Duration(w.RetryInMs) * time.Millisecond, Remaining: time.Duration(w.RemainingMs) * time.Millisecond})
		}
		if stderr.String() != s.Notice {
			t.Errorf("%s: notice %q, want %q", s.Title, stderr.String(), s.Notice)
		}
	}
}

func TestExpiryWarningVectors(t *testing.T) {
	f := loadAPIClientVectors(t)
	for _, c := range f.Expiry.Stored {
		credential, err := jsjson.Parse(c.Credential)
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if c.Warning != nil {
			want = *c.Warning
		}
		if got := ExpiryWarning("https://s.example", credential, f.Now); got != want {
			t.Errorf("ExpiryWarning(%s) = %q, want %q", c.Credential, got, want)
		}
	}
	for _, c := range f.Expiry.Header {
		want := ""
		if c.Warning != nil {
			want = *c.Warning
		}
		if got := EnvTokenExpiryWarning("https://s.example", c.ExpiresAt, f.Now); got != want {
			t.Errorf("EnvTokenExpiryWarning(%q) = %q, want %q", c.ExpiresAt, got, want)
		}
	}
}
