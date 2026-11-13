// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestLiveTrustedRootCancelledBefore(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := liveTrustedRoot(ctx, "", srv.URL, srv.Client()); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests after cancellation", hits.Load())
	}
}

// A repository that stops answering cannot hold the caller past its
// deadline.
func TestLiveTrustedRootStalledResponse(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{"))
		w.(http.Flusher).Flush()
		select { // stall mid-body
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := liveTrustedRoot(ctx, "", srv.URL, srv.Client())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("returned %s after a 300 ms deadline", took)
	}
}

func TestFetcher(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("hello"))
		case "/missing":
			http.NotFound(w, r)
		case "/flaky":
			if calls.Load()%2 == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("second try"))
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		case "/bad":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	f := &ctxFetcher{ctx: context.Background(), client: srv.Client()}

	if data, err := f.DownloadFile(srv.URL+"/ok", 10, 0); err != nil || string(data) != "hello" {
		t.Fatalf("ok: %q %v", data, err)
	}
	var httpErr *metadata.ErrDownloadHTTP
	calls.Store(0)
	if _, err := f.DownloadFile(srv.URL+"/missing", 10, 0); !errors.As(err, &httpErr) || httpErr.StatusCode != 404 || calls.Load() != 1 {
		t.Fatalf("404: %v after %d calls (go-tuf needs ErrDownloadHTTP, no retry)", err, calls.Load())
	}
	calls.Store(0)
	if _, err := f.DownloadFile(srv.URL+"/bad", 10, 0); !errors.As(err, &httpErr) || calls.Load() != 1 {
		t.Fatalf("403: %v after %d calls", err, calls.Load())
	}
	calls.Store(0)
	if data, err := f.DownloadFile(srv.URL+"/flaky", 100, 0); err != nil || string(data) != "second try" || calls.Load() != 2 {
		t.Fatalf("503 then 200: %q %v after %d calls", data, err, calls.Load())
	}
	var lenErr *metadata.ErrDownloadLengthMismatch
	if _, err := f.DownloadFile(srv.URL+"/big", 10, 0); !errors.As(err, &lenErr) {
		t.Fatalf("too long: %v", err)
	}
}
