// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentRequestsShareTheBudget: requests in flight together on one
// client (the MCP server's tool calls) ride out maintenance on the one
// budget the SDK keeps per client, without a data race (run with -race).
func TestConcurrentRequestsShareTheBudget(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1)%2 == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"MAINTENANCE","message":"m"}}`))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := New(Options{Server: srv.URL, Env: mapEnv{}, Sleep: func(time.Duration) {}})
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			if _, err := c.Request(context.Background(), "GET", "/v1/organizations", NoBody, nil); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
