// SPDX-License-Identifier: AGPL-3.0-or-later

package publictls

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
)

// fakeIssuances is the count in memory.
type fakeIssuances struct {
	mu       sync.Mutex
	counted  int
	oldest   time.Time
	begun    []string
	ended    map[int64]string
	countErr error
}

func (f *fakeIssuances) Count(_ context.Context, name string, since time.Time) (int, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counted, f.oldest, f.countErr
}

func (f *fakeIssuances) Begin(_ context.Context, name string, at time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun = append(f.begun, name)
	return int64(len(f.begun)), nil
}

func (f *fakeIssuances) End(_ context.Context, id int64, outcome string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended == nil {
		f.ended = map[int64]string{}
	}
	f.ended[id] = outcome
	return nil
}

// newCounted is a Manager whose CA does not answer (nothing listens there):
// an attempt that asks fails on the network.
func newCounted(t *testing.T, f *fakeIssuances, limit int, now time.Time) *Manager {
	t.Helper()
	m, err := New(Options{Host: "Vault.Varlatch.Test", CA: "https://127.0.0.1:1/dir", DataDir: t.TempDir(), TLSPort: 443,
		Issuances: f, IssuanceLimit: limit, Now: func() time.Time { return now }, Backoff: []time.Duration{time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

// TestIssuanceCountRefusesAtTheLimit: at the limit the attempt is refused
// before the CA is asked (nothing recorded), with when it may ask again:
// the oldest counted attempt's end of the window.
func TestIssuanceCountRefusesAtTheLimit(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	f := &fakeIssuances{counted: LetsEncryptLimit, oldest: now.Add(-2 * 24 * time.Hour)}
	m := newCounted(t, f, LetsEncryptLimit, now)
	m.attempt(context.Background())
	until := now.Add(5*24*time.Hour + time.Hour)
	if len(f.begun) != 0 || m.state.nextAttempt != until || m.state.failures != 1 || !strings.Contains(m.state.lastError, "the issuance count: 5 certificates for Vault.Varlatch.Test") {
		t.Fatalf("at the limit: begun %q, state %+v", f.begun, m.state)
	}
	if d := m.due(now); d != 5*24*time.Hour+time.Hour {
		t.Errorf("due in %v", d)
	}
}

// TestIssuanceCountRecordsAttempts: under the limit, or with none, the
// attempt is recorded (lower case) before the CA is asked; one that failed
// on the network stays started, so it counts; a count that cannot be read
// asks nothing.
func TestIssuanceCountRecordsAttempts(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for _, limit := range []int{LetsEncryptLimit, 0} {
		f := &fakeIssuances{counted: 4}
		m := newCounted(t, f, limit, now)
		m.attempt(context.Background())
		if len(f.begun) != 1 || f.begun[0] != "vault.varlatch.test" || len(f.ended) != 0 || m.state.failures != 1 {
			t.Errorf("limit %d: begun %q, ended %v, state %+v", limit, f.begun, f.ended, m.state)
		}
	}
	f := &fakeIssuances{countErr: errors.New("the database is gone")}
	m := newCounted(t, f, LetsEncryptLimit, now)
	m.attempt(context.Background())
	if len(f.begun) != 0 || !strings.Contains(m.state.lastError, "the issuance count cannot be read") {
		t.Errorf("an unreadable count: begun %q, state %+v", f.begun, m.state)
	}
}

// TestIssuanceOutcomes: issued on success; refused when the CA answered
// with a problem (nothing issued); left started otherwise (it may have
// issued: it counts).
func TestIssuanceOutcomes(t *testing.T) {
	f := &fakeIssuances{}
	m := newCounted(t, f, 0, time.Now())
	m.endIssuance(context.Background(), 1, nil, true)
	m.endIssuance(context.Background(), 2, fmt.Errorf("obtaining: %w", acme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Status: 403}), true)
	m.endIssuance(context.Background(), 3, context.DeadlineExceeded, true)
	m.endIssuance(context.Background(), 4, fmt.Errorf("obtaining: %w", rateLimit("too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-11-21 08:37:05 UTC: see https://letsencrypt.org/docs/rate-limits/")), true)
	m.endIssuance(context.Background(), -1, nil, true)
	// With no account before it and none after: only a stop's is known to
	// have ended before any order.
	m.endIssuance(context.Background(), 5, context.DeadlineExceeded, false)
	stopped, stop := context.WithCancel(context.Background())
	stop()
	m.endIssuance(stopped, 6, context.Canceled, false)
	// An account there before the attempt, and gone after it, may have been
	// used: certmagic removes one the CA no longer knows.
	m.endIssuance(stopped, 7, context.Canceled, true)
	if f.ended[1] != OutcomeIssued || f.ended[2] != OutcomeRefused || f.ended[6] != OutcomeRefused || len(f.ended) != 3 {
		t.Errorf("ended %v (the rate-limited attempt stays counted, and one that may have asked for an order)", f.ended)
	}
}

func rateLimit(detail string) acme.Problem {
	return acme.Problem{Type: "urn:ietf:params:acme:error:rateLimited", Status: 429, Detail: detail}
}

// TestRateLimitRetryAfter: the CA's rate-limit problem names when to retry,
// and that is the next attempt when it is later than the backoff's; a
// problem without one, or another problem, keeps the backoff.
func TestRateLimitRetryAfter(t *testing.T) {
	limited, until := rateLimitedUntil(fmt.Errorf("wrapped: %w", rateLimit("too many certificates, retry after 2026-11-21 08:37:05 UTC: see the docs")))
	if !limited || !until.Equal(time.Date(2026, 11, 21, 8, 37, 5, 0, time.UTC)) {
		t.Errorf("%v %v", limited, until)
	}
	if limited, until := rateLimitedUntil(rateLimit("too many new orders recently")); !limited || !until.IsZero() {
		t.Errorf("without a time: %v %v", limited, until)
	}
	if limited, _ := rateLimitedUntil(acme.Problem{Type: "urn:ietf:params:acme:error:unauthorized"}); limited {
		t.Error("another problem is not a rate limit")
	}
	if limited, _ := rateLimitedUntil(context.DeadlineExceeded); limited {
		t.Error("a timeout is not a rate limit")
	}
	// The next attempt: the CA's time when later than the backoff's, the
	// backoff's otherwise.
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	m := newCounted(t, &fakeIssuances{}, LetsEncryptLimit, now)
	m.failedLocked(rateLimit("retry after 2026-11-21 08:37:05 UTC"))
	if !m.state.nextAttempt.Equal(time.Date(2026, 11, 21, 8, 37, 5, 0, time.UTC)) {
		t.Errorf("after a rate limit: %v", m.state.nextAttempt)
	}
	m.failedLocked(rateLimit("retry after 2026-11-20 12:00:30 UTC"))
	if !m.state.nextAttempt.Equal(now.Add(time.Minute)) {
		t.Errorf("a retry time before the backoff's: %v", m.state.nextAttempt)
	}
}

// TestLimitFor: Let's Encrypt's limit for its production and staging
// directories, none for another CA.
func TestLimitFor(t *testing.T) {
	for ca, want := range map[string]int{
		"https://acme-v02.api.letsencrypt.org/directory":         5,
		"https://ACME-STAGING-V02.api.letsencrypt.org/directory": 5,
		"https://127.0.0.1:14000/dir":                            0,
		"https://acme.zerossl.com/v2/DV90":                       0,
	} {
		if got := LimitFor(ca); got != want {
			t.Errorf("%s: %d, want %d", ca, got, want)
		}
	}
}
