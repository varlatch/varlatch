// SPDX-License-Identifier: AGPL-3.0-or-later

package publictls

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// hangingCA is a certificate authority that takes every request and never
// answers: an issuance in progress, until the test ends. asked receives
// one value when the first request came.
func hangingCA(t *testing.T) (directory string, roots *x509.CertPool, asked <-chan struct{}) {
	t.Helper()
	first, ended := make(chan struct{}, 1), make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case first <- struct{}{}:
		default:
		}
		select {
		case <-ended:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(ended) })
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv.URL + "/directory", roots, first
}

// accountCA is a certificate authority that registers the account and then
// takes the order and never answers, until the test ends: ordered receives
// one value when the order came.
func accountCA(t *testing.T) (directory string, roots *x509.CertPool, ordered <-chan struct{}) {
	t.Helper()
	first, ended := make(chan struct{}, 1), make(chan struct{})
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "bm9uY2U")
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"newNonce":"`+srv.URL+`/nonce","newAccount":"`+srv.URL+`/account","newOrder":"`+srv.URL+`/order"}`)
		case "/nonce":
		case "/account":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", srv.URL+"/account/1")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"status":"valid"}`)
		case "/order":
			select {
			case first <- struct{}{}:
			default:
			}
			select {
			case <-ended:
			case <-r.Context().Done():
			}
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(ended) })
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv.URL + "/directory", roots, first
}

// countedIssuances counts the attempts: Run reads the count once for each.
// With block, the read itself waits for ctx, as a read of the database a
// stop cuts short. With stall, the record of an attempt's end waits for its
// context, as a write that is not begun. outcomes are the ends recorded.
type countedIssuances struct {
	reads        atomic.Int64
	block, stall bool
	reading      chan struct{}
	mu           sync.Mutex
	outcomes     []string
}

func (c *countedIssuances) Count(ctx context.Context, _ string, _ time.Time) (int, time.Time, error) {
	if c.reads.Add(1) == 1 {
		close(c.reading)
	}
	if c.block {
		<-ctx.Done()
		return 0, time.Time{}, ctx.Err()
	}
	return 0, time.Time{}, nil
}
func (c *countedIssuances) Begin(context.Context, string, time.Time) (int64, error) { return 1, nil }
func (c *countedIssuances) End(ctx context.Context, _ int64, outcome string, _ time.Time) error {
	if c.stall {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outcomes = append(c.outcomes, outcome)
	return nil
}

// TestRunEndsDuringAnAttempt: a stop while a certificate is being obtained
// or renewed ends Run, after that one attempt. Run tried again without end
// then, so varlatchd never exited. The attempt is recorded as refused, and
// so not counted, only when it is known to have ended before any order:
// with no ACME account before it and none after it. Anything else counts.
func TestRunEndsDuringAnAttempt(t *testing.T) {
	const host = "vault.example.com"
	for _, c := range []struct {
		name                             string
		renewal, reading, order, account bool
		want                             string // the end recorded, "" for none
	}{
		{name: "the first certificate, before the account", want: OutcomeRefused},
		{name: "the first certificate, at the order", order: true},
		{name: "an account of an earlier attempt", account: true},
		{name: "a renewal", renewal: true},
		{name: "reading the issuance count", reading: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ca := hangingCA
			if c.order {
				ca = accountCA
			}
			directory, roots, asked := ca(t)
			counted := &countedIssuances{block: c.reading, reading: make(chan struct{})}
			m := newManager(t, Options{Host: host, CA: directory, CARoots: roots, Issuances: counted})
			if c.renewal {
				// In its last third: renewed as soon as Run starts.
				now := time.Now()
				certPEM, keyPEM := selfSigned(t, host, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
				issuer := m.issuer.IssuerKey()
				for key, value := range map[string][]byte{
					certmagic.StorageKeys.SiteCert(issuer, host):       certPEM,
					certmagic.StorageKeys.SitePrivateKey(issuer, host): keyPEM,
					certmagic.StorageKeys.SiteMeta(issuer, host):       []byte(`{"sans":["` + host + `"]}`),
				} {
					if err := m.cm.Storage.Store(context.Background(), key, value); err != nil {
						t.Fatal(err)
					}
				}
			}
			// A lock an earlier process left says nothing of an account.
			if err := m.cm.Storage.Store(context.Background(), "locks/left.lock", []byte("{}")); err != nil {
				t.Fatal(err)
			}
			if c.account {
				// Any file of an account's: how certmagic names it is not
				// relied on.
				if err := m.cm.Storage.Store(context.Background(), "acme/a-ca/users/ops/ops.json", []byte("{}")); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ended := make(chan struct{})
			go func() {
				defer close(ended)
				m.Run(ctx)
			}()
			started := asked
			if c.reading {
				started = counted.reading
			}
			select {
			case <-started:
			case <-time.After(20 * time.Second):
				t.Fatalf("no attempt was made:\n%s", fmtReport(m))
			}
			if renewing := m.HasCertificate(); renewing != c.renewal {
				t.Fatalf("a certificate is served: %v, want %v", renewing, c.renewal)
			}
			cancel()
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatalf("Run did not end within 5 s of the stop; it began %d attempts", counted.reads.Load())
			}
			if n := counted.reads.Load(); n != 1 {
				t.Errorf("%d attempts, want the one the stop cut short", n)
			}
			if got := strings.Join(counted.outcomes, ","); got != c.want {
				t.Errorf("the attempt's recorded end is %q, want %q", got, c.want)
			}
			if st := m.state; st.attempting || st.failures != 0 || st.lastError != "" {
				t.Errorf("the attempt cut short is recorded as a failure: %+v", st)
			}
		})
	}
}

// TestRunAfterTheStop: Run on a context that ended makes no attempt.
func TestRunAfterTheStop(t *testing.T) {
	counted := &countedIssuances{reading: make(chan struct{})}
	m := newManager(t, Options{Host: "vault.example.com", Issuances: counted})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		m.Run(ctx)
	}()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatalf("Run did not end within 5 s; it began %d attempts", counted.reads.Load())
	}
	if n := counted.reads.Load(); n != 0 {
		t.Errorf("%d attempts after the stop", n)
	}
}

// TestRunEndsWithAStalledRecord: the record of an attempt's end, made while
// stopping, is given up after endIssuanceWait.
func TestRunEndsWithAStalledRecord(t *testing.T) {
	old := endIssuanceWait
	endIssuanceWait = 200 * time.Millisecond
	t.Cleanup(func() { endIssuanceWait = old })
	directory, roots, asked := hangingCA(t)
	counted := &countedIssuances{stall: true, reading: make(chan struct{})}
	m := newManager(t, Options{Host: "vault.example.com", CA: directory, CARoots: roots, Issuances: counted})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		m.Run(ctx)
	}()
	select {
	case <-asked:
	case <-time.After(20 * time.Second):
		t.Fatal("no attempt was made")
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("Run waits for the record without end")
	}
}
