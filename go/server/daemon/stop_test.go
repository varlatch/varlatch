// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/publictls"
	"github.com/varlatch/varlatch/go/server/write"
)

const stopHost = "vault.varlatch.test"

// hangingInstall is an installation with public HTTPS whose CA takes every
// request and never answers, until the test ends: an issuance in progress.
// asked receives a value for each request.
func hangingInstall(t *testing.T) (in install, asked chan struct{}) {
	t.Helper()
	asked = make(chan struct{}, 64)
	ended := make(chan struct{})
	ca := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case asked <- struct{}{}:
		default:
		}
		select {
		case <-ended:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(ca.Close)
	t.Cleanup(func() { close(ended) })
	rootFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, port, _ := net.SplitHostPort(addr)
	return newInstall(t, "public_url = https://"+stopHost+":"+port+"\nlisten_https = "+addr+"\nlisten_http_redirect = off\n"+
		"acme_ca = "+ca.URL+"/directory\nacme_ca_root = "+rootFile+"\nacme_email = ops@varlatch.test\n"), asked
}

func waitAsked(t *testing.T, asked <-chan struct{}, out fmt.Stringer) {
	t.Helper()
	select {
	case <-asked:
	case <-time.After(30 * time.Second):
		t.Fatalf("the CA was not asked: %s", out.String())
	}
}

// issuances are the recorded attempts, as name outcome ended, the database
// whole (integrity_check), and how many of them count for stopHost.
func issuances(t *testing.T, path string) (rows []string, counted int) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var ok string
	if err := store.Reader().QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&ok); err != nil || ok != "ok" {
		t.Fatalf("integrity_check: %q, %v", ok, err)
	}
	r, err := store.Reader().QueryContext(ctx, "SELECT name || ' ' || outcome || ' ' || (ended_at IS NOT NULL) FROM certificate_issuances ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for r.Next() {
		var row string
		if err := r.Scan(&row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	counted, _, err = publictls.StoreIssuances{DB: store}.Count(ctx, stopHost, time.Now().Add(-publictls.IssuanceWindow))
	if err != nil {
		t.Fatal(err)
	}
	return rows, counted
}

func (in install) database() string { return filepath.Join(in.data, "varlatch.db") }

// TestStopDuringAnIssuance: SIGTERM while the first public certificate is
// being obtained (the CA took the request for its directory and does not
// answer) stops varlatchd cleanly and at once; so does a second start on
// the same data. It did not stop at all, and systemd killed it. No order
// was asked for, so neither attempt counts.
func TestStopDuringAnIssuance(t *testing.T) {
	in, asked := hangingInstall(t)
	for run := 1; run <= 2; run++ {
		for len(asked) > 0 { // an earlier run's requests
			<-asked
		}
		r := startWith(t, in, &hooks{})
		waitAsked(t, asked, r.stderr)
		began := time.Now()
		r.signals <- syscall.SIGTERM
		select {
		case code := <-r.done:
			<-r.exited
			if code != ExitOK {
				t.Fatalf("run %d: stopped with %d: %s", run, code, r.stderr.String())
			}
		case <-time.After(StopTimeout / 2):
			t.Fatalf("run %d: varlatchd did not stop within %s of SIGTERM: %s", run, StopTimeout/2, r.stderr.String())
		}
		t.Logf("run %d: stopped %s after SIGTERM", run, time.Since(began).Round(time.Millisecond))
		if n := strings.Count(r.stderr.String(), "could not get certificate from issuer"); n > 1 {
			t.Errorf("run %d: %d attempts were made while stopping", run, n)
		}
		rows, counted := issuances(t, in.database())
		if want := strings.TrimSpace(strings.Repeat(stopHost+" refused 1\n", run)); strings.Join(rows, "\n") != want || counted != 0 {
			t.Errorf("run %d: the issuance count holds %q, %d counted; want every attempt refused", run, rows, counted)
		}
	}
}

// stalledIssuances are the installation's, but the record of an attempt's
// end never answers, whatever its context: a write the database began and
// does not finish.
type stalledIssuances struct {
	publictls.Issuances
	release <-chan struct{}
}

func (s stalledIssuances) End(context.Context, int64, string, time.Time) error {
	<-s.release
	return context.Canceled
}

// TestStopWithAStalledAttempt: an attempt that does not end is left at the
// stop's deadline for work in flight, and the rest of the stop goes on: the
// database is closed, the attempt stays recorded as started, and counts.
func TestStopWithAStalledAttempt(t *testing.T) {
	in, asked := hangingInstall(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	const limit = 8 * time.Second
	r := startWith(t, in, &hooks{stopTimeout: limit, publicTLS: func(o *publictls.Options) {
		o.Issuances = stalledIssuances{o.Issuances, release}
	}})
	waitAsked(t, asked, r.stderr)
	began := time.Now()
	r.signals <- syscall.SIGTERM
	select {
	case code := <-r.done:
		<-r.exited
		if took := time.Since(began); code != ExitOK || took < stopDrain(limit) || took > limit {
			t.Errorf("stopped with %d after %s, want %d between %s and %s: %s", code, took, ExitOK, stopDrain(limit), limit, r.stderr.String())
		}
	case <-time.After(2 * limit):
		t.Fatalf("varlatchd did not stop: %s", r.stderr.String())
	}
	if out := r.stderr.String(); !strings.Contains(out, "attempt did not end at the stop deadline") || !strings.Contains(out, "msg=stopped") {
		t.Errorf("the stop said: %s", out)
	}
	if rows, counted := issuances(t, in.database()); strings.Join(rows, ",") != stopHost+" started 0" || counted != 1 {
		t.Errorf("the issuance count holds %q, %d counted; want the one attempt, started and counted", rows, counted)
	}
}

// TestStopWithAStalledWriter: the database's writer does not answer (a
// transaction in progress, its writes made and not committed) when SIGTERM
// comes, so neither the attempt's end nor the database's close can be. The
// process ends within the stop's limit all the same, with ExitFailure, in
// the middle of that transaction; and the database is whole: what was
// committed is there, the transaction is not, and the attempt counts. The
// next start serves, and stops cleanly. A real process and a real signal.
func TestStopWithAStalledWriter(t *testing.T) {
	const limit = 3 * time.Second
	if conf := os.Getenv("VARLATCH_TEST_STALL_CONF"); conf != "" {
		trigger := os.Getenv("VARLATCH_TEST_STALL_TRIGGER")
		os.Exit(serve(Options{ConfigPath: conf, Stderr: os.Stderr}, &hooks{stopTimeout: limit, writer: func(w *write.Writer) {
			go func() {
				for {
					if _, err := os.Stat(trigger); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				_ = w.Store.Write(context.Background(), func(tx *storage.Tx) error {
					if _, err := tx.ExecContext(context.Background(), "INSERT INTO certificate_issuances (name, started_at) VALUES ('half.done', 1)"); err != nil {
						panic(err)
					}
					fmt.Fprintln(os.Stderr, "the writer is stalled")
					select {}
				})
			}()
		}}))
	}
	in, asked := hangingInstall(t)
	trigger := filepath.Join(in.dir, "stall")
	out := &syncBuffer{}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStopWithAStalledWriter$")
	cmd.Env = append(os.Environ(), "VARLATCH_TEST_STALL_CONF="+in.conf, "VARLATCH_TEST_STALL_TRIGGER="+trigger)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	// The attempt's start is committed; then the writer stalls.
	waitAsked(t, asked, out)
	if err := os.WriteFile(trigger, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(20 * time.Second); !strings.Contains(out.String(), "the writer is stalled") || !strings.Contains(out.String(), "is serving"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the writer did not stall: %s", out.String())
		}
	}
	began := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(4 * limit):
		t.Fatalf("varlatchd did not end within %s of SIGTERM: %s", 4*limit, out.String())
	}
	took := time.Since(began)
	if code := cmd.ProcessState.ExitCode(); code != ExitFailure || took > limit+5*time.Second {
		t.Errorf("ended with %d after %s, want %d within %s: %s", code, took, ExitFailure, limit, out.String())
	}
	if !bytes.Contains([]byte(out.String()), []byte("the stop did not end in time")) {
		t.Errorf("the stop said: %s", out.String())
	}
	if rows, counted := issuances(t, in.database()); strings.Join(rows, ",") != stopHost+" started 0" || counted != 1 {
		t.Errorf("the issuance count holds %q, %d counted; want the one attempt, started and counted, and nothing of the transaction", rows, counted)
	}
	// And it starts again.
	for len(asked) > 0 {
		<-asked
	}
	r := startWith(t, in, &hooks{})
	waitAsked(t, asked, r.stderr)
	r.stop(t)
	if rows, counted := issuances(t, in.database()); strings.Join(rows, ",") != stopHost+" started 0,"+stopHost+" refused 1" || counted != 1 {
		t.Errorf("after the next run the issuance count holds %q, %d counted", rows, counted)
	}
}
