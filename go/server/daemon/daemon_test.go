// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type install struct {
	dir, conf, kekFile, data, accessLog string
}

func newInstall(t *testing.T, extra string) install {
	t.Helper()
	dir := t.TempDir()
	in := install{dir: dir, conf: filepath.Join(dir, "varlatchd.conf"), kekFile: filepath.Join(dir, "root-kek"),
		data: filepath.Join(dir, "data"), accessLog: filepath.Join(dir, "access.log")}
	if err := os.Mkdir(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.kekFile, []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, extra)
	return in
}

func (in install) write(t *testing.T, extra string) {
	t.Helper()
	conf := fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\naccess_log = %s\n%s", in.data, in.kekFile, in.accessLog, extra)
	if err := os.WriteFile(in.conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
}

type running struct {
	addr    string
	signals chan os.Signal
	done    chan int
	stderr  *syncBuffer
}

func start(t *testing.T, in install) *running {
	t.Helper()
	r := &running{signals: make(chan os.Signal, 1), done: make(chan int, 1), stderr: &syncBuffer{}}
	ready := make(chan string, 1)
	go func() {
		r.done <- Serve(Options{ConfigPath: in.conf, Stderr: r.stderr, Signals: r.signals, Ready: func(a net.Addr) { ready <- a.String() }})
	}()
	select {
	case r.addr = <-ready:
	case code := <-r.done:
		t.Fatalf("exited %d before serving: %s", code, r.stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("not serving after 30 s")
	}
	return r
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.signals <- syscall.SIGTERM
	select {
	case code := <-r.done:
		if code != ExitOK {
			t.Fatalf("stopped with %d: %s", code, r.stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("did not stop within 30 s")
	}
}

func getJSON(t *testing.T, url string, into any) int {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if into != nil {
		if err := json.Unmarshal(b, into); err != nil {
			t.Fatalf("%s: %q: %v", url, b, err)
		}
	}
	return res.StatusCode
}

// varlatchd starts on an empty data directory, creates the schema and the
// installation, serves, stops cleanly on SIGTERM, and starts again on the
// same data with the same installation and Root KEK.
func TestStartStopRestart(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	var ready struct {
		Ready  bool
		Checks map[string]bool
	}
	if code := getJSON(t, "http://"+r.addr+"/readyz", &ready); code != 200 || !ready.Ready {
		t.Fatalf("readyz %d %+v", code, ready)
	}
	var meta struct{ InstallationID string }
	getJSON(t, "http://"+r.addr+"/v1/meta", &meta)
	if !strings.HasPrefix(meta.InstallationID, "inst_") || len(meta.InstallationID) != len("inst_")+26 {
		t.Fatalf("installation id %q", meta.InstallationID)
	}
	if !strings.Contains(r.stderr.String(), "installation initialized") {
		t.Errorf("stderr: %s", r.stderr.String())
	}
	r.stop(t)
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); err != nil {
		t.Fatal(err)
	}

	r = start(t, in)
	var again struct{ InstallationID string }
	getJSON(t, "http://"+r.addr+"/v1/meta", &again)
	if again.InstallationID != meta.InstallationID || strings.Contains(r.stderr.String(), "installation initialized") {
		t.Errorf("restart made another installation: %q then %q", meta.InstallationID, again.InstallationID)
	}
	// A request in flight finishes before the stop completes.
	res, err := http.Get("http://" + r.addr + "/v1/organizations")
	if err != nil || res.StatusCode != http.StatusNotImplemented {
		t.Errorf("stub: %v %v", res, err)
	}
	r.stop(t)
	log, _ := os.ReadFile(in.accessLog)
	if !strings.Contains(string(log), `"path":"/v1/organizations","status":501`) {
		t.Errorf("access log: %s", log)
	}
}

// A configuration error no retry can fix exits 78, before anything is
// opened; one a retry may fix exits 1.
func TestExitStatuses(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, in install)
		want int
	}{
		{"unparsable file", func(t *testing.T, in install) { os.WriteFile(in.conf, []byte("listen 127.0.0.1:1\n"), 0o644) }, ExitConfig},
		{"unknown setting", func(t *testing.T, in install) { in.write(t, "port = 1\n") }, ExitConfig},
		{"repeated setting", func(t *testing.T, in install) { in.write(t, "listen = 127.0.0.1:0\n") }, ExitConfig},
		{"invalid value", func(t *testing.T, in install) { in.write(t, "sync = maybe\n") }, ExitConfig},
		{"no Root KEK configured", func(t *testing.T, in install) {
			os.WriteFile(in.conf, []byte("data_dir = "+in.data+"\n"), 0o644)
		}, ExitConfig},
		{"Root KEK material too short", func(t *testing.T, in install) { os.WriteFile(in.kekFile, []byte("abcd\n"), 0o600) }, ExitConfig},
		{"missing configuration file", func(t *testing.T, in install) { os.Remove(in.conf) }, ExitFailure},
		{"missing Root KEK file", func(t *testing.T, in install) { os.Remove(in.kekFile) }, ExitFailure},
		{"missing data directory", func(t *testing.T, in install) { os.Remove(in.data) }, ExitFailure},
		{"port in use", func(t *testing.T, in install) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			conf, _ := os.ReadFile(in.conf)
			os.WriteFile(in.conf, bytes.Replace(conf, []byte("127.0.0.1:0"), []byte(ln.Addr().String()), 1), 0o644)
		}, ExitFailure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := newInstall(t, "")
			c.prep(t, in)
			var stderr syncBuffer
			got := Serve(Options{ConfigPath: in.conf, Stderr: &stderr, Signals: make(chan os.Signal)})
			if got != c.want {
				t.Errorf("exit %d, want %d: %s", got, c.want, stderr.String())
			}
			if c.want == ExitConfig {
				if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); err == nil {
					t.Error("a configuration error opened the database")
				}
			}
		})
	}
}

// A Root KEK that is not this installation's: refused, and not as a
// configuration error (the database told), so the unit retries.
func TestWrongRootKEK(t *testing.T) {
	in := newInstall(t, "")
	start(t, in).stop(t)
	if err := os.WriteFile(in.kekFile, []byte(hex.EncodeToString(envelope.GenerateKey())), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	if got := Serve(Options{ConfigPath: in.conf, Stderr: &stderr, Signals: make(chan os.Signal)}); got != ExitFailure ||
		!strings.Contains(stderr.String(), "does not open this installation's canary") {
		t.Errorf("exit %d: %s", got, stderr.String())
	}
}

// The canary varlatchd writes opens with the TypeScript server's own
// purpose and context (lib/envelope's fixtures check the format both ways).
func TestCanaryStored(t *testing.T) {
	in := newInstall(t, "")
	start(t, in).stop(t)
	ctx := context.Background()
	s, err := storage.Open(ctx, storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	row, err := query.New(s.Reader()).GetInstallation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var canary envelope.Envelope
	if err := json.Unmarshal([]byte(row.KekCanary), &canary); err != nil {
		t.Fatal(err)
	}
	material, _ := os.ReadFile(in.kekFile)
	key, _ := envelope.ParseRootKEK(string(material))
	if !envelope.VerifyCanary(key, canary, row.ID) || row.BootstrappedAt.Valid {
		t.Errorf("canary %s does not open, or bootstrapped_at set", row.KekCanary)
	}
}

func TestDumpable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("varlatchd runs on Linux")
	}
	if err := disableDumps(); err != nil {
		t.Fatal(err)
	}
	if d, err := dumpable(); err != nil || d != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, %v", d, err)
	}
}
