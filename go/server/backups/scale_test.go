// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package backups

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// TestScaleBackup times a backup of the installation in
// VARLATCH_SCALE_DATA (TestScale's, kept; a copy: it is written to), paced
// and not, and what a write and a read wait meanwhile. Off by default.
func TestScaleBackup(t *testing.T) {
	dir := os.Getenv("VARLATCH_SCALE_DATA")
	if dir == "" {
		t.Skip("VARLATCH_SCALE_DATA is not set")
	}
	ctx := context.Background()
	key := filepath.Join(dir, "bek")
	if err := os.WriteFile(key, []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Listen: "127.0.0.1:8686", DataDir: dir, AccessLog: "off", BackupKeyFile: key, BackupKeep: 1}
	store, err := storage.Open(ctx, storage.Options{Path: cfg.DatabasePath()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS scale_probe (id INTEGER PRIMARY KEY, v TEXT) STRICT")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A write and a read every 20 ms until stop is closed.
	probe := func(stop chan struct{}) func() {
		var writes, reads []time.Duration
		done := make(chan struct{})
		go func() {
			defer close(done)
			tick := time.NewTicker(20 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
				at := time.Now()
				_ = store.Write(ctx, func(tx *storage.Tx) error {
					_, err := tx.ExecContext(ctx, "INSERT INTO scale_probe (v) VALUES ('x')")
					return err
				})
				writes = append(writes, time.Since(at))
				at = time.Now()
				var n int
				_ = store.Reader().QueryRowContext(ctx, "SELECT count(*) FROM (SELECT 1 FROM audit_events ORDER BY event_order DESC LIMIT 100)").Scan(&n)
				reads = append(reads, time.Since(at))
			}
		}()
		return func() {
			<-done
			for _, l := range []struct {
				name string
				d    []time.Duration
			}{{"write", writes}, {"read", reads}} {
				slices.Sort(l.d)
				q := func(p float64) time.Duration { return l.d[int(p*float64(len(l.d)-1))].Round(10 * time.Microsecond) }
				t.Logf("  %-5s n %d, p50 %v, p95 %v, p99 %v, max %v", l.name, len(l.d), q(0.5), q(0.95), q(0.99), q(1))
			}
		}
	}
	cpu := func() time.Duration {
		var u syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &u)
		return time.Duration(u.Utime.Nano() + u.Stime.Nano())
	}
	stop := make(chan struct{})
	end := probe(stop)
	at := cpu()
	time.Sleep(20 * time.Second)
	close(stop)
	t.Logf("idle: %.1f s of CPU in 20 s", (cpu() - at).Seconds())
	end()
	for _, c := range []struct {
		name string
		o    Options
	}{{"paced", Options{}}, {"not paced", Options{SealRate: -1, Snapshot: storage.SnapshotOptions{StepPages: 4096, Pause: time.Nanosecond}}}} {
		c.o.Config, c.o.Store, c.o.RootKEK, c.o.Log = cfg, store, migrationtest.Load(t).RootKEK, slog.New(slog.DiscardHandler)
		stop := make(chan struct{})
		end := probe(stop)
		at, start := cpu(), time.Now()
		res, err := New(c.o).Run(ctx)
		wall, used := time.Since(start), cpu()-at
		close(stop)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %.1f s, %.1f s of CPU (the probe's included); snapshot %.1f s, seal %.1f s; %d MB, archive %.1f MB", c.name, wall.Seconds(), used.Seconds(),
			float64(res.Capture.SnapshotHeldMs)/1000, float64(res.Capture.DumpMs)/1000, res.Capture.DumpBytes/1e6, float64(res.Bytes)/1e6)
		end()
		// And a restore's opening of it.
		bek, _ := os.ReadFile(key)
		material, _ := backup.ParseKey(string(bek))
		b, _ := backup.KeyBEK(material)
		start = time.Now()
		o, err := backup.Open(res.Path, b, dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("  opened in %.1f s", time.Since(start).Seconds())
		_ = o.Close()
	}
}
