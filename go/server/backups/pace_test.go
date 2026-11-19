// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
)

// A backup derives the archive key (scrypt: 32 MiB, about 0.2 s of a CPU)
// once: the sealing derives it and the check reuses it (ADR-0059 G9's bound
// run, 2026-11-18: two derivations a backup were a third of its CPU).
func TestRunDerivesOnce(t *testing.T) {
	f := newFixture(t)
	s := f.service(nil)
	before := backup.Derivations()
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := backup.Derivations() - before; n != 1 {
		t.Fatalf("a backup derived %d archive keys, want 1", n)
	}
	if !res.Verification.Integrity || !res.Verification.KeyMatch || !res.Verification.Compatibility {
		t.Fatalf("verification %+v", res.Verification)
	}
}

// The manifest's hashing, the sealing and the check each go at SealRate:
// before, only the sealing did, and the check's full re-open ran unpaced
// at a whole CPU. With every step paced a run takes at least the paced
// bytes over the rate: the hashing (the snapshot), the sealing (about the
// snapshot) and the check (decryption and hashing, twice the snapshot),
// four times the snapshot where the sealing alone was once.
func TestRunPacesHashingSealingAndCheck(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "CREATE TABLE filler (v BLOB) STRICT")
	f.exec(t, "INSERT INTO filler VALUES (randomblob(400000))")
	unpaced, err := f.service(nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	size := unpaced.Capture.DumpBytes
	rate := int64(float64(size) / 0.25) // the snapshot in 0.25 s
	s := f.service(func(o *Options) { o.SealRate = rate })
	start := time.Now()
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if want := time.Duration(0.9 * 4 * 0.25 * float64(time.Second)); elapsed < want {
		t.Fatalf("a paced run took %v, under the %v that pacing every step gives (the snapshot %d bytes at %d bytes/s)", elapsed, want, size, rate)
	}
	if !res.Verification.Integrity || !res.Verification.KeyMatch || !res.Verification.Compatibility {
		t.Fatalf("verification %+v", res.Verification)
	}
}

// A stop during the paced check ends the run as a stop during the sealing
// does: no archive and no status record are left.
func TestStopDuringCheck(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "CREATE TABLE filler (v BLOB) STRICT")
	for i := 0; i < 4; i++ {
		f.exec(t, "INSERT INTO filler VALUES (randomblob(1048576))")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := f.service(func(o *Options) { o.SealRate = 4 << 20 })
	done := make(chan error, 1)
	go func() { _, err := s.Run(ctx); done <- err }()
	// The archive is linked into place when the sealing ends; the check
	// (about 8 MiB at 4 MiB/s) follows.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if m, _ := filepath.Glob(filepath.Join(f.dir, Dir, "*.vltbak")); len(m) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no archive was sealed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "check was stopped") {
		t.Fatalf("a run stopped during its check: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(f.dir, Dir))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".vltbak") || strings.HasSuffix(e.Name(), ".json") {
			t.Fatalf("a run stopped during its check left %s", e.Name())
		}
	}
}
