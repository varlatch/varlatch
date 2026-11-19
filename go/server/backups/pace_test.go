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
	// The archive is staged in the run's work directory when the sealing
	// ends; the check (about 8 MiB at 4 MiB/s) follows.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if m, _ := filepath.Glob(filepath.Join(f.dir, Dir, ".work-*", "*.vltbak")); len(m) > 0 {
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

// published lists the archives and status records under their final names.
func published(t *testing.T, backups string) []string {
	t.Helper()
	var out []string
	entries, _ := os.ReadDir(backups)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".vltbak") || strings.HasSuffix(e.Name(), ".json") {
			out = append(out, e.Name())
		}
	}
	return out
}

// A stop that lands after the check's last pacing step, so the check
// itself returns success, is caught at the publication boundary: no
// archive under its final name, no status record, no staged archive left.
func TestStopAfterTheLastPacingStep(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testHooks.verified = cancel
	defer func() { testHooks.verified = nil }()
	_, err := f.service(nil).Run(ctx)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "check was stopped") {
		t.Fatalf("a run stopped after its check: %v", err)
	}
	backups := filepath.Join(f.dir, Dir)
	if p := published(t, backups); len(p) != 0 {
		t.Fatalf("a run stopped after its check published %v", p)
	}
	if m, _ := filepath.Glob(filepath.Join(backups, ".work-*")); len(m) != 0 {
		t.Fatalf("left %v", m)
	}
}

// A kill during the check (the disk as it is mid-check, copied, and the
// process gone) leaves no archive that retention or the status list
// counts: the staged archive is in the run's work directory only, and the
// next run's cleanup removes it.
func TestKillDuringCheck(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "CREATE TABLE filler (v BLOB) STRICT")
	for i := 0; i < 4; i++ {
		f.exec(t, "INSERT INTO filler VALUES (randomblob(1048576))")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := f.service(func(o *Options) { o.SealRate = 4 << 20 })
	done := make(chan error, 1)
	go func() { _, err := s.Run(ctx); done <- err }()
	backups := filepath.Join(f.dir, Dir)
	// The check has begun once its scratch directory (the decrypted files)
	// exists in the work directory.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if m, _ := filepath.Glob(filepath.Join(backups, ".work-*", "varlatch-backup-*")); len(m) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the check never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	killed := filepath.Join(t.TempDir(), Dir)
	if err := os.CopyFS(killed, os.DirFS(backups)); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done

	if p := published(t, killed); len(p) != 0 {
		t.Fatalf("mid-check, the disk held %v under final names", p)
	}
	staged, _ := filepath.Glob(filepath.Join(killed, ".work-*", "*.vltbak"))
	if len(staged) != 1 {
		t.Fatalf("mid-check, the staged archive: %v", staged)
	}
	// backup_keep 0: every archive retention counts would be removed.
	s.o.Config.BackupKeep = 0
	if removed := s.retain(killed); len(removed) != 0 {
		t.Fatalf("retention counted %v", removed)
	}
	if _, err := os.Stat(staged[0]); err != nil {
		t.Fatalf("retention touched the staged archive: %v", err)
	}
	s.clean(killed)
	if left, _ := os.ReadDir(killed); len(left) != 0 {
		var names []string
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Fatalf("the next run's cleanup left %v", names)
	}
}
