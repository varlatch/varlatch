// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux || darwin

package backups

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// G7 for backups, on a full disk: these fill a small filesystem of their
// own, named by VARLATCH_G7_SMALL_FS (go.yml mounts a 32 MiB tmpfs and
// sets VARLATCH_REQUIRE_G7_DISK=1, as for the server's disk tests).

func smallFS(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("VARLATCH_G7_SMALL_FS")
	if dir == "" {
		if os.Getenv("VARLATCH_REQUIRE_G7_DISK") == "1" {
			t.Fatal("VARLATCH_G7_SMALL_FS is not set, and VARLATCH_REQUIRE_G7_DISK requires the disk tests")
		}
		t.Skip("VARLATCH_G7_SMALL_FS names no small filesystem to fill")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	if size := int64(st.Blocks) * int64(st.Bsize); size > 256<<20 {
		t.Fatalf("%s is %d MiB: the disk tests fill it, so it must be a small filesystem of its own", dir, size>>20)
	}
	sub, err := os.MkdirTemp(dir, "g7-backup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sub) })
	return sub
}

// leaveFree fills the filesystem until about free bytes are left; the
// returned function frees the space again.
func leaveFree(t *testing.T, dir string, free int) func() {
	t.Helper()
	slack := filepath.Join(dir, "slack")
	if err := os.WriteFile(slack, make([]byte, free), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ballast")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for size := len(chunk); size >= 512; {
		if _, err := f.Write(chunk[:size]); err != nil {
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatal(err)
			}
			size /= 2
		}
	}
	_ = f.Close()
	if err := os.Remove(slack); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// A full disk during the snapshot: the run fails, leaves no archive, no
// status record and no temporary file, and loses nothing committed; the
// free-space check refuses such a run before it starts; and once there is
// room a run succeeds.
func TestFullDiskDuringSnapshot(t *testing.T) {
	ctx := context.Background()
	f := newFixtureIn(t, smallFS(t))
	f.exec(t, "CREATE TABLE committed (v BLOB) STRICT")
	for range 6 {
		f.exec(t, "INSERT INTO committed VALUES (randomblob(1048576))")
	}
	rows := func() int {
		t.Helper()
		var n int
		if err := f.store.Reader().QueryRow("SELECT count(*) FROM committed").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	clean := func(what string) {
		t.Helper()
		if l := listing(t, filepath.Join(f.dir, Dir)); l != "" {
			t.Errorf("%s left %q", what, l)
		}
	}
	free := leaveFree(t, f.dir, 1<<20)

	// The free-space check refuses first.
	var space *SpaceError
	if _, err := f.service(nil).Run(ctx); !errors.As(err, &space) {
		t.Fatalf("on a full disk: %v", err)
	}
	clean("the refused run")
	// Past the check (as if the disk filled after it), the snapshot fails.
	past := f.service(func(o *Options) { o.FreeSpace = func(string) (int64, error) { return 1 << 40, nil } })
	if _, err := past.Run(ctx); err == nil || !errors.Is(err, syscall.ENOSPC) && !strings.Contains(err.Error(), "database or disk is full") {
		t.Fatalf("a snapshot on a full disk: %v", err)
	}
	clean("the failed snapshot")
	if n := rows(); n != 6 {
		t.Fatalf("%d committed rows after the failed snapshot", n)
	}
	var check string
	if err := f.store.Reader().QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check %q, %v", check, err)
	}

	free()
	f.exec(t, "INSERT INTO committed VALUES (randomblob(1024))")
	res, err := past.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verification.Integrity || rows() != 7 {
		t.Errorf("%+v, %d rows", res, rows())
	}
}
