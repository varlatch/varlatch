// SPDX-License-Identifier: Apache-2.0

//go:build unix

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Where the temporary files go: SQLite's own order while one of those is
// writable, the data directory when none is, a refusal naming what to set
// when that is not either. Whatever is not asked is not set.
func TestPrepareTempChoosesADirectory(t *testing.T) {
	for _, c := range []struct {
		name     string
		env      map[string]string
		writable string
		want     string
		set      string
	}{
		{"SQLITE_TMPDIR", map[string]string{"SQLITE_TMPDIR": "/a", "TMPDIR": "/b"}, "/a /b /tmp /data", "/a", ""},
		{"SQLITE_TMPDIR is not writable", map[string]string{"SQLITE_TMPDIR": "/a", "TMPDIR": "/b"}, "/b /tmp /data", "/b", ""},
		{"the system's", nil, "/tmp /data", "/tmp", ""},
		{"none but the data directory", map[string]string{"SQLITE_TMPDIR": "/a", "TMPDIR": "/b"}, "/data", "/data", "/data"},
		{"none at all", nil, "", "", ""},
	} {
		var set string
		got, err := prepareTemp("/data", func(n string) string { return c.env[n] },
			func(n, v string) error {
				if n != "SQLITE_TMPDIR" {
					t.Errorf("%s: sets %s", c.name, n)
				}
				set = v
				return nil
			},
			func(d string) bool { return strings.Contains(" "+c.writable+" ", " "+d+" ") })
		if got != c.want || set != c.set || (err == nil) != (c.want != "") {
			t.Errorf("%s: %q, set %q, %v", c.name, got, set, err)
		}
		if err != nil && (!strings.Contains(err.Error(), "/data") || !strings.Contains(err.Error(), "set SQLITE_TMPDIR")) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestUsableTempIsADirectoryThatCanBeWritten(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !usableTemp(dir) || usableTemp(file) || usableTemp(filepath.Join(dir, "missing")) {
		t.Error("usableTemp")
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		if usableTemp(dir) {
			t.Error("a directory without write permission")
		}
		_ = os.Chmod(dir, 0o700)
	}
}

// SQLite, as this driver builds it, reads SQLITE_TMPDIR as PrepareTemp set
// it: in a process of its own (it is read once), the open temporary file is
// in that directory, without a name there. The refusal where nothing is writable
// is go/image/check-image.mjs's (a read-only root filesystem).
func TestTheDriverUsesTheDirectorySet(t *testing.T) {
	if dir := os.Getenv("VARLATCH_TEST_TEMP"); dir != "" {
		if err := os.Setenv(envTempDir, dir); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if err := proveTemp(ctx, dir); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, tempProofCache); err != nil {
			t.Fatal(err)
		}
		rows, err := conn.QueryContext(ctx, tempProof)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		if !rows.Next() {
			t.Fatal(rows.Err())
		}
		// The open temporary file: /proc says where it is.
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			fmt.Println("no /proc")
			return
		}
		for _, fd := range fds {
			if to, err := os.Readlink("/proc/self/fd/" + fd.Name()); err == nil && strings.HasPrefix(to, dir+"/") {
				fmt.Println("used", strings.HasSuffix(to, " (deleted)"))
			}
		}
		if left, err := os.ReadDir(dir); err != nil || len(left) != 0 {
			t.Errorf("left behind: %v, %v", left, err)
		}
		return
	}
	child := func(dir string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTheDriverUsesTheDirectorySet$", "-test.v")
		cmd.Env = append(os.Environ(), "VARLATCH_TEST_TEMP="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return string(out)
	}
	if out := child(t.TempDir()); !strings.Contains(out, "used true") && !strings.Contains(out, "no /proc") {
		t.Errorf("no temporary file in the directory:\n%s", out)
	}
}
