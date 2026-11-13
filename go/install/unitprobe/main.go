// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command unitprobe checks, from inside varlatchd.service's sandbox, that
// the sandbox lets varlatchd do what it needs and nothing it should not.
// go/install/test-unit.sh runs it as the unit's ExecStart (CI, as root, on
// a disposable runner); it exits 0 only if every check passes.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
	"github.com/varlatch/varlatch/go/lib/storage"
)

const stateDir = "/var/lib/varlatch"

func main() {
	failed := false
	check := func(name string, err error) {
		if err != nil {
			failed = true
			fmt.Printf("FAIL %s: %v\n", name, err)
			return
		}
		fmt.Printf("ok   %s\n", name)
	}
	mustFail := func(name string, err error) {
		if err == nil {
			check(name, errors.New("allowed, should be refused"))
			return
		}
		fmt.Printf("ok   %s (refused: %v)\n", name, err)
	}

	creds := os.Getenv("CREDENTIALS_DIRECTORY")
	for _, c := range []string{"root-kek", "backup-key"} {
		b, err := os.ReadFile(filepath.Join(creds, c))
		if err == nil && len(b) == 0 {
			err = errors.New("empty")
		}
		check("reads its credential "+c, err)
	}
	_, err := os.ReadFile("/etc/varlatch/root-kek")
	mustFail("cannot read /etc/varlatch/root-kek itself", err)
	if os.Getuid() == 0 {
		check("does not run as root", errors.New("uid 0"))
	}

	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(stateDir, "probe.db")})
	check("opens the database in the state directory", err)
	if err == nil {
		err = db.Write(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS t (x INTEGER) STRICT`)
			if err == nil {
				_, err = tx.ExecContext(ctx, `INSERT INTO t VALUES (1)`)
			}
			return err
		})
		check("commits a write (fsync)", err)
		snap := filepath.Join(stateDir, fmt.Sprintf("probe-%d.snap", time.Now().UnixNano()))
		_, err = db.Snapshot(ctx, snap, storage.SnapshotOptions{StepPages: 1 << 20})
		check("takes a snapshot", err)
		_ = os.Remove(snap)
		check("closes the database", db.Close())
	}
	// Too few samples on a slow runner disk is no sandbox problem; any
	// other error (a refused fdatasync, say) is.
	_, err = diskprobe.Run(ctx, diskprobe.Options{Dir: stateDir, Duration: 2 * time.Second, Interval: time.Millisecond})
	if err != nil && strings.Contains(err.Error(), "samples") {
		err = nil
	}
	check("runs the fsync probe", err)

	ln, err := net.Listen("tcp", ":443")
	check("binds port 443", err)
	if ln != nil {
		_ = ln.Close()
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	check("opens a netlink route socket", err)
	if err == nil {
		_ = syscall.Close(fd)
	}
	_, err = os.ReadFile("/proc/net/route")
	check("reads /proc/net/route", err)
	_, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	mustFail("cannot open packet sockets", err)

	mustFail("cannot write /etc", os.WriteFile("/etc/varlatch-probe", []byte("x"), 0o600))
	mustFail("cannot write /usr/local/bin", os.WriteFile("/usr/local/bin/varlatch-probe", []byte("x"), 0o600))
	if entries, err := os.ReadDir("/home"); err == nil && len(entries) > 0 {
		check("sees no home directories", fmt.Errorf("%d entries", len(entries)))
	} else {
		check("sees no home directories", nil)
	}

	if failed {
		os.Exit(1)
	}
	fmt.Println("all checks passed")
}
