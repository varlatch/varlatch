// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command unitprobe checks, from inside varlatchd.service's sandbox, that
// the sandbox lets varlatchd do what it needs and nothing it should not.
// go/install/test-unit.sh runs it as the ExecStart of a renamed copy of the
// unit (CI, as root, on a disposable runner); it exits 0 only if every
// check passes. The denials are checked against fixtures the service user
// could otherwise change or read, and must fail for the sandbox's reason.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
	"github.com/varlatch/varlatch/go/lib/storage"
)

func main() {
	stateDir := flag.String("state-dir", "", "the unit's StateDirectory")
	keyFile := flag.String("key-file", "", "the Root KEK file on disk (root-only)")
	roFiles := flag.String("ro-files", "", "comma-separated files owned by the service user under protected mounts")
	homeFile := flag.String("home-file", "", "a world-readable file under /home")
	flag.Parse()
	if *stateDir == "" || *keyFile == "" || *roFiles == "" || *homeFile == "" {
		fmt.Println("FAIL usage: every flag is required")
		os.Exit(2)
	}

	failed := false
	check := func(name string, err error) {
		if err != nil {
			failed = true
			fmt.Printf("FAIL %s: %v\n", name, err)
			return
		}
		fmt.Printf("ok   %s\n", name)
	}
	// refused passes only if err is one of the expected errnos.
	refused := func(name string, err error, want ...syscall.Errno) {
		for _, w := range want {
			if errors.Is(err, w) {
				fmt.Printf("ok   %s (refused: %v)\n", name, err)
				return
			}
		}
		check(name, fmt.Errorf("want %v, got %v", want, err))
	}

	creds := os.Getenv("CREDENTIALS_DIRECTORY")
	for _, c := range []string{"root-kek", "backup-key"} {
		b, err := os.ReadFile(filepath.Join(creds, c))
		if err == nil && len(b) == 0 {
			err = errors.New("empty")
		}
		check("reads its credential "+c, err)
	}
	_, err := os.ReadFile(*keyFile)
	refused("cannot read the key file itself", err, syscall.EACCES)
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		check("does not run as root", errors.New("uid 0"))
	} else {
		check("does not run as root", nil)
	}

	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(*stateDir, "probe.db")})
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
		snap := filepath.Join(*stateDir, fmt.Sprintf("probe-%d.snap", time.Now().UnixNano()))
		_, err = db.Snapshot(ctx, snap, storage.SnapshotOptions{StepPages: 1 << 20})
		check("takes a snapshot in the state directory", err)
		_ = os.Remove(snap)
		check("closes the database", db.Close())
	}
	// Too few samples on a slow runner disk is no sandbox problem; any
	// other error (a refused fdatasync, say) is.
	_, err = diskprobe.Run(ctx, diskprobe.Options{Dir: *stateDir, Duration: 2 * time.Second, Interval: time.Millisecond})
	if err != nil && strings.Contains(err.Error(), "samples") {
		err = nil
	}
	check("runs the fsync probe in the state directory", err)

	ln, err := net.Listen("tcp", ":443")
	check("binds port 443", err)
	if ln != nil {
		_ = ln.Close()
	}
	udp, err := net.ListenPacket("udp", ":0")
	check("opens a UDP socket (tailnet, STUN)", err)
	if udp != nil {
		_ = udp.Close()
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	check("opens a netlink route socket", err)
	if err == nil {
		_ = syscall.Close(fd)
	}
	_, err = os.ReadFile("/proc/net/route")
	check("reads /proc/net/route", err)
	_, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	refused("cannot open packet sockets", err, syscall.EAFNOSUPPORT)

	// Files the service user owns, outside its state directory: only
	// ProtectSystem=strict stops it from changing them.
	for _, f := range strings.Split(*roFiles, ",") {
		err := os.WriteFile(f, []byte("changed"), 0o600)
		refused("cannot change its own file "+f, err, syscall.EROFS)
	}

	// A file anyone may read under /home: only ProtectHome hides it.
	_, err = os.ReadFile(*homeFile)
	refused("cannot read "+*homeFile, err, syscall.ENOENT, syscall.EACCES)
	if entries, err := os.ReadDir("/home"); err == nil && len(entries) > 0 {
		check("sees nothing in /home", fmt.Errorf("%d entries", len(entries)))
	} else if err != nil && !errors.Is(err, fs.ErrPermission) {
		check("sees nothing in /home", err)
	} else {
		check("sees nothing in /home", nil)
	}

	if failed {
		os.Exit(1)
	}
	fmt.Println("all checks passed")
}
