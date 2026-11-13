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
	config := flag.String("config", "", "the configuration file the unit points at")
	roFiles := flag.String("ro-files", "", "comma-separated files owned by the service user under protected mounts")
	homeFile := flag.String("home-file", "", "a world-readable file under /home")
	flag.Parse()
	if *stateDir == "" || *keyFile == "" || *config == "" || *roFiles == "" || *homeFile == "" {
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
	// A permission check, not a sandbox one: the file is root's, mode 0600.
	_, err := os.ReadFile(*keyFile)
	refused("cannot read the key file itself (file permissions)", err, syscall.EACCES)
	_, err = os.ReadFile(*config)
	check("reads its configuration", err)
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		check("does not run as root", errors.New("uid 0"))
	} else {
		check("does not run as root", nil)
	}
	check("holds CAP_NET_BIND_SERVICE only, with no_new_privs", capabilities())
	check("cannot write a core dump (LimitCORE=0)", noCoreDumps())

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
	refused("cannot read "+*homeFile, err, syscall.EACCES)
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

// noCoreDumps checks the core file size limit is 0, soft and hard: a core
// dump would hold the Root KEK.
func noCoreDumps() error {
	b, err := os.ReadFile("/proc/self/limits")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Max core file size") {
			f := strings.Fields(strings.TrimPrefix(line, "Max core file size"))
			if len(f) >= 2 && f[0] == "0" && f[1] == "0" {
				return nil
			}
			return fmt.Errorf("limit is %q", strings.TrimSpace(line))
		}
	}
	return errors.New("no core file size limit in /proc/self/limits")
}

// capabilities checks the process holds exactly CAP_NET_BIND_SERVICE (bit
// 10) in every set, and that no_new_privs is on: binding port 443 alone
// would also pass where unprivileged ports start lower.
func capabilities() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	want := map[string]string{
		"CapEff:": "0000000000000400", "CapPrm:": "0000000000000400",
		"CapBnd:": "0000000000000400", "CapAmb:": "0000000000000400",
		"CapInh:": "0000000000000400", "NoNewPrivs:": "1",
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if w, ok := want[f[0]]; ok {
				if f[1] != w {
					return fmt.Errorf("%s %s, want %s", f[0], f[1], w)
				}
				delete(want, f[0])
			}
		}
	}
	if len(want) != 0 {
		return fmt.Errorf("missing from /proc/self/status: %v", want)
	}
	return nil
}
