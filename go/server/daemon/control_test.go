// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/write"
)

func runAdmin(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := admin(args, strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

var (
	enrollURL      = regexp.MustCompile(`^Open this one-time enrollment URL in your browser to create\nthe first Installation Admin's passkey \(ADR-0006\):\n  http://localhost:\d+/enroll#\S+\nExpires: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\. If it lapses, run bootstrap again\.\n$`)
	bootstrapCLI   = regexp.MustCompile(`^Installation bootstrapped\.\nInstallation Admin identity: (idn_[a-z2-7]+)\nOne-time CLI credential \(store it now; it is not retrievable\):\n(vlt_\S+)\n$`)
	recoveryURL    = regexp.MustCompile(`^Open this one-time recovery URL to enroll a new passkey:\n  http://localhost:\d+/enroll#\S+\nExpires: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\.\n$`)
	recoveryCLI    = regexp.MustCompile(`^Recovery completed for (idn_[a-z2-7]+)\.\nOne-time CLI credential \(store it now; it is not retrievable\):\n(vlt_\S+)\n$`)
	refusalMessage = "a varlatchd holds the data directory"
)

// bootstrap and recover print what they printed before (the TypeScript
// admin CLI's lines), through the running daemon's socket and offline. A
// command that succeeds while the daemon runs went through the socket: the
// daemon holds the lock, so the offline route would have refused.
func TestAdminThroughTheDaemonAndOffline(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	sock := filepath.Join(in.data, ControlSocket)
	if st, err := os.Stat(sock); err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("the control socket: %v %v", st, err)
	}
	code, out, errOut := runAdmin(t, "bootstrap", "--config", in.conf)
	if code != ExitOK || !enrollURL.MatchString(out) {
		t.Fatalf("bootstrap through the daemon: %d %q %q", code, out, errOut)
	}
	code, out, errOut = runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap --cli-credential through the daemon: %d %q %q", code, out, errOut)
	}
	admin := m[1]
	if code, out, errOut = runAdmin(t, "recover", "--identity", admin, "--config", in.conf); code != ExitOK || !recoveryURL.MatchString(out) {
		t.Fatalf("recover through the daemon: %d %q %q", code, out, errOut)
	}
	if code, out, errOut = runAdmin(t, "recover", "--identity", admin, "--cli-credential", "--config", in.conf); code != ExitOK || recoveryCLI.FindStringSubmatch(out)[1] != admin {
		t.Fatalf("recover --cli-credential through the daemon: %d %q %q", code, out, errOut)
	}
	// A refusal comes back with its status and message.
	if code, _, errOut = runAdmin(t, "recover", "--identity", "idn_nobody", "--config", in.conf); code != ExitFailure || !strings.HasPrefix(errOut, "varlatchd admin recover: ") {
		t.Errorf("a refused recovery through the daemon: %d %q", code, errOut)
	}
	// A usage error never reaches the daemon.
	if code, _, errOut = runAdmin(t, "recover", "--config", in.conf); code != 64 || !strings.Contains(errOut, "Usage: varlatchd admin recover --identity <id> [--enable] | --new-admin") {
		t.Errorf("usage: %d %q", code, errOut)
	}
	r.stop(t)
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("the socket outlived the daemon: %v", err)
	}
	// Offline, under the lock.
	if code, out, errOut = runAdmin(t, "recover", "--identity", admin, "--config", in.conf); code != ExitOK || !recoveryURL.MatchString(out) {
		t.Fatalf("recover offline: %d %q %q", code, out, errOut)
	}
	if code, out, errOut = runAdmin(t, "recover", "--identity", admin, "--cli-credential", "--config", in.conf); code != ExitOK || recoveryCLI.FindStringSubmatch(out)[1] != admin {
		t.Fatalf("recover --cli-credential offline: %d %q %q", code, out, errOut)
	}
	// And the daemon starts again afterwards: the offline command let go.
	start(t, in).stop(t)
}

// Offline on a fresh data directory: bootstrap creates the installation as
// serve would, and prints the same lines.
func TestAdminOfflineBootstrap(t *testing.T) {
	in := newInstall(t, "")
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	if code != ExitOK || !bootstrapCLI.MatchString(out) {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	code, out, errOut = runAdmin(t, "bootstrap", "--config", in.conf)
	if code != ExitFailure || out != "" || !strings.HasPrefix(errOut, "varlatchd admin bootstrap: ") {
		t.Errorf("a second bootstrap: %d %q %q", code, out, errOut)
	}
}

// A writing command against a varlatchd that holds the lock but whose
// socket does not answer (here: the lock held, a dead socket file left)
// refuses and writes nothing.
func TestAdminRefusesWhenTheSocketDoesNotAnswer(t *testing.T) {
	in := newInstall(t, "")
	unlock, err := lockDataDir(in.data)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	// A socket file nobody listens on.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(in.data, ControlSocket), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	_ = ln.Close()
	for _, args := range [][]string{{"bootstrap"}, {"recover", "--new-admin", "--cli-credential"}} {
		code, out, errOut := runAdmin(t, append(args, "--config", in.conf)...)
		if code != ExitFailure || out != "" || !strings.Contains(errOut, refusalMessage) || !strings.Contains(errOut, "nothing was written") {
			t.Errorf("%v: %d %q %q", args, code, out, errOut)
		}
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Errorf("the database was touched: %v", err)
	}
}

// serve refuses to start while an offline command (or another serve)
// holds the lock, so the two never both write; it starts once it is free.
func TestServeRefusesWhileTheLockIsHeld(t *testing.T) {
	in := newInstall(t, "")
	unlock, err := lockDataDir(in.data)
	if err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr}); code != ExitFailure || !strings.Contains(stderr.String(), "holds this data directory's lock") {
		t.Fatalf("%d %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Errorf("the database was touched: %v", err)
	}
	unlock()
	r := start(t, in)
	// A second serve on the same data directory refuses too.
	stderr = syncBuffer{}
	if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr}); code != ExitFailure || !strings.Contains(stderr.String(), "holds this data directory's lock") {
		t.Errorf("a second serve: %d %s", code, stderr.String())
	}
	// And an offline command cannot take it from the running daemon.
	if _, err := lockDataDir(in.data); err != errLocked {
		t.Errorf("the lock while serving: %v", err)
	}
	r.stop(t)
}

// The control socket accepts its own user and root only.
func TestControlPeers(t *testing.T) {
	if !peerAllowed(os.Getuid()) || !peerAllowed(0) || peerAllowed(os.Getuid()+1) && os.Getuid() != 0 {
		t.Error("peerAllowed")
	}
	in := newInstall(t, "")
	r := start(t, in)
	defer r.stop(t)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(in.data, ControlSocket), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, ok := peerUID(conn)
	if !ok || uid != os.Getuid() {
		t.Errorf("peerUID %d %v", uid, ok)
	}
}

// A data directory whose socket path a Unix socket cannot hold: serve
// refuses to start with a message that says so.
func TestServeRefusesASocketPathTooLong(t *testing.T) {
	in := newInstall(t, "")
	long := filepath.Join(in.dir, strings.Repeat("d", 120))
	if err := os.Mkdir(long, 0o700); err != nil {
		t.Fatal(err)
	}
	in.data = long
	in.write(t, "")
	var stderr syncBuffer
	if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr}); code != ExitFailure || !strings.Contains(stderr.String(), "shorter path") {
		t.Errorf("%d %s", code, stderr.String())
	}
}

// Shutdown never lets a handler start after close returned (the database
// closes then): connections accepted while the listener closes are either
// handled before close returns or never handled.
func TestControlShutdownWithConcurrentAccepts(t *testing.T) {
	in := newInstall(t, "")
	cfg, err := config.Load(in.conf)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i := range 40 {
		var closed atomic.Bool
		var late atomic.Int32
		c, err := listenControl(&hostEnv{cfg: cfg}, log)
		if err != nil {
			t.Fatal(err)
		}
		c.handled = func() {
			if closed.Load() {
				late.Add(1)
			}
		}
		go c.serve(context.Background())
		stop := make(chan struct{})
		var dialers sync.WaitGroup
		for range 8 {
			dialers.Add(1)
			go func() {
				defer dialers.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if conn, err := net.Dial("unix", filepath.Join(in.data, ControlSocket)); err == nil {
						_ = conn.Close()
					}
				}
			}()
		}
		time.Sleep(time.Duration(i%5) * time.Millisecond)
		c.close()
		closed.Store(true)
		time.Sleep(5 * time.Millisecond)
		close(stop)
		dialers.Wait()
		if late.Load() != 0 {
			t.Fatalf("iteration %d: %d handlers started after close returned", i, late.Load())
		}
	}
}

// serve refuses (78) a data directory its group or others may write, or
// that another user owns; varlatchd admin refuses to connect through one,
// or through a socket file that is not the owner's socket.
func TestDataDirectoryOwnership(t *testing.T) {
	in := newInstall(t, "")
	if err := os.Chmod(in.data, 0o770); err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr}); code != ExitConfig || !strings.Contains(stderr.String(), "may be written by its group or by others") {
		t.Errorf("group-writable: %d %s", code, stderr.String())
	}
	if code, _, errOut := runAdmin(t, "bootstrap", "--config", in.conf); code != ExitConfig || !strings.Contains(errOut, "may be written by its group or by others") {
		t.Errorf("admin, group-writable: %d %s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Errorf("the database was touched: %v", err)
	}
	if err := os.Chmod(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	// Owned by someone else (as seen by a check for another uid).
	if _, err := checkServeDir(in.data, os.Getuid()+1); err == nil || !strings.Contains(err.Error(), "uid") {
		t.Errorf("another owner: %v", err)
	}
	if os.Getuid() != 0 {
		if _, _, err := checkClientDir(in.data, os.Getuid()+1); err == nil || !strings.Contains(err.Error(), "not by you") {
			t.Errorf("admin, another owner: %v", err)
		}
	}
	// A link where the socket should be.
	if err := os.Symlink(filepath.Join(in.dir, "elsewhere.sock"), filepath.Join(in.data, ControlSocket)); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "bootstrap", "--config", in.conf); code != ExitConfig || !strings.Contains(errOut, "is not a socket owned by the data directory's owner") {
		t.Errorf("admin, a link: %d %s", code, errOut)
	}
}

// recover takes its subject's gate from the gate set it runs with: with
// --enable exclusively, so it waits while an effect holds the person
// (shared) across its call, and commits once the effect ends; without
// --enable shared, alongside the effect.
func TestRecoverTakesItsSubjectsGate(t *testing.T) {
	in := newInstall(t, "")
	cfg, err := config.Load(in.conf)
	if err != nil {
		t.Fatal(err)
	}
	env, status := openOffline(cfg, "test", io.Discard)
	if env == nil {
		t.Fatalf("open: %d", status)
	}
	defer env.store.Close()
	ctx := context.Background()
	host := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := runHost(ctx, env, args, nil, &out, &errOut)
		return code, out.String() + errOut.String()
	}
	code, out := host("bootstrap", "--cli-credential")
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %s", code, out)
	}
	admin := m[1]
	if err := env.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_r', 'r', 'R', '{}')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	waiting := make(chan write.Gate, 4)
	env.gates.Observe(func(event string, g write.Gate) {
		if event == "waiting" {
			waiting <- g
		}
	})
	started, release := make(chan struct{}), make(chan struct{})
	effectDone := make(chan error, 1)
	w := &write.Writer{Store: env.store, Gates: env.gates}
	go func() {
		_, _, err := write.RunEffect(ctx, w, write.Effect[string, string]{
			OrganizationID: "org_r", People: []write.Gate{write.Person(admin, write.Shared)},
			Call:  func(context.Context) (string, error) { close(started); <-release; return "ok", nil },
			Final: func(context.Context, *storage.Tx, string) (string, error) { return "ok", nil },
		})
		effectDone <- err
	}()
	<-started
	// Without --enable: alongside the effect.
	if code, out := host("recover", "--identity", admin); code != ExitOK || !recoveryURL.MatchString(out) {
		t.Fatalf("recover: %d %s", code, out)
	}
	// With --enable: waits for the effect.
	recovered := make(chan string, 1)
	go func() {
		code, out := host("recover", "--identity", admin, "--enable")
		recovered <- fmt.Sprint(code, " ", out)
	}()
	select {
	case g := <-waiting:
		if g != write.Person(admin, write.Exclusive) {
			t.Fatalf("waiting for %s", g)
		}
	case r := <-recovered:
		t.Fatalf("recover --enable did not wait: %s", r)
	case <-time.After(10 * time.Second):
		t.Fatal("recover --enable never reached its gate")
	}
	select {
	case r := <-recovered:
		t.Fatalf("recover --enable ran during the effect: %s", r)
	default:
	}
	close(release)
	if err := <-effectDone; err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-recovered:
		if !strings.HasPrefix(r, "0 ") || !recoveryURL.MatchString(strings.TrimPrefix(r, "0 ")) {
			t.Fatalf("recover --enable after the effect: %s", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recover --enable did not finish after the effect")
	}
}

// The data directory's path must lead to the same directory for as long as
// varlatchd uses it: a symbolic link as the last component, or an ancestor
// someone else may replace entries of (0777 without the sticky bit), is
// refused by serve (78) and by varlatchd admin; a sticky world-writable
// ancestor (/tmp) is not. A directory swapped under the path after the
// check is caught by the identity check serve repeats after the lock and
// the socket.
func TestDataDirectoryPath(t *testing.T) {
	in := newInstall(t, "")
	serveRefuses := func(want string) {
		t.Helper()
		var stderr syncBuffer
		if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr}); code != ExitConfig || !strings.Contains(stderr.String(), want) {
			t.Errorf("serve: %d %s", code, stderr.String())
		}
		if code, _, errOut := runAdmin(t, "bootstrap", "--config", in.conf); code != ExitConfig || !strings.Contains(errOut, want) {
			t.Errorf("admin: %d %s", code, errOut)
		}
	}
	real := in.data

	// A link as the last component.
	link := filepath.Join(in.dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	in.data = link
	in.write(t, "")
	serveRefuses("is a symbolic link")

	// An ancestor anyone may write, without the sticky bit.
	open := filepath.Join(in.dir, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	in.data = filepath.Join(open, "data")
	if err := os.Mkdir(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	in.write(t, "")
	serveRefuses("without the sticky bit")
	// The same reached through a link in a trusted ancestor: the resolved
	// path is checked too.
	via := filepath.Join(in.dir, "via")
	if err := os.Symlink(open, via); err != nil {
		t.Fatal(err)
	}
	in.data = filepath.Join(via, "data")
	in.write(t, "")
	serveRefuses("without the sticky bit")
	// With the sticky bit, as /tmp has, it is trusted.
	if err := os.Chmod(open, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := checkServeDir(filepath.Join(open, "data"), os.Getuid()); err != nil {
		t.Errorf("a sticky ancestor: %v", err)
	}

	// A directory swapped under the path after the check.
	id, err := checkServeDir(real, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := sameDir(real, id); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(real, real+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sameDir(real, id); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("swapped: %v", err)
	}

	// The client accepts the directory's owner or root on the socket.
	if !serverPeerAllowed(1000, 1000) || !serverPeerAllowed(0, 1000) || serverPeerAllowed(1001, 1000) {
		t.Error("serverPeerAllowed")
	}
}

// The resolution checks every link it follows and every directory it
// passes through, at every hop. A test cannot create another user's files,
// so ownerOf stands in: entries named here belong to uid 4242, "attacker".
//   - an attacker's link in a sticky directory, pointing at a trusted
//     directory, is refused (its owner could replace it later);
//   - a trusted alias whose target passes through a directory the attacker
//     owns (the jump in it could be replaced) is refused;
//   - a chain of trusted links, relative and absolute, passes.
func TestDataDirectoryLinkHops(t *testing.T) {
	base := t.TempDir()
	mkdir := func(p string, mode os.FileMode) string {
		t.Helper()
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, at string) string {
		t.Helper()
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	trusted := mkdir(filepath.Join(base, "trusted"), 0o755)
	mkdir(filepath.Join(trusted, "data"), 0o700)
	sticky := mkdir(filepath.Join(base, "sticky"), os.ModeSticky|0o777)
	attacker := mkdir(filepath.Join(base, "attacker"), 0o755)
	attackerLink := link(trusted, filepath.Join(sticky, "link"))
	jump := link(trusted, filepath.Join(attacker, "jump"))
	alias := link(jump, filepath.Join(base, "alias"))

	owned := map[string]bool{attackerLink: true, attacker: true, jump: true}
	defer func(f func(string, fs.FileInfo) uint32) { ownerOf = f }(ownerOf)
	ownerOf = func(p string, fi fs.FileInfo) uint32 {
		if owned[p] {
			return 4242
		}
		return fi.Sys().(*syscall.Stat_t).Uid
	}
	uid := os.Getuid()
	for _, c := range []struct{ path, want string }{
		{filepath.Join(attackerLink, "data"), "the link " + attackerLink + ", on its path, is owned by uid 4242"},
		{filepath.Join(alias, "data"), attacker + ", on its path, is owned by uid 4242"},
	} {
		if _, err := checkServeDir(c.path, uid); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("serve, %s: %v", c.path, err)
		}
		if _, _, err := checkClientDir(c.path, uid); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("admin, %s: %v", c.path, err)
		}
	}

	// Trusted links, a relative one through "..", then an absolute one.
	hops := mkdir(filepath.Join(base, "hops"), 0o755)
	rel := link("../trusted", filepath.Join(hops, "rel"))
	abs := link(rel, filepath.Join(base, "abs"))
	for _, p := range []string{filepath.Join(rel, "data"), filepath.Join(abs, "data"), filepath.Join(trusted, "data")} {
		if _, err := checkServeDir(p, uid); err != nil {
			t.Errorf("a trusted chain, %s: %v", p, err)
		}
	}
	// A loop is refused, not followed for ever (by the kernel or by the
	// resolution's own bound).
	loop := link(filepath.Join(base, "loop"), filepath.Join(base, "loop"))
	if _, err := checkServeDir(filepath.Join(loop, "data"), uid); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Errorf("a loop: %v", err)
	}
}

// The resolution's own bound, for a chain the kernel would also refuse
// once it reaches the last component: 41 trusted links in a row.
func TestDataDirectoryLinkBound(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	prev := filepath.Join(base, "d")
	for i := range maxLinks + 1 {
		at := filepath.Join(base, fmt.Sprintf("l%d", i))
		if err := os.Symlink(prev, at); err != nil {
			t.Fatal(err)
		}
		prev = at
	}
	if _, err := resolveTrusted(prev, func(uint32) bool { return true }); err == nil || !strings.Contains(err.Error(), "more than 40 symbolic links") {
		t.Errorf("%v", err)
	}
}
