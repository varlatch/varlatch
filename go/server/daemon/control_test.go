// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
