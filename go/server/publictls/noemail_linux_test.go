// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package publictls

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// noEmailHelper is the variable that makes TestNoEmailHelper run: in a
// process of its own, since certmagic keeps the first email address it
// saw in a package variable, which another test of this process sets.
const noEmailHelper = "VARLATCH_TEST_NO_EMAIL_HELPER"

// TestPebbleWithoutEmailAsksNothing: without acme_email (#323 review P3),
// a certificate is obtained with an account that has no contact, and
// nothing is read from stdin or written to stdout: certmagic's prompt
// for an email address never runs. The log says once that there is no
// contact.
func TestPebbleWithoutEmailAsksNothing(t *testing.T) {
	pebble(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestNoEmailHelper$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), noEmailHelper+"=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil || !strings.Contains(out.String(), "--- PASS: TestNoEmailHelper") {
		t.Fatalf("the helper: %v\n%s", err, out.String())
	}
}

// TestNoEmailHelper is not a test by itself: TestPebbleWithoutEmailAsksNothing
// runs it as a process of its own.
func TestNoEmailHelper(t *testing.T) {
	if os.Getenv(noEmailHelper) == "" {
		t.Skip("run by TestPebbleWithoutEmailAsksNothing")
	}
	// stdin (fd 0, which certmagic reads its answers from) is a pipe
	// holding one line; it must still be there at the end.
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	const sentinel = "sentinel@varlatch.test\n"
	if _, err := inW.WriteString(sentinel); err != nil {
		t.Fatal(err)
	}
	saved, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup3(int(inR.Fd()), 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Dup3(saved, 0, 0); _ = unix.Close(saved) }()
	// stdout (where certmagic would print its question) is a pipe.
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = outW
	printed := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(outR); printed <- b }()

	s := startPebbleAs(t, "", "noemail.varlatch.test", t.TempDir(), true, true, []time.Duration{time.Second})
	waitFor(t, "a certificate without an email address", 30*time.Second, s.m.HasCertificate)

	os.Stdout = stdout
	_ = outW.Close()
	if b := <-printed; len(b) != 0 {
		t.Errorf("written to stdout: %q", b)
	}
	_ = inW.Close()
	left, _ := io.ReadAll(inR)
	if string(left) != sentinel {
		t.Errorf("stdin was read: %q left of %q", left, sentinel)
	}
	if n := strings.Count(s.log.String(), "acme_email is not set"); n != 1 {
		t.Errorf("the missing contact is logged %d times:\n%s", n, s.log.String())
	}
}
