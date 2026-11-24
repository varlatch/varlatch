// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestSetupRefusals: what `varlatch setup` refuses before it changes
// anything: a Compose installation (--dir, the TypeScript CLI's), the
// restore without its keys, unknown options, an answers file that is not one
// or disagrees with a flag, half of the keys' copies; and a run that is
// not root's, which it says before anything.
func TestSetupRefusals(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"ingress":"proxy","color":"blue"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	answers := filepath.Join(dir, "answers.json")
	if err := os.WriteFile(answers, []byte(`{"ingress":"proxy","publicUrl":"https://vault.example.com","backups":"host"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		code int
		has  string
	}{
		{[]string{"--dir", "/srv/varlatch"}, 64, "varlatch-ts setup --dir"},
		{[]string{"--restore", "/srv/a.vltbak"}, 64, "--restore needs your two keys"},
		{[]string{"--root-kek-file", "/root/k"}, 64, "give them with --restore"},
		{[]string{"--restore", "/srv/a.vltbak", "--root-kek-file", "/root/k", "--backup-key-file", "/root/b", "--root-kek-out", "/x", "--backup-key-out", "/y"}, 64, "it writes no copies"},
		{[]string{"--nope"}, 64, "unknown option --nope"},
		{[]string{"extra"}, 64, "unexpected argument extra"},
		{[]string{"--public-url"}, 64, "--public-url needs a value"},
		{[]string{"--answers", bad}, 64, "is not a JSON object of answers"},
		{[]string{"--answers", answers, "--ingress", "public"}, 64, "--ingress differs from the answers file"},
		{[]string{"--root-kek-out", "/tmp/k"}, 64, "go together"},
	} {
		code, out, errText := runSetupCLI(t, c.args...)
		if code != c.code || out != "" || !strings.Contains(errText, c.has) {
			t.Errorf("%v: %d %q %q", c.args, code, out, errText)
		}
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		code, out, errText := runSetupCLI(t, "--answers", answers)
		if code != ExitDenied || out != "" || !strings.Contains(errText, "run it as root: sudo varlatch setup") {
			t.Errorf("not root: %d %q %q", code, out, errText)
		}
	}
}

// TestSetupFlagValueForms: --name=value is --name value, split at the
// first "=", for every option that takes a value; the accepting switches
// take none; an empty attached value is refused as a missing one, and an
// unknown option's attached value is never echoed.
func TestSetupFlagValueForms(t *testing.T) {
	dir := t.TempDir()
	answers := filepath.Join(dir, "answers.json")
	if err := os.WriteFile(answers, []byte(`{"ingress":"proxy","publicUrl":"https://vault.example.com","backups":"host"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	spaced, err := parseSetupArgs([]string{"--answers", answers, "--trusted-proxies", "10.0.0.1,10.0.0.2", "--acme-ca", "https://ca.example/dir?a=b",
		"--root-kek-out", "/root/k", "--backup-key-out", "/root/b", "--accept-slow-disk", "--accept-existing-user",
		"--admin-link-out", "/root/link", "--admin-wait", "0s", "--attest"})
	if err != nil {
		t.Fatal(err)
	}
	attached, err := parseSetupArgs([]string{"--answers=" + answers, "--trusted-proxies=10.0.0.1,10.0.0.2", "--acme-ca=https://ca.example/dir?a=b",
		"--root-kek-out=/root/k", "--backup-key-out=/root/b", "--accept-slow-disk", "--accept-existing-user",
		"--admin-link-out=/root/link", "--admin-wait=0s", "--attest"})
	if err != nil {
		t.Fatal(err)
	}
	if def, err := parseSetupArgs(nil); err != nil || def.adminWait != 15*time.Minute {
		t.Errorf("the default wait: %v %v", def.adminWait, err)
	}
	if spaced != attached {
		t.Errorf("--name value gives %+v, --name=value %+v", spaced, attached)
	}
	if attached.given.ACMECA != "https://ca.example/dir?a=b" || attached.given.Ingress != "proxy" || !attached.acceptSlow || !attached.acceptUser ||
		attached.linkOut != "/root/link" || attached.adminWait != 0 || !attached.attest {
		t.Errorf("parsed %+v", attached)
	}
	for _, c := range []struct {
		args []string
		has  string
	}{
		{[]string{"--public-url="}, "--public-url needs a value"},
		{[]string{"--answers="}, "--answers needs a value"},
		{[]string{"--accept-slow-disk=yes"}, "--accept-slow-disk takes no value"},
		{[]string{"--accept-existing-user=true"}, "--accept-existing-user takes no value"},
		{[]string{"--attest=yes"}, "--attest takes no value"},
		{[]string{"--admin-wait", "-1s"}, "--admin-wait must be a duration"},
		{[]string{"--admin-wait=forever"}, "--admin-wait must be a duration"},
		{[]string{"--admin-link-out="}, "--admin-link-out needs a value"},
		{[]string{"--dir=/srv/varlatch"}, "varlatch-ts setup --dir"},
		{[]string{"--answers=" + answers, "--ingress=public"}, "--ingress differs from the answers file"},
		{[]string{"--root-kek-out=/root/k"}, "go together"},
	} {
		if _, err := parseSetupArgs(c.args); err == nil || !strings.Contains(err.Error(), c.has) {
			t.Errorf("%v: %v", c.args, err)
		}
	}
	code, out, errText := runSetupCLI(t, "--nope=blue")
	if code != 64 || out != "" || !strings.Contains(errText, "unknown option --nope=[redacted]") || strings.Contains(errText, "blue") {
		t.Errorf("an unknown option's value: %d %q %q", code, out, errText)
	}
}

// TestEnrollLinkShown: the first administrator's link is shown whole, from
// a bootstrap and from a recovery; nothing but its own token passes the
// fail-safe; a line that is no such link is not printed.
func TestEnrollLinkShown(t *testing.T) {
	show := func(link, expires string, held ...string) (string, error) {
		var stdout strings.Builder
		r := &Run{IO: IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &strings.Builder{}}, Env: MapEnv{}, Secrets: &Secrets{}, inFlight: held}
		err := r.showEnrollLink(link, expires)
		return stdout.String(), err
	}
	const tail = "AbCdEfGhIjKlMnOp-_0123456789"
	for _, link := range []string{
		"https://vault.example.com/enroll#vlt_setup_" + tail,
		"http://localhost:8686/enroll#vlt_recover_" + tail,
		"https://vault.example.com:8443/enroll#vlt_setup_" + tail,
	} {
		out, err := show(link, "2026-11-24T06:43:20.527Z")
		if err != nil || !strings.Contains(out, "\n  "+link+"\n") || strings.Contains(out, Redacted) || !strings.Contains(out, "expires 2026-11-24T06:43:20.527Z;") {
			t.Errorf("%s: %v %q", link, err, out)
		}
	}
	// Any other token stays redacted, and a value in flight.
	if out, err := show("https://vault.example.com/enroll#vlt_setup_"+tail, "vlt_cli_"+tail); err != nil || strings.Contains(out, "vlt_cli_") || !strings.Contains(out, "vlt_setup_"+tail) {
		t.Errorf("another token: %v %q", err, out)
	}
	if out, err := show("https://vault.example.com/enroll#vlt_setup_"+tail, "soon", tail); err != nil || strings.Contains(out, tail) {
		t.Errorf("a value in flight: %v %q", err, out)
	}
	for _, link := range []string{
		"", "https://vault.example.com/enroll#[redacted]", "https://vault.example.com/enroll#vlt_cli_" + tail,
		"https://vault.example.com/enroll#vlt_setup_" + tail + " vlt_cli_" + tail, "https://vault.example.com/other#vlt_setup_" + tail,
		"ftp://vault.example.com/enroll#vlt_setup_" + tail, "https://vault.example.com/enroll#vlt_setup_" + tail + "\x1b[2K",
	} {
		if out, err := show(link, "soon"); err == nil || out != "" {
			t.Errorf("%q: %v %q", link, err, out)
		}
	}
}

func runSetupCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := Main(append([]string{"setup"}, args...), MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir(), "PATH": t.TempDir()},
		IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}
