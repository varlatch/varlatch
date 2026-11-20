// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSetupRefusals: what `varlatch setup` refuses before it changes
// anything: a Compose installation (--dir, the TypeScript CLI's), the
// restore (slice 6.4c), unknown options, an answers file that is not one
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
		{[]string{"--restore", "a.vltbak"}, 64, "slice 6.4c"},
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

func runSetupCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := Main(append([]string{"setup"}, args...), MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir(), "PATH": t.TempDir()},
		IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}
