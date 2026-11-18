// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInitRefusesServerCredentials: varlatch.toml is committed, so init
// refuses a server URL with a user name or password, from any source (the
// flag, VARLATCH_SERVER, the default server, the only stored credential),
// with exit 64, writes nothing (neither varlatch.toml nor the agent files),
// and does not repeat the URL. A URL without them is written as before.
func TestInitRefusesServerCredentials(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const refusal = "varlatch init: a server URL with a user name or password can't be written to varlatch.toml, so nothing was written; give the server without them (--server <url>)\n"
	cases := []struct {
		name   string
		args   []string
		env    map[string]string
		config map[string]string
		ok     bool
	}{
		{name: "flag", args: []string{"--server", "https://u:PW@host.example"}},
		{name: "flag, user name only", args: []string{"--server", "https://u@host.example"}},
		{name: "flag, a user name that looks like a mask", args: []string{"--server", "https://[redacted]@host.example"}},
		{name: "flag, a password only", args: []string{"--server", "https://:PW@host.example"}},
		{name: "flag, encoded", args: []string{"--server", "https://u%40x:PW%3A@host.example/base"}},
		{name: "flag, backslashes", args: []string{"--server", `https:\\u:PW@host.example`}},
		{name: "flag, other scheme", args: []string{"--server", "varlatch+https://u:PW@host.example"}},
		{name: "VARLATCH_SERVER", env: map[string]string{"VARLATCH_SERVER": "https://u:PW@var.example"}},
		{name: "the default server", config: map[string]string{"settings.json": `{"defaultServer": "https://u:PW@default.example"}` + "\n"}},
		{name: "the only credential", config: map[string]string{"credentials.json": `{"servers": {"https://u:PW@only.example": {"token": "vlt_cli_fakeAAAA"}}}` + "\n"}},
		{name: "control: no user name or password", args: []string{"--server", "https://host.example/a@b"}, ok: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			project, config := filepath.Join(dir, "project"), filepath.Join(dir, "config")
			for _, d := range []string{project, config, filepath.Join(dir, "home")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for name, content := range c.config {
				if err := os.WriteFile(filepath.Join(config, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(exe, append([]string{"init", "--org", "acme", "--project", "web"}, c.args...)...)
			cmd.Dir = project
			cmd.Env = []string{asCLI + "=1", "PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(dir, "home"), "VARLATCH_CONFIG_DIR=" + config}
			for k, v := range c.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if exit, isExit := err.(*exec.ExitError); isExit {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			entries, _ := os.ReadDir(project)
			if c.ok {
				if code != 0 || len(entries) == 0 {
					t.Fatalf("exit %d, %d entries; stderr %q", code, len(entries), stderr.String())
				}
				return
			}
			if code != 64 || stdout.String() != "" || stderr.String() != refusal {
				t.Errorf("exit %d, stdout %q, stderr %q; want 64 and the refusal", code, stdout.String(), stderr.String())
			}
			if len(entries) != 0 {
				t.Errorf("%d entries written into the project", len(entries))
			}
		})
	}
}
