// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

func TestServerKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://Varlatch.Example.com:443/base//": "https://varlatch.example.com/base",
		"http://127.0.0.1:8080":                   "http://127.0.0.1:8080",
		"http://localhost:80/":                    "http://localhost",
		"https://h.example/a?x=1#y":               "https://h.example/a",
	} {
		if got, err := ServerKey(in); err != nil || got != want {
			t.Errorf("ServerKey(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	if _, err := ServerKey("not a url"); err == nil {
		t.Error("a value that is not a URL has a key")
	}
}

// TestPendingSignInsFile: entries by key, the file 0600 in a 0700
// directory, unknown keys kept, the file deleted with its last entry, and
// nothing read or written inside an agent-safe run.
func TestPendingSignInsFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	env := mapEnv{"VARLATCH_CONFIG_DIR": dir}
	entry := jsjson.Object{{Key: "server", Value: "https://h.example/"}, {Key: "deviceCode", Value: "dc_x"}, {Key: "future", Value: true}}
	if replaced, err := SavePendingSignIn(entry, env); err != nil || replaced != nil {
		t.Fatalf("%v, %v", replaced, err)
	}
	path := filepath.Join(dir, "pending-sign-ins.json")
	data, _ := os.ReadFile(path)
	if want := "{\n  \"servers\": {\n    \"https://h.example\": {\n      \"server\": \"https://h.example/\",\n      \"deviceCode\": \"dc_x\",\n      \"future\": true\n    }\n  }\n}\n"; string(data) != want {
		t.Errorf("file\n%s\nwant\n%s", data, want)
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{path: 0o600, dir: 0o700} {
			if info, _ := os.Stat(p); info.Mode().Perm() != want {
				t.Errorf("%s: mode %o, want %o", p, info.Mode().Perm(), want)
			}
		}
	}
	got, err := LoadPendingSignIn("https://H.example", env)
	if err != nil || jsjson.String(got.Value("deviceCode")) != "dc_x" {
		t.Fatalf("%v, %v", got, err)
	}
	if err := DeletePendingSignIn("https://h.example//", env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the file outlived its last entry: %v", err)
	}
	run := mapEnv{"VARLATCH_CONFIG_DIR": dir, "VARLATCH_AGENT_RUN": "run_1"}
	if _, err := SavePendingSignIn(entry, run); err == nil || !strings.Contains(err.Error(), "agent-safe run run_1") {
		t.Errorf("written inside an agent-safe run: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the file was written inside an agent-safe run")
	}
}
