// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/values/valuestest"
)

// G3 at the database level for the Root KEK canary: varlatchd opens the
// canary of an installation row the TypeScript server wrote (v0.21.0's
// crypto code and v0.22.0's), and one Go wrote, at startup, with the
// installation's Root KEK, and serves; any other key is refused with exit
// 78, as the TypeScript server refuses it. (The read path's parity tests
// open the same rows again through /readyz, and the TypeScript server
// opens the Go-written canary in go-values-fixture.test.ts.)
func TestCanaryFromFixtures(t *testing.T) {
	goSealed := func(f *valuestest.Fixture) {
		kek, _ := hex.DecodeString(f.RootKEK)
		for _, inst := range f.Rows["installation"] {
			c, err := envelope.NewCanary(kek, inst["id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(c)
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			inst["kek_canary"] = v
		}
	}
	for _, c := range []struct {
		name, file string
		reseal     func(*valuestest.Fixture)
	}{
		{"sealed by v0.21.0", "values-v0.21.0.json", nil},
		{"sealed by v0.22.0", "values-v0.22.0.json", nil},
		{"sealed by Go", "values-v0.22.0.json", goSealed},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := valuestest.Read(valuestest.Path(c.file))
			if err != nil {
				t.Fatal(err)
			}
			if c.reseal != nil {
				c.reseal(&f)
			}
			in := newInstall(t, "")
			if err := os.WriteFile(in.kekFile, []byte(f.RootKEK+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := valuestest.Prepare(filepath.Join(in.data, config.DatabaseFile), f); err != nil {
				t.Fatal(err)
			}
			r := start(t, in)
			var ready readiness
			if code := getJSON(t, "http://"+r.addr+"/readyz", &ready); code != 200 || !ready.Checks.KEK || !ready.Checks.Installation {
				t.Errorf("/readyz %d %+v", code, ready)
			}
			if strings.Contains(r.stderr.String(), "installation initialized") {
				t.Error("varlatchd made a new installation instead of reading the fixture's")
			}
			r.stop(t)

			// Another Root KEK does not open the canary: refused, exit 78.
			if err := os.WriteFile(in.kekFile, []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			if code := Serve(Options{ConfigPath: in.conf, Stderr: &stderr, Signals: make(chan os.Signal)}); code != ExitConfig || !strings.Contains(stderr.String(), "does not open this installation's canary") {
				t.Errorf("a wrong Root KEK: exit %d: %s", code, stderr.String())
			}
		})
	}
}

// readiness is /readyz's answer.
type readiness struct {
	Ready  bool `json:"ready"`
	Checks struct {
		Schema, KEK, Installation bool
	} `json:"checks"`
}
