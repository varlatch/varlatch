// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate/fakerelease"
	"github.com/varlatch/varlatch/go/lib/release"
)

// `varlatch upgrade --check` records the verified target (ADR-0065
// Decision 3): after discovery, the newer release's signed SHA256SUMS, its
// release.json and varlatchd-image.txt verified as an upgrade would, and
// what they declare recorded through `varlatchd admin release-check
// record-target`; a release that does not verify is recorded as such and
// said, without failing the check. Run with a stand-in varlatchd that only
// says its version and keeps the admin commands it is given.
func TestUpgradeCheckRecordsTheVerifiedTarget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("varlatch upgrade runs on a Go installation's Linux host")
	}
	srv := fakerelease.New()
	defer srv.Close()
	defer func(f func(*Run) selfupdate.Source) { selfUpdateSource = f }(selfUpdateSource)
	selfUpdateSource = func(*Run) selfupdate.Source { return srv.Source() }

	dir := t.TempDir()
	bin, log := filepath.Join(dir, "bin"), filepath.Join(dir, "admin.log")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	standIn := func(targetStatus int) {
		script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo varlatchd 0.51.0; exit 0; fi\nprintf '%s\\n' \"$*\" >> " + log + "\n"
		if targetStatus != 0 {
			script += "case \"$3\" in record-target) echo 'Usage: varlatchd admin release-check record ...' >&2; exit 64;; esac\n"
		}
		if err := os.WriteFile(filepath.Join(bin, "varlatchd"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(log)
	}
	image := "ghcr.io/varlatch/varlatchd:0.52.0@sha256:" + strings.Repeat("0123456789abcdef", 4)
	publish := func(files map[string][]byte, r *fakerelease.Release) {
		m, err := release.NewManifest("0.52.0", release.Declaration{SchemaVersion: 8, CompatibleFrom: 7, RollbackSafe: true, Previous: &release.Previous{Version: "0.51.1", SchemaVersion: 7}, ReversibleTo: &reversible})
		if err != nil {
			t.Fatal(err)
		}
		manifest, _ := m.Bytes()
		r.Files = map[string][]byte{release.ManifestAsset: manifest, targetImageAsset: []byte(image + "\n")}
		for k, v := range files {
			r.Files[k] = v
		}
		srv.Publish("0.52.0", r)
	}
	admin := func() []string {
		b, _ := os.ReadFile(log)
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	conf := filepath.Join(dir, "varlatchd.conf")

	// Verified: discovery, then the target, exactly as declared.
	standIn(0)
	publish(nil, &fakerelease.Release{})
	code, out, errs := runUpgrade(t, MapEnv{"PATH": bin}, "--check", "--config", conf)
	if code != ExitOK || !strings.Contains(out, "varlatchd 0.52.0 is available (this host runs 0.51.0)") || errs != "" {
		t.Fatalf("--check: %d %q %q", code, out, errs)
	}
	got := admin()
	want := "admin release-check record-target --version 0.52.0 --schema-version 8 --compatible-from 7 --rollback-safe true --previous 0.51.1 --previous-schema 7 --ends-rollback-window false --image " + image + " --config " + conf
	if len(got) != 2 || !strings.HasPrefix(got[0], "admin release-check record --repo varlatch/varlatch --version 0.52.0") || got[1] != want {
		t.Fatalf("the admin commands:\n%s", strings.Join(got, "\n"))
	}

	// A signature that does not verify: recorded as not-verified, said on
	// stderr, and the check still answers.
	standIn(0)
	publish(nil, &fakerelease.Release{SumsAfterSigning: func(b []byte) []byte { return append(b, '\n') }})
	code, out, errs = runUpgrade(t, MapEnv{"PATH": bin}, "--check", "--config", conf)
	if code != ExitOK || !strings.Contains(out, "0.52.0 is available") || !strings.Contains(errs, "0.52.0 could not be verified as an upgrade would verify it") {
		t.Fatalf("not verified: %d %q %q", code, out, errs)
	}
	if got := admin(); len(got) != 2 || got[1] != "admin release-check record-target --version 0.52.0 --failed not-verified --config "+conf {
		t.Fatalf("the admin commands, not verified:\n%s", strings.Join(got, "\n"))
	}

	// A release without varlatchd-image.txt in its SHA256SUMS: not-found.
	standIn(0)
	r := &fakerelease.Release{}
	publish(nil, r)
	delete(r.Files, targetImageAsset)
	code, _, errs = runUpgrade(t, MapEnv{"PATH": bin}, "--check", "--config", conf)
	if got := admin(); code != ExitOK || len(got) != 2 || got[1] != "admin release-check record-target --version 0.52.0 --failed not-found --config "+conf || !strings.Contains(errs, "does not list "+targetImageAsset) {
		t.Fatalf("no image record: %d %q\n%s", code, errs, strings.Join(got, "\n"))
	}

	// A varlatchd that does not know record-target: discovery is
	// recorded, the target is not, and the check says so.
	standIn(64)
	publish(nil, &fakerelease.Release{})
	code, out, errs = runUpgrade(t, MapEnv{"PATH": bin}, "--check", "--config", conf)
	if code != ExitOK || !strings.Contains(out, "0.52.0 is available") || !strings.Contains(errs, "the verified release is not recorded for the dashboard") {
		t.Fatalf("an older varlatchd: %d %q %q", code, out, errs)
	}

	// Nothing newer: no target is looked at.
	standIn(0)
	srv = fakerelease.New()
	defer srv.Close()
	m, _ := release.NewManifest("0.51.0", release.Declaration{SchemaVersion: 7, CompatibleFrom: 7, Previous: &release.Previous{Version: "0.50.2", SchemaVersion: 6}, ReversibleTo: &reversible})
	manifest, _ := m.Bytes()
	srv.Publish("0.51.0", &fakerelease.Release{Files: map[string][]byte{release.ManifestAsset: manifest}})
	code, out, errs = runUpgrade(t, MapEnv{"PATH": bin}, "--check", "--config", conf)
	if got := admin(); code != ExitOK || !strings.Contains(out, "is up to date") || len(got) != 1 || strings.Contains(got[0], "record-target") {
		t.Fatalf("up to date: %d %q %q\n%s", code, out, errs, strings.Join(got, "\n"))
	}
}
