// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate/fakerelease"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/upgrade"
	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

// `varlatch upgrade --from-request` end to end on a host in a temporary
// directory (ADR-0065 phase 2), as root (the helper's unit runs it so), the
// data directory the service user's: a request varlatchd wrote is taken
// into the root-only directory, the release is found and verified again,
// and the engine upgrades with its snapshot checked off the host. Here the
// host has no backup destination, so the request is refused before the
// stop and nothing changes (and, undone before the stop, the version may be
// asked for again); then --recover finds nothing to do. Root only: go.yml's
// Go container runs it.
func TestUpgradeFromARequestOnAHost(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("builds varlatchd and runs as root on Linux (go.yml's Go container)")
	}
	const from, to = "0.60.0", "0.61.0"
	srv := fakerelease.New()
	defer srv.Close()
	defer func(f func(*Run) selfupdate.Source) { selfUpdateSource = f }(selfUpdateSource)
	selfUpdateSource = func(*Run) selfupdate.Source { return srv.Source() }
	fromSchema := checkoutSchema(t)
	m, err := release.NewManifest(to, release.Declaration{SchemaVersion: fromSchema + 1, CompatibleFrom: 1, RollbackSafe: true,
		Previous: &release.Previous{Version: from, SchemaVersion: fromSchema}, ReversibleTo: &reversible})
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := m.Bytes()
	cli, server, name := upgrade.Assets(to, runtime.GOARCH)
	srv.Publish(to, &fakerelease.Release{Files: map[string][]byte{cli: []byte("#!/bin/sh\necho varlatch " + to + "\n"), server: cliBuild(t, to, "g6fixture"), name: manifest}})

	h := newCLIHostServing(t, cliBuild(t, from, ""), from)
	taken := filepath.Join(filepath.Dir(h.data), "upgrade", "taken")
	if err := os.MkdirAll(taken, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func(d string, o uint32) { webTakenDir, webTakenOwner = d, o }(webTakenDir, webTakenOwner)
	webTakenDir, webTakenOwner = taken, 0
	if err := os.WriteFile(filepath.Join(filepath.Dir(h.conf), upgraderequest.ConfFile), upgraderequest.EncodeConf(true), 0o644); err != nil {
		t.Fatal(err)
	}
	// As varlatchd writes it: the service user's file in its directory.
	r := upgraderequest.NewRequest("upr_"+strings.Repeat("a", 26), to, "idn_"+strings.Repeat("b", 26), time.Now())
	if err := upgraderequest.WriteRequest(h.data, r); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(h.data, upgraderequest.Dir), filepath.Join(h.data, upgraderequest.Dir, upgraderequest.RequestFile)} {
		if err := os.Chown(p, serviceUID, serviceUID); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := runUpgrade(t, MapEnv{"PATH": h.bin}, "--from-request", "--config", h.conf)
	if code != ExitOK || !strings.Contains(out, "was refused (no-backup-destination). Nothing was changed.") {
		t.Fatalf("--from-request: %d %q %q", code, out, errs)
	}
	h.serves(t, from)
	if _, err := os.Stat(filepath.Join(taken, r.ID+".json")); err != nil {
		t.Fatalf("the request is not kept as taken: %v", err)
	}
	s, err := upgraderequest.ReadStatus(h.data)
	if err != nil || s == nil || s.RequestID != r.ID || s.Phase != upgraderequest.Refused || s.Reason != "no-backup-destination" || s.JournalID == "" {
		t.Fatalf("the status: %+v %v", s, err)
	}
	if info, err := os.Stat(filepath.Join(h.data, upgraderequest.Dir, upgraderequest.StatusFile)); err != nil {
		t.Fatalf("the status file: %v", err)
	} else if owner := info.Sys().(*syscall.Stat_t).Uid; owner != serviceUID {
		t.Fatalf("the status file is uid %d's, not the service user's", owner)
	}
	if j, err := journal.Read(filepath.Dir(h.conf)); err != nil || j == nil || j.State != journal.Undone || j.Reached(journal.Snapshot) || j.ID != s.JournalID {
		t.Fatalf("the journal: %+v %v", j, err)
	}
	// Nothing to take now.
	if code, out, _ := runUpgrade(t, MapEnv{"PATH": h.bin}, "--from-request", "--config", h.conf); code != ExitOK || !strings.Contains(out, "There is no upgrade request") {
		t.Fatalf("again: %d %q", code, out)
	}
	if code, out, errs := runUpgrade(t, MapEnv{"PATH": h.bin}, "--recover", "--config", h.conf); code != ExitOK || !strings.Contains(out, "No upgrade or rollback is pending.") {
		t.Fatalf("--recover: %d %q %q", code, out, errs)
	}
}
