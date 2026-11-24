// SPDX-License-Identifier: Apache-2.0

//go:build selfupdatetest

package cli

// Built only with -tags selfupdatetest, by the self-update process tests
// (cmd/varlatch's TestSelfUpdate*): a release build has no way to change
// where releases come from or what verifies them. TestSeamIsTestOnly holds
// this file to its build tag and the release build to no tags.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/upgrade"
)

const (
	// testSourceVariable names a JSON file describing the test's releases.
	testSourceVariable = "VARLATCH_TEST_SELFUPDATE_SOURCE"
	// testKillVariable is the crash point (upgrade.Upgrader.Crash) at which
	// this process kills itself, as a SIGKILL or a power cut would end it.
	testKillVariable = "VARLATCH_TEST_UPGRADE_KILL"
)

func init() {
	upgradeSeam = func(r *Run, u *upgrade.Upgrader) {
		at := r.Getenv(testKillVariable)
		if at == "" {
			return
		}
		u.Crash = func(point string) bool {
			if point != at {
				return false
			}
			self, err := os.FindProcess(os.Getpid())
			if err == nil {
				err = self.Kill()
			}
			if err != nil {
				panic(err)
			}
			select {}
		}
	}
	release := selfUpdateSource
	selfUpdateSource = func(r *Run) selfupdate.Source {
		path := r.Getenv(testSourceVariable)
		if path == "" {
			return release(r)
		}
		var cfg struct {
			API, Download, Pages string
			Hosts                []string
			CA, TrustedRoot      string
		}
		data, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(data, &cfg)
		}
		if err != nil {
			panic(err)
		}
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			panic(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(pem)
		src := selfupdate.Source{
			API: cfg.API, Download: cfg.Download, Pages: cfg.Pages, Hosts: cfg.Hosts, UserAgent: r.UserAgent(),
			Trusted: func(context.Context) (root.TrustedMaterial, error) {
				return root.NewTrustedRootFromPath(cfg.TrustedRoot)
			},
		}
		return src.WithRoots(roots)
	}
}
