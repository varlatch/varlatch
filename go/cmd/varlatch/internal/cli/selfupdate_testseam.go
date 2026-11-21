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
)

// testSourceVariable names a JSON file describing the test's releases.
const testSourceVariable = "VARLATCH_TEST_SELFUPDATE_SOURCE"

func init() {
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
