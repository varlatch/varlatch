// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build headscale && linux

package daemon

import (
	"fmt"
	"os"
	"testing"

	"github.com/varlatch/varlatch/go/server/tailnet/headscaletest"
)

// The Headscale tests' one TestMain (build tag headscale): the tailnet
// listener's identity cases and a handoff's node commands (step 7.5c c3,
// tailnet_headscale_test.go) and the restore's take-name (c4,
// tailnettakename_headscale*_test.go). Each test starts its own Headscale
// container (headscaletest.Start); what they share is the run's CA, whose
// certificate the process trusts through SSL_CERT_FILE.

// headscaleCA is the run's CA; nil in a take-name child process
// (TestHeadscaleTakeNameChild), which trusts its parent's through the
// SSL_CERT_FILE it inherits and starts no Headscale of its own.
var headscaleCA *headscaletest.CA

// takeNameChild is the environment variable that marks the take-name
// child of TestKillTheHeadscaleTakeoverAtEveryStep.
const takeNameChild = "VARLATCH_HS_TAKENAME_CHILD_CONF"

func TestMain(m *testing.M) {
	var dir string
	if os.Getenv(takeNameChild) == "" {
		var err error
		if dir, err = os.MkdirTemp("", "daemon-headscale-ca-"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		// Before anything in the process uses TLS: Go reads the roots once.
		if headscaleCA, err = headscaletest.Trust(dir); err != nil {
			_ = os.RemoveAll(dir)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}
