// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build crashpoint

package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// In a crashpoint build only (G5's interruption gate,
// server/migration/g5): VARLATCH_TEST_TAILNET_CONTROL points varlatchd's
// tailnet node, and its handoff commands, at the gate's in-process control
// server (testcontrol), which the configuration refuses as a control URL.
// A release is built without tags (go/release/build-assets.sh), so it has
// none of this; TestTestHooksAreCrashpointOnly holds every such file to
// the tag.
//
// VARLATCH_TEST_TAILSCALE_API and VARLATCH_TEST_TAILSCALE_CA point the
// restore's take-name at the gate's fake of Tailscale's API, and its
// certificate; VARLATCH_TEST_HANDOFF_LOG and VARLATCH_TEST_HANDOFF_PAUSE
// are take-name's kill points (handoffPoint), as varlatch migrate's.
func init() {
	if u := os.Getenv("VARLATCH_TEST_TAILNET_CONTROL"); u != "" {
		testTailnetControl, nodeControlURL = u, u
	}
	if u := os.Getenv("VARLATCH_TEST_TAILSCALE_API"); u != "" {
		takeNameAPI = u
	}
	if path := os.Getenv("VARLATCH_TEST_TAILSCALE_CA"); path != "" {
		if pem, err := os.ReadFile(path); err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(pem)
			takeNameTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
	}
	if path := os.Getenv("VARLATCH_TEST_HANDOFF_LOG"); path != "" {
		pause := os.Getenv("VARLATCH_TEST_HANDOFF_PAUSE")
		handoffPoint = func(point string) {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
			if err != nil {
				return
			}
			fmt.Fprintf(f, "reached %s\n", point)
			if point == pause {
				fmt.Fprintf(f, "paused %s\n", point)
				_ = f.Sync()
				_ = f.Close()
				select {}
			}
			_ = f.Close()
		}
	}
}
