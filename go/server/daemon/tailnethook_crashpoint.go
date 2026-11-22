// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build crashpoint

package daemon

import "os"

// In a crashpoint build only (G5's interruption gate,
// server/migration/g5): VARLATCH_TEST_TAILNET_CONTROL points varlatchd's
// tailnet node, and its handoff commands, at the gate's in-process control
// server (testcontrol), which the configuration refuses as a control URL.
// A release is built without tags (go/release/build-assets.sh), so it has
// none of this; TestTestHooksAreCrashpointOnly holds every such file to
// the tag.
func init() {
	if u := os.Getenv("VARLATCH_TEST_TAILNET_CONTROL"); u != "" {
		testTailnetControl, nodeControlURL = u, u
	}
}
