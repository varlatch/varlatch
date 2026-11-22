// SPDX-License-Identifier: Apache-2.0

//go:build !crashpoint

package cli

import "github.com/varlatch/varlatch/go/cmd/varlatch/internal/setup"

// targetHost is the host a migration's target is made on: this one.
func targetHost(varlatchd string, env []string) (setup.Host, bool) {
	return setup.SystemHost{Varlatchd: varlatchd, Env: env}, false
}
