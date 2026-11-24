// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"os"
	"strings"
)

// bootID is this boot's identity: another after each reboot.
func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
