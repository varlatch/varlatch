// SPDX-License-Identifier: Apache-2.0

//go:build linux

package setup

import (
	"slices"
	"testing"
)

// TestSystemHostReadsAccounts: the real host's login shell (through the
// name service) and the system accounts' uid range.
func TestSystemHostReadsAccounts(t *testing.T) {
	h := SystemHost{}
	if shell, err := h.LoginShell("root"); err != nil || shell == "" {
		t.Errorf("root's shell: %q %v", shell, err)
	}
	if _, err := h.LoginShell("varlatch-no-such-user-here"); err == nil {
		t.Error("a user with no entry has a shell")
	}
	if groups, err := h.SupplementaryGroups("root"); err != nil || slices.Contains(groups, "root") {
		t.Errorf("root's supplementary groups: %q %v", groups, err)
	}
	if _, err := h.SupplementaryGroups("varlatch-no-such-user-here"); err == nil {
		t.Error("a user with no entry has groups")
	}
	if n := h.SysUIDMax(); n < 99 {
		t.Errorf("SYS_UID_MAX %d", n)
	}
}
