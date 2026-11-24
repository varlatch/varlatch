// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"os"
	"testing"
)

// The test program is the owner's child too, as varlatch is.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == ChildCommand {
		os.Exit(Child(os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
