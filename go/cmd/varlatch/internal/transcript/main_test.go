// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"os"
	"testing"
)

// TestMain runs the package's tests under goKit.ts's TRANSCRIPT_UMASK (022),
// as the cmd/varlatch package's TestMain does: the replay tests write
// inputs with Node.js's default modes less the umask and compare the modes
// they hold, so an ambient umask such as 077 must not change them.
func TestMain(m *testing.M) {
	setTranscriptUmask()
	os.Exit(m.Run())
}
