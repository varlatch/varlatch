// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
)

// TestNoHomeDirectoryExits64: a command that needs the home directory when
// none is known (clientctx.HomeDirectoryError, however deep it was
// returned) prints the message, as the TypeScript CLI's catch does, and
// exits 64.
func TestNoHomeDirectoryExits64(t *testing.T) {
	var stderr strings.Builder
	r := &Run{IO: IO{Stdout: &strings.Builder{}, Stderr: &stderr}, Env: MapEnv{}}
	code := r.finish(fmt.Errorf("reading the store: %w", &clientctx.HomeDirectoryError{}))
	want := "varlatch: the home directory is unknown: HOME is empty or unset, and the system records none for this user. Set HOME, or VARLATCH_CONFIG_DIR\n"
	if code != ExitUsage || stderr.String() != want {
		t.Errorf("exit %d, stderr %q; want 64 and %q", code, stderr.String(), want)
	}
}
