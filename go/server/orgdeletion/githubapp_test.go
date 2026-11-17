// SPDX-License-Identifier: AGPL-3.0-or-later

package orgdeletion_test

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/httpserver"
)

// TestGitHubAppTeardownWaitsForStep410 holds GitHubAppTeardown's marker
// (finalize.go): until step 4.10 builds the GitHub App, a deletion changes
// the App's rows as the TypeScript server does, and nothing else of the
// App exists in this varlatchd. Once any of 4.10's operations (every one
// under /github-app) is built, this fails: move the teardown into 4.10's
// package with whatever it keeps of an App, and remove this test.
func TestGitHubAppTeardownWaitsForStep410(t *testing.T) {
	for _, p := range httpserver.BuiltOperations {
		if strings.Contains(p, "/github-app") {
			t.Errorf("%s is built (step 4.10): orgdeletion.GitHubAppTeardown is still the row-only stand-in; replace it with 4.10's teardown and remove this test", p)
		}
	}
}
