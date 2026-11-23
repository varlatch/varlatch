// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps_test

import (
	"testing"

	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// `varlatchd admin outbound check` lists a GitHub Connection's destination
// as outbound.GitHubAPI: the address this package calls.
func TestOutboundCheckNamesGitHubsAPI(t *testing.T) {
	if outbound.GitHubAPI != githubapps.GitHubAPI {
		t.Errorf("outbound.GitHubAPI %q, githubapps.GitHubAPI %q", outbound.GitHubAPI, githubapps.GitHubAPI)
	}
}
