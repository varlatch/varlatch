// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// TestAgentRunOverrideWithoutHome: inside an agent-safe run, an explicit
// VARLATCH_CONFIG_DIR is used as given when there is no home directory
// (and no XDG_CONFIG_HOME): there is no default directory for it to be.
// Without the override, the store is still refused as the operator's.
func TestAgentRunOverrideWithoutHome(t *testing.T) {
	saved := systemHomeDir
	defer func() { systemHomeDir = saved }()
	systemHomeDir = func() (string, error) { return "", errors.New("user: unknown userid 12345") }
	dir := t.TempDir()
	env := mapEnv{AgentRunEnv: "run_1", "VARLATCH_CONFIG_DIR": dir}
	if err := SaveCredential("https://a.example", jsjson.Object{{Key: "token", Value: "vlt_cli_fakeAAAA"}}, env); err != nil {
		t.Fatalf("save: %v", err)
	}
	list, err := ListCredentials(env)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v, %v", list, err)
	}
	if path, err := CredentialsPath(env); err != nil || path != filepath.Join(dir, "credentials.json") {
		t.Errorf("path %q, %v", path, err)
	}
	// No override: blocked as before, not a home-directory error.
	if blocked, err := operatorStoreBlocked(mapEnv{AgentRunEnv: "run_1"}); err != nil || !blocked {
		t.Errorf("without the override: blocked %v, %v", blocked, err)
	}
}
