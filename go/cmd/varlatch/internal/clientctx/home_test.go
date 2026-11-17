// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"errors"
	"testing"
)

// TestNoHomeDirectory: with HOME (USERPROFILE) empty or unset and no home
// directory on record (no record, or one that names none), every reader of
// the home directory gets HomeDirectoryError, never a path relative to the
// working directory.
func TestNoHomeDirectory(t *testing.T) {
	saved := systemHomeDir
	defer func() { systemHomeDir = saved }()
	for name, system := range map[string]func() (string, error){
		"no record":          func() (string, error) { return "", errors.New("user: unknown userid 12345") },
		"a record with none": func() (string, error) { return "", nil },
	} {
		systemHomeDir = system
		for _, env := range []mapEnv{{}, {"HOME": "", "USERPROFILE": ""}} {
			var e *HomeDirectoryError
			if _, err := HomeDir(env); !errors.As(err, &e) {
				t.Errorf("%s, %v: HomeDir: %v", name, env, err)
			}
			if _, err := ConfigDir(env); !errors.As(err, &e) {
				t.Errorf("%s, %v: ConfigDir: %v", name, env, err)
			}
		}
		if dir, err := ConfigDir(mapEnv{"VARLATCH_CONFIG_DIR": "/given"}); err != nil || dir != "/given" {
			t.Errorf("%s: VARLATCH_CONFIG_DIR still decides: %q, %v", name, dir, err)
		}
	}
}
