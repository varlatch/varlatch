// SPDX-License-Identifier: Apache-2.0

//go:build windows

package clientctx

import (
	"golang.org/x/sys/windows"
)

// HomeDir is the home directory as Node.js's os.homedir() finds it
// (libuv's uv_os_homedir): USERPROFILE, else the profile directory of the
// process's user. An empty USERPROFILE counts as unset.
func HomeDir(env Env) (string, error) {
	if home := getenv(env, "USERPROFILE"); home != "" {
		return home, nil
	}
	return recordedHomeDir()
}

// systemHomeDir is the profile directory of the process's user; a
// variable so tests can replace it.
var systemHomeDir = func() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	return token.GetUserProfileDirectory()
}
