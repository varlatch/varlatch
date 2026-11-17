// SPDX-License-Identifier: Apache-2.0

//go:build windows

package clientctx

import (
	"golang.org/x/sys/windows"
)

// HomeDir is the home directory as Node.js's os.homedir() finds it
// (libuv's uv_os_homedir): USERPROFILE, else the profile directory of the
// process's user. An empty USERPROFILE counts as unset, so the default
// store is never placed relative to the working directory.
func HomeDir(env Env) (string, error) {
	if home := getenv(env, "USERPROFILE"); home != "" {
		return home, nil
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	return token.GetUserProfileDirectory()
}
