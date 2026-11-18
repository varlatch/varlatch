// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package clientctx

import (
	"os"
	"os/user"
	"strconv"
)

// HomeDir is the home directory as Node.js's os.homedir() finds it
// (libuv's uv_os_homedir): HOME, else the password database's entry for
// the effective user. An empty HOME counts as unset.
func HomeDir(env Env) (string, error) {
	if home := getenv(env, "HOME"); home != "" {
		return home, nil
	}
	return recordedHomeDir()
}

// systemHomeDir is the password database's home directory for the
// effective user; a variable so tests need no such entry.
var systemHomeDir = func() (string, error) {
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}
