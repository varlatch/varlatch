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
// the effective user. An empty HOME counts as unset, so the default store
// is never placed relative to the working directory.
func HomeDir(env Env) (string, error) {
	if home := getenv(env, "HOME"); home != "" {
		return home, nil
	}
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}
