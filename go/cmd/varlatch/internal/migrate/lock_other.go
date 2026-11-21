// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package migrate

import "errors"

// lockDir refuses: a migration runs on the Linux host of a Compose
// installation.
func lockDir(string) (func(), error) {
	return nil, errors.New("varlatch migrate runs on the Linux host of the installation it migrates")
}
