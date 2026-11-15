// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

import "errors"

// lockDataDir: varlatchd serves on Linux only (its release builds Linux
// binaries); elsewhere there is no lifetime lock, so nothing may write.
func lockDataDir(string) (func(), error) {
	return nil, errors.New("varlatchd's data directory lock needs a Unix system")
}
