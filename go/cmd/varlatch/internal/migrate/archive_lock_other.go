// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package migrate

import "errors"

// conversionSupported: the converter refuses off Linux and macOS (no
// lock; Docker there runs no Linux image as the conversion needs).
const conversionSupported = false

func defaultLockDir() string { return "" }

func lockConversion(string) (func(), error) {
	return nil, errors.New("varlatch migrate --from-archive runs on a Linux or macOS host with Docker")
}
