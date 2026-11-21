// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package migrate

import "errors"

func defaultLockDir() string { return "" }

func lockConversion(string) (func(), error) {
	return nil, errors.New("varlatch migrate --from-archive runs on a Linux or macOS host with Docker")
}
