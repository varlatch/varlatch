// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package storage

// tempFromEnvironment: elsewhere (Windows) SQLite asks the system.
const tempFromEnvironment = false

func usableTemp(string) bool { return true }
