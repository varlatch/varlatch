// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package doctor

import "errors"

// freeSpace: varlatchd runs on Linux; elsewhere it is not known.
func freeSpace(string) (uint64, error) { return 0, errors.New("not measured on this system") }

// clockSynced: not known on this system.
func clockSynced() (synced, known bool) { return false, false }
