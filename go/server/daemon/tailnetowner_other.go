// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

import "io/fs"

// ownedByMe: no owner to tell; nothing is swept.
func ownedByMe(fs.FileInfo) bool { return false }

// giveToOwner: no owner to give files to.
func giveToOwner(string, int) {}
