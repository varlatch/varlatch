// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

// giveToOwner: no owner to give files to.
func giveToOwner(string, int) {}
