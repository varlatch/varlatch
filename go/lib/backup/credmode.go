// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"fmt"
	"io/fs"
)

// CredentialsModeProblem is what is wrong with a bucket key file's mode
// (writeCredentialsFile), "" when nothing is: varlatchd reads the file as
// the service's user, so the file may be readable by the service's group
// (root:varlatch 0640, docs/operations/backup.md), but by no other group,
// by no one else, and writable by no group. serviceGID is that group's id
// (-1: unknown, the group is then not compared). Modes are judged on Unix
// only (FileGID): elsewhere every file passes.
func CredentialsModeProblem(path string, info fs.FileInfo, serviceGID int) string {
	if !info.Mode().IsRegular() {
		return fmt.Sprintf("the bucket key file %s is not a regular file", path)
	}
	gid, ok := FileGID(info)
	if !ok {
		return ""
	}
	perm := info.Mode().Perm()
	switch {
	case perm&0o007 != 0:
		return fmt.Sprintf("the bucket key file %s is open to others (mode %04o): only its owner and the service's group may read it (chmod 0640)", path, perm)
	case perm&0o020 != 0:
		return fmt.Sprintf("the bucket key file %s may be written by its group (mode %04o): chmod 0640", path, perm)
	case perm&0o040 != 0 && serviceGID >= 0 && gid != serviceGID:
		return fmt.Sprintf("the bucket key file %s is readable by group %d, not the service's group (%d): chgrp it to the service's group, or make it the service user's alone (0600)", path, gid, serviceGID)
	}
	return ""
}
