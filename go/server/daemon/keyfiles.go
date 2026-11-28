// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
)

// The key files varlatchd serve reads (the Root KEK, the backup key) are
// looked at before they are read. One that is not a regular file is
// refused (exit 78): a directory, a pipe or a device is never a key file.
// One its group or others may read is said, loudly, each start, and fails
// `varlatch doctor` (files.keys); it is not refused, so an installation
// whose mount gives looser modes (a container's secret mounted 0644)
// keeps serving across an upgrade while its operator tightens them.
//
// Under the unit, the keys are systemd's credentials: systemd makes each
// copy itself, for the service's user alone, and may grant that access
// with an ACL that stat shows as group bits. A file in
// $CREDENTIALS_DIRECTORY is therefore judged as a regular file only; its
// source in /etc/varlatch is root's 0600 file, which doctor checks.

// keyFileProblem is what is wrong with the key file at path, as varlatchd
// serve reads it: refuse when it must not be read at all, loose when its
// group or others may read it ("" when not). A file that cannot be looked
// at is neither: reading it says why, as it did before.
func keyFileProblem(what, path, credentialsDir string) (loose string, refuse error) {
	if path == "" {
		return "", nil
	}
	info, err := os.Stat(path) // a link is followed: a mounted secret is often one
	if err != nil {
		return "", nil
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s %s is not a regular file (%s)", what, path, info.Mode().Type())
	}
	if credentialsDir != "" && filepath.Dir(filepath.Clean(path)) == filepath.Clean(credentialsDir) {
		return "", nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("%s %s is readable by its group or others (mode %04o): make it the service user's alone (chmod 0600, or 0400 in the container image); varlatch doctor fails until then", what, path, perm), nil
	}
	return "", nil
}
