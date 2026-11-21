// SPDX-License-Identifier: Apache-2.0

//go:build windows

package backup

// syncDir does nothing on Windows. A directory there cannot be synced
// through a handle os.Open gives (FlushFileBuffers needs write access, so
// it fails "Access is denied"), and NTFS records a rename or link in its
// own metadata journal; the archive file itself is still synced before it
// is linked into place.
func syncDir(string) error { return nil }
