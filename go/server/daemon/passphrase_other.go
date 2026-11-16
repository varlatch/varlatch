// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !(linux || darwin || freebsd || openbsd || netbsd)

package daemon

import "io"

// readHidden has no terminal prompt here: the passphrase comes from
// --passphrase-file or VARLATCH_KEK_PASSPHRASE.
func readHidden(string, io.Writer) (string, bool, error) { return "", false, nil }
