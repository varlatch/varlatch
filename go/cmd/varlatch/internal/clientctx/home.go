// SPDX-License-Identifier: Apache-2.0

package clientctx

// HomeDirectoryError: neither HOME (USERPROFILE on Windows) nor the
// operating system names a home directory, so the default configuration
// directory and the user-scope agent files have no place. The command line
// must give one (64).
type HomeDirectoryError struct{}

func (*HomeDirectoryError) Error() string {
	return "varlatch: the home directory is unknown: HOME is empty or unset, and the system records none for this user. Set HOME, or VARLATCH_CONFIG_DIR"
}

// recordedHomeDir is the home directory the operating system records for
// the user; a record that cannot be read, or names none, is no home
// directory.
func recordedHomeDir() (string, error) {
	home, err := systemHomeDir()
	if err != nil || home == "" {
		return "", &HomeDirectoryError{}
	}
	return home, nil
}
