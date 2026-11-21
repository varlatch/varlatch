// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package backup

import (
	"errors"
	"os"
)

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
