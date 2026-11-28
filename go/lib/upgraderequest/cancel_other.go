// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package upgraderequest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// cancelRequest is CancelRequest by path, where there is no openat: the
// upgrade-request directory and request.json are checked with Lstat first.
// No host helper runs here; varlatchd's own cancel is the only remover.
func cancelRequest(dataDir, id string) error {
	if err := CheckDir(dataDir); errors.Is(err, os.ErrNotExist) {
		return ErrTaken
	} else if err != nil {
		return err
	}
	path := filepath.Join(dataDir, Dir, RequestFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrTaken
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	r, err := ReadRequest(dataDir)
	if err != nil {
		return err
	}
	if r == nil || r.ID != id {
		return ErrTaken
	}
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return ErrTaken
	} else if err != nil {
		return err
	}
	return nil
}
