// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgraderequest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// cancelRequest is CancelRequest through descriptors: the upgrade-request
// directory opened relative to dataDir without following a link, and
// request.json opened, read and unlinked below that descriptor. A link
// there, for the directory or the file, is refused, and nothing outside the
// directory is removed.
func cancelRequest(dataDir, id string) error {
	parent, err := unix.Open(dataDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return ErrTaken
	case err != nil:
		return err
	}
	defer unix.Close(parent)
	path := filepath.Join(dataDir, Dir)
	dir, err := unix.Openat(parent, Dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return ErrTaken
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%w: %s", ErrNotDirectory, path)
	case err != nil:
		return err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, RequestFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return ErrTaken
	case errors.Is(err, unix.ELOOP):
		return fmt.Errorf("%s is a link: it is no request", filepath.Join(path, RequestFile))
	case err != nil:
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(path, RequestFile))
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a regular file", f.Name())
	}
	b, err := readLimited(f)
	if err != nil {
		return err
	}
	r, err := ParseRequest(b)
	if err != nil {
		return err
	}
	if r.ID != id {
		return ErrTaken
	}
	if err := unix.Unlinkat(dir, RequestFile, 0); errors.Is(err, unix.ENOENT) {
		return ErrTaken
	} else if err != nil {
		return err
	}
	return nil
}
