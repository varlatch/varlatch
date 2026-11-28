// SPDX-License-Identifier: Apache-2.0

//go:build unix

package webupgrade

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

// take is Decision 1's take: request.json renamed, in one step, from the
// data directory's upgrade-request directory into takenDir (root's, on the
// same file system) under a name of the helper's own; only then is it
// opened, once, and read. Every directory on the way is opened without
// following a link, and the rename is relative to the directories opened,
// so a link put where a directory was moves nothing else. The file must be
// a regular file of the data directory's owner, with one link, of at most
// MaxBytes. ErrNoRequest when there is none: cancelled, or already taken.
// takenOwner is root (0), but in the tests.
func take(dataDir, takenDir string, takenOwner uint32) (raw []byte, taken string, err error) {
	owner, err := ownerOf(dataDir)
	if err != nil {
		return nil, "", err
	}
	data, err := openDir(-1, dataDir)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(data)
	dir, err := openDir(data, upgraderequest.Dir)
	if errors.Is(err, unix.ENOENT) {
		return nil, "", ErrNoRequest
	}
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(dir)
	to, err := openDir(-1, takenDir)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(to)
	var st unix.Stat_t
	if err := unix.Fstat(to, &st); err != nil {
		return nil, "", err
	}
	if st.Uid != takenOwner || st.Mode&0o077 != 0 {
		return nil, "", fmt.Errorf("%s is not root's alone (uid %d, mode %04o)", takenDir, st.Uid, st.Mode&0o7777)
	}
	name := make([]byte, 8)
	if _, err := rand.Read(name); err != nil {
		return nil, "", err
	}
	taken = "take-" + hex.EncodeToString(name) + ".json"
	// The take: from here the file is the helper's, and a cancel finds
	// nothing to remove.
	if err := unix.Renameat(dir, upgraderequest.RequestFile, to, taken); errors.Is(err, unix.ENOENT) {
		return nil, "", ErrNoRequest
	} else if err != nil {
		return nil, "", fmt.Errorf("taking the request: %w", err)
	}
	_ = unix.Fsync(to)
	taken = filepath.Join(takenDir, taken)
	fd, err := unix.Openat(to, filepath.Base(taken), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, taken, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	f := os.NewFile(uintptr(fd), taken)
	defer f.Close()
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, taken, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, taken, fmt.Errorf("%w: not a regular file", ErrInvalid)
	case st.Uid != owner:
		return nil, taken, fmt.Errorf("%w: owned by uid %d, not the data directory's owner (uid %d)", ErrInvalid, st.Uid, owner)
	case st.Nlink != 1:
		return nil, taken, fmt.Errorf("%w: %d links", ErrInvalid, st.Nlink)
	case st.Size > upgraderequest.MaxBytes:
		return nil, taken, fmt.Errorf("%w: more than %d bytes", ErrInvalid, upgraderequest.MaxBytes)
	}
	raw, err = io.ReadAll(io.LimitReader(f, upgraderequest.MaxBytes+1))
	if err != nil {
		return nil, taken, err
	}
	if len(raw) > upgraderequest.MaxBytes {
		return nil, taken, fmt.Errorf("%w: more than %d bytes", ErrInvalid, upgraderequest.MaxBytes)
	}
	return raw, taken, nil
}

// openDir opens a directory relative to at (-1: an absolute path),
// following no link at its end.
func openDir(at int, path string) (int, error) {
	if at < 0 {
		at = unix.AT_FDCWD
	}
	return unix.Openat(at, path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

// ownerOf is a directory's owner.
func ownerOf(dir string) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return 0, fmt.Errorf("%s is not a directory", dir)
	}
	return st.Uid, nil
}

// sameFileSystem is whether two directories are on one file system, as the
// take's rename needs.
func sameFileSystem(a, b string) (bool, error) {
	var sa, sb unix.Stat_t
	if err := unix.Stat(a, &sa); err != nil {
		return false, err
	}
	if err := unix.Stat(b, &sb); err != nil {
		return false, err
	}
	return sa.Dev == sb.Dev, nil
}
