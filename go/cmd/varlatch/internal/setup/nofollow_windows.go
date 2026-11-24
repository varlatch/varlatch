// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"
	"io/fs"
	"os"
)

// noFollow: setup runs on Linux; elsewhere it only builds.
const noFollow = 0

const nonBlock = 0

// readNoFollow reads a file, refusing a symbolic link (setup runs on
// Linux; elsewhere it only builds and its tests run), at most 1 MiB.
func readNoFollow(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
