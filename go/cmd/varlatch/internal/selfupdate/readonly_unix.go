// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package selfupdate

import (
	"errors"
	"syscall"
)

func isReadOnly(err error) bool { return errors.Is(err, syscall.EROFS) }
