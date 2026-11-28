// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package webupgrade

import (
	"context"
	"errors"
	"io/fs"
)

var errNotHere = errors.New("the web upgrade's helper runs on the Linux host of a Go installation")

func take(string, string, uint32) ([]byte, string, error) { return nil, "", errNotHere }

func sameFileSystem(string, string) (bool, error) { return false, errNotHere }

func writeRootFile(string, []byte, fs.FileMode) error { return errNotHere }

func mkdirRoot(string, fs.FileMode) error { return errNotHere }

func systemctl(context.Context, ...string) error { return errNotHere }
