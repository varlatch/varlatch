// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package setup

import (
	"context"
	"errors"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
)

// errNotLinux: a Go installation is set up on a Linux host with systemd.
var errNotLinux = errors.New("setup: a Go installation is set up on Linux, with systemd")

// SystemHost refuses everything off Linux.
type SystemHost struct {
	Varlatchd string
	Env       []string
}

func (SystemHost) Path(p string) string                         { return p }
func (SystemHost) LookupUser(string) (int, int, bool, error)    { return 0, 0, false, errNotLinux }
func (SystemHost) CreateUser(string) error                      { return errNotLinux }
func (SystemHost) LoginShell(string) (string, error)            { return "", errNotLinux }
func (SystemHost) SupplementaryGroups(string) ([]string, error) { return nil, errNotLinux }
func (SystemHost) SysUIDMax() int                               { return 999 }
func (SystemHost) Chown(string, int, int) error                 { return errNotLinux }
func (SystemHost) Systemctl(...string) (string, error)          { return "", errNotLinux }
func (SystemHost) CheckConfig(string) (string, error)           { return "", errNotLinux }
func (SystemHost) Ready(context.Context, string) error          { return errNotLinux }
func (SystemHost) Probe(context.Context, string) (diskprobe.Result, error) {
	return diskprobe.Result{}, errNotLinux
}
