// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

import "github.com/varlatch/varlatch/go/server/config"

func giveFiles(int, int, ...string) {}

func giveDataFiles(string) {}

func becomeOwner(*config.Config, func(uid, gid int)) error { return nil }
