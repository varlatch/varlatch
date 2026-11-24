// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

import "github.com/varlatch/varlatch/go/server/config"

func becomeOwner(*config.Config, func()) error { return nil }

func below(string, string) bool { return false }
