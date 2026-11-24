// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix && !linux

package daemon

func noCapabilities() error { return nil }
