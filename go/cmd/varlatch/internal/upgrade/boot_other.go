// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package upgrade

func bootID() string { return "" }
