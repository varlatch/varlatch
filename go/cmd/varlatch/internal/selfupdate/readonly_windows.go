// SPDX-License-Identifier: Apache-2.0

//go:build windows

package selfupdate

func isReadOnly(error) bool { return false }
