// SPDX-License-Identifier: Apache-2.0

package g9a

import "runtime"

func goos() string { return runtime.GOOS + "/" + runtime.GOARCH }

func cpus() int { return runtime.NumCPU() }
