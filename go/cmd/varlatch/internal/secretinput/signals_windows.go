// SPDX-License-Identifier: Apache-2.0

package secretinput

import "os"

// fatalSignals are those after which Node.js restores its standard
// streams before it ends.
var fatalSignals = []os.Signal{os.Interrupt}

// reraise ends the process as Ctrl-C ends it on Windows.
func reraise(os.Signal) { os.Exit(130) }
