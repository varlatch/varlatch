// SPDX-License-Identifier: Apache-2.0

// Command stubcli stands in for the varlatch binary in install.ps1's
// end-to-end test: it reports a version and, unless STUB_VERIFY=fail,
// passes verify-release (the real command is tested in cmd/varlatch); it
// appends its arguments to STUB_LOG.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if log := os.Getenv("STUB_LOG"); log != "" {
		if f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprintln(f, strings.Join(os.Args[1:], " "))
			_ = f.Close()
		}
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version":
			v := os.Getenv("STUB_REPORTS")
			if v == "" {
				v = "0.50.0"
			}
			fmt.Println("varlatch", v)
			return
		case "verify-release":
			if os.Getenv("STUB_VERIFY") == "fail" {
				fmt.Fprintln(os.Stderr, "signature does not verify")
				os.Exit(1)
			}
			fmt.Println("SHA256SUMS of 0.50.0 is signed (stub)")
			return
		}
	}
	os.Exit(2)
}
