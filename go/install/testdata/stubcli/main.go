// SPDX-License-Identifier: Apache-2.0

// Command stubcli stands in for the varlatch binary in install.ps1's
// end-to-end test. It reports a version (STUB_REPORTS, default 0.50.0).
// Its verify-release fails if STUB_VERIFY=fail, and otherwise checks the
// files it is given against the SHA-256 the test expects (STUB_WANT_SUMS,
// STUB_WANT_BUNDLE, STUB_WANT_FILE, under the name STUB_WANT_NAME), so the
// test sees the installer pass the staged files intact; the real command is
// tested in cmd/varlatch. Every call's arguments are appended to STUB_LOG
// as a JSON array. Like the real binary, it carries self-update's refusal
// for a Homebrew copy (homebrewRefusal), which install.sh must not take
// for a sign of Homebrew; install.sh's tests run it too.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	if log := os.Getenv("STUB_LOG"); log != "" {
		if f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			b, _ := json.Marshal(os.Args[1:])
			fmt.Fprintln(f, string(b))
			_ = f.Close()
		}
	}
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	// STUB_FAIL_UNDER: the stub fails when it runs from below that
	// directory (installed, as opposed to staged).
	if under := os.Getenv("STUB_FAIL_UNDER"); under != "" {
		if exe, err := os.Executable(); err == nil && strings.HasPrefix(strings.ToLower(exe), strings.ToLower(under)) {
			os.Exit(1)
		}
	}
	switch os.Args[1] {
	case "self-update":
		fail(fmt.Sprintf(homebrewRefusal, "/the/stub"))
	case "--version":
		v := os.Getenv("STUB_REPORTS")
		if v == "" {
			v = "0.50.0"
		}
		fmt.Println("varlatch", v)
	case "verify-release":
		if os.Getenv("STUB_VERIFY") == "fail" {
			fail("signature does not verify")
		}
		args := os.Args[2:]
		for i := 0; i+1 < len(args); i += 2 {
			switch args[i] {
			case "--sums":
				check(args[i+1], "STUB_WANT_SUMS")
			case "--bundle":
				check(args[i+1], "STUB_WANT_BUNDLE")
			case "--file":
				path, name, _ := strings.Cut(args[i+1], "=")
				if want := os.Getenv("STUB_WANT_NAME"); want != "" && name != want {
					fail("--file names " + name)
				}
				check(path, "STUB_WANT_FILE")
			}
		}
		fmt.Println("SHA256SUMS of 0.50.0 is signed (stub)")
	default:
		os.Exit(2)
	}
}

// homebrewRefusal is cmd/varlatch/internal/selfupdate's message for a
// Homebrew copy, which every Go varlatch binary carries.
const homebrewRefusal = "varlatch is installed with Homebrew at %s; update it with: brew upgrade varlatch"

func check(path, wantVar string) {
	want := os.Getenv(wantVar)
	if want == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != want {
		fail(path + " is not the file the test served")
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "stub verify-release:", msg)
	os.Exit(1)
}
