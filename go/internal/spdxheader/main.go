// SPDX-License-Identifier: Apache-2.0

// Command spdxheader puts an SPDX-License-Identifier line at the top of a
// generated Go file, as scripts/check-licenses.mjs requires of every source
// file (within its first three lines). Generators such as oapi-codegen write
// their own header and have no option for this one, so a go:generate line
// runs this command right after the generator:
//
//	go run ../../internal/spdxheader AGPL-3.0-or-later api.gen.go
//
// A file that already starts with the line is left as it is.
package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
)

var licenseID = regexp.MustCompile(`^[A-Za-z0-9.+-]+$`)

func main() {
	if len(os.Args) != 3 || !licenseID.MatchString(os.Args[1]) {
		fmt.Fprintln(os.Stderr, "usage: spdxheader <SPDX license identifier> <file>")
		os.Exit(2)
	}
	if err := apply(os.Args[2], os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "spdxheader:", err)
		os.Exit(1)
	}
}

func apply(path, license string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out := withHeader(data, license)
	if bytes.Equal(out, data) {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, info.Mode().Perm())
}

// withHeader returns src with "// SPDX-License-Identifier: <license>" and a
// blank line in front, unless src already starts with that line. The blank
// line keeps the header out of the package's doc comment and away from any
// //go:build line that follows.
func withHeader(src []byte, license string) []byte {
	header := []byte("// SPDX-License-Identifier: " + license + "\n")
	if bytes.HasPrefix(src, header) {
		return src
	}
	return append(append(append([]byte{}, header...), '\n'), src...)
}
