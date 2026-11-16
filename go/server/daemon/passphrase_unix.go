// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux || darwin || freebsd || openbsd || netbsd

package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// readHidden reads one line from the terminal without echoing it, as the
// TypeScript CLI's raw-mode prompt does; false when stdin is not one.
func readHidden(prompt string, stderr io.Writer) (string, bool, error) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return "", false, nil
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
		return "", true, err
	}
	defer unix.IoctlSetTermios(fd, ioctlSetTermios, old)
	fmt.Fprint(stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(stderr)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", true, err
	}
	return strings.TrimRight(line, "\r\n"), true, nil
}
