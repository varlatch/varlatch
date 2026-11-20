// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Runner runs a program and gives back what it wrote: the sides' only way
// to the installations. stdin is what the program reads (a key, the run
// key, the journal), never an argument; nil gives it none.
type Runner interface {
	Run(ctx context.Context, dir, name string, args []string, stdin []byte) (Ran, error)
}

// Ran is a program's outcome: its standard output, its standard error, its
// exit status.
type Ran struct {
	Answer []byte
	Said   []byte
	Code   int
}

// ExecRunner runs programs on this host.
type ExecRunner struct {
	// Env is the programs' environment (nil: this process's).
	Env []string
}

// Run runs name with args in dir. A program that could not be started is
// the error; one that ran and failed is its Ran's Code.
func (x ExecRunner) Run(ctx context.Context, dir, name string, args []string, stdin []byte) (Ran, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = x.Env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return Ran{}, err
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return Ran{}, err
	}
	if err := cmd.Start(); err != nil {
		return Ran{}, fmt.Errorf("%s could not be started: %w", name, err)
	}
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(errPipe)
		done <- b
	}()
	answer, _ := io.ReadAll(outPipe)
	said := <-done
	err = cmd.Wait()
	r := Ran{Answer: answer, Said: said}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.Code = exit.ExitCode()
		if r.Code < 0 {
			r.Code = 1
		}
	case err != nil:
		return r, err
	}
	return r, nil
}

// failure is a program that failed, with the last lines it said (the
// sides say nothing secret on stderr: their own tests hold them to it, and
// the CLI shows what it prints through its fail-safe).
func failure(what string, r Ran) error {
	said := strings.TrimSpace(string(r.Said))
	lines := strings.Split(said, "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	if said == "" {
		return fmt.Errorf("%s failed (exit %d)", what, r.Code)
	}
	return fmt.Errorf("%s failed (exit %d): %s", what, r.Code, strings.Join(lines, "; "))
}
