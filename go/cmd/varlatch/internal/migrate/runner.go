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

// Streamer is a Runner that also runs a program on streams, for what is
// too large to hold in memory (a migration bundle): in is the program's
// input, read to its end and then closed, as the program reads it; what
// the program writes on its standard output goes to out as it writes it;
// only its standard error is kept, its last saidLimit bytes, in the Ran's
// Said (Answer is empty). These are the child's streams, never the CLI's
// own: the CLI writes only through its fail-safe.
type Streamer interface {
	Stream(ctx context.Context, dir, name string, args []string, in io.Reader, out io.Writer) (Ran, error)
}

// saidLimit bounds what a streamed program's stderr keeps: its last lines
// are what failure and a summary read.
const saidLimit = 1 << 20

// tail keeps the last n bytes written to it (bytes). It holds up to 2n
// and trims back to n only then, so a long stream costs one copy of n
// bytes per n written, never one per write.
type tail struct {
	n int
	b []byte
}

func (t *tail) Write(p []byte) (int, error) {
	if len(p) >= t.n {
		t.b = append(t.b[:0], p[len(p)-t.n:]...)
		return len(p), nil
	}
	t.b = append(t.b, p...)
	if len(t.b) > 2*t.n {
		t.b = append(t.b[:0], t.b[len(t.b)-t.n:]...)
	}
	return len(p), nil
}

// bytes is the last n bytes written.
func (t *tail) bytes() []byte {
	if len(t.b) > t.n {
		return t.b[len(t.b)-t.n:]
	}
	return t.b
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
	// As, when set, runs them as that uid and gid (an image's user, whose
	// files they write): this process must be root.
	As *Owner
}

// Owner is a uid and a gid.
type Owner struct {
	UID, GID uint32
}

// Run runs name with args in dir. A program that could not be started is
// the error; one that ran and failed is its Ran's Code.
func (x ExecRunner) Run(ctx context.Context, dir, name string, args []string, stdin []byte) (Ran, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = x.Env
	if x.As != nil {
		if err := runAs(cmd, *x.As); err != nil {
			return Ran{}, err
		}
	}
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

// Stream runs name with args in dir on streams (Streamer). The child's
// output is read from its pipes, as Run reads it. A program that stops
// reading its input early (it refused before reading) is no error of the
// copy: its exit status says why. A write to out that fails kills the
// program, whose output is then drained, so Wait never waits on a pipe
// nobody reads.
func (x ExecRunner) Stream(ctx context.Context, dir, name string, args []string, in io.Reader, out io.Writer) (Ran, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = x.Env
	if x.As != nil {
		if err := runAs(cmd, *x.As); err != nil {
			return Ran{}, err
		}
	}
	cmd.Stdin = in
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
	said := &tail{n: saidLimit}
	saidDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(said, errPipe)
		close(saidDone)
	}()
	_, copyErr := io.Copy(out, outPipe)
	if copyErr != nil {
		_ = cmd.Process.Kill()
		_, _ = io.Copy(io.Discard, outPipe)
	}
	<-saidDone
	err = cmd.Wait()
	r := Ran{Said: said.bytes()}
	if copyErr != nil {
		return r, fmt.Errorf("%s's output could not be written: %w", name, copyErr)
	}
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
