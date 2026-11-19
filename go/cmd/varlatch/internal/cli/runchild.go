// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
)

// runChild is inject.ts's runChild: start the command and give back its
// exit status, or 128 plus the number of the signal that ended it. Every
// mode of `varlatch run` starts its command here.
//
// Without redaction the command inherits this process's stdin, stdout and
// stderr. With redaction (the sensitive values delivered in env, and in
// assisted mode also inherited values under known Secret names) its stdout
// and stderr are pipes relayed through internal/matcher's OutputRedaction,
// even when this process's own output is a terminal; stdin, signals and the
// exit status are unchanged, and the run ends once the command has exited
// and both pipes have closed. The bytes written are the command's own,
// masked or as it wrote them: never the CLI's text, so they do not go
// through the fail-safe (failsafe_test.go's writers).
//
// The signals in forwardedSignals are passed on to the command while it
// runs (a service manager or script that signals only the CLI must reach
// the command, or the CLI would exit and leave it running); one that
// usually ends a run (interruptingSignals) makes the relay discard what it
// holds rather than release it at the end of the stream.
func (r *Run) runChild(command string, args []string, env []string, redaction *matcher.OutputRedaction) (int, error) {
	if redaction != nil {
		for _, line := range redaction.Notices() {
			r.eprintln(line)
		}
	}
	path, err := lookCommand(command, envValue(env, "PATH"))
	if err != nil {
		return 0, spawnError(command, err)
	}
	cmd := &exec.Cmd{Path: path, Args: append([]string{command}, args...), Env: env, Stdin: r.Stdin}
	var pairs []matcher.Pair
	var writeEnds []*os.File
	if redaction == nil {
		cmd.Stdout, cmd.Stderr = r.Stdout, r.Stderr
	} else {
		for _, dest := range []io.Writer{r.Stdout, r.Stderr} {
			read, write, err := os.Pipe()
			if err != nil {
				return 0, err
			}
			pairs = append(pairs, matcher.Pair{Source: read, Dest: dest})
			writeEnds = append(writeEnds, write)
		}
		cmd.Stdout, cmd.Stderr = writeEnds[0], writeEnds[1]
		// A destination that goes away fails the write (EPIPE) instead of
		// ending this process: the relay then stops reading, as a closed
		// pipe would, so the command's next write fails. The command
		// itself starts with SIGPIPE's default (a handled signal is reset
		// at exec).
		stopPipe := ignoreBrokenPipe()
		defer stopPipe()
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, forwardedSignals...)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		for _, f := range writeEnds {
			_ = f.Close()
		}
		for _, p := range pairs {
			_ = p.Source.Close()
		}
		return 0, spawnError(command, err)
	}
	// The command holds the write ends now; the relay ends when it (and
	// whatever it started) closes them.
	for _, f := range writeEnds {
		_ = f.Close()
	}
	relayed := make(chan struct{})
	if redaction != nil {
		go func() {
			redaction.Relay(pairs)
			for _, p := range pairs {
				_ = p.Source.Close()
			}
			close(relayed)
		}()
	} else {
		close(relayed)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var waitErr error
forwarding:
	for {
		select {
		case sig := <-signals:
			if redaction != nil && slices.Contains(interruptingSignals, sig) {
				redaction.Interrupt()
			}
			forwardSignal(cmd.Process, sig)
		case waitErr = <-exited:
			break forwarding
		}
	}
	signal.Stop(signals)
	<-relayed
	var exit *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exit) {
		return 0, waitErr
	}
	return exitStatus(cmd.ProcessState), nil
}

// envValue is the last value env gives name ("" when none), as the
// command's environment holds it.
func envValue(env []string, name string) string {
	value := ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && envNameEqual(k, name) {
			value = v
		}
	}
	return value
}

// spawnError is Node's error for a command that could not be started:
// `spawn <command> <code>`.
func spawnError(command string, err error) error {
	var code string
	switch {
	case errors.Is(err, errNotFound), errors.Is(err, os.ErrNotExist):
		code = "ENOENT"
	case errors.Is(err, errBatchFile):
		code = "EINVAL"
	case errors.Is(err, os.ErrPermission):
		code = "EACCES"
	default:
		return err
	}
	return errors.New("spawn " + command + " " + code)
}

var (
	errNotFound  = errors.New("not found")
	errBatchFile = errors.New("a .bat or .cmd file is never started without a shell")
)

// envLines is env as the command's environment: name=value, each
// variable once.
func envLines(names []string, values map[string]string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n+"="+values[n])
	}
	return out
}

// orderedEnv is an environment that keeps the order its variables were
// set in, as a JavaScript object keeps its keys: the parent's first, a
// variable set again keeps its place, a new one is added at the end.
type orderedEnv struct {
	names  []string
	values map[string]string
}

func newOrderedEnv() *orderedEnv { return &orderedEnv{values: map[string]string{}} }

func (e *orderedEnv) find(name string) (string, bool) {
	for _, n := range e.names {
		if envNameEqual(n, name) {
			return n, true
		}
	}
	return "", false
}

func (e *orderedEnv) Set(name, value string) {
	if n, ok := e.find(name); ok {
		e.values[n] = value
		return
	}
	e.names = append(e.names, name)
	e.values[name] = value
}

func (e *orderedEnv) Delete(name string) {
	n, ok := e.find(name)
	if !ok {
		return
	}
	e.names = slices.DeleteFunc(e.names, func(s string) bool { return s == n })
	delete(e.values, n)
}

func (e *orderedEnv) Get(name string) (string, bool) {
	n, ok := e.find(name)
	if !ok {
		return "", false
	}
	return e.values[n], true
}

func (e *orderedEnv) Lines() []string { return envLines(e.names, e.values) }
