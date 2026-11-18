// SPDX-License-Identifier: Apache-2.0

package secretinput

import (
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
)

// Cancelled is the prompt's answer to Ctrl-C: the command ends with 130
// and nothing is stored. Its message has been written already.
type Cancelled struct{}

func (Cancelled) Error() string { return "cancelled" }

// IsTerminal is process.stdin.isTTY for the run's standard input.
func IsTerminal(stream io.Reader) bool {
	f, ok := stream.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// Hook, when set, is called at each stage of the prompt before the
// question is shown ("signals": the signal handler is in place; "raw": the
// terminal is in raw mode). Tests only: the pseudo-terminal tests stop
// there to send a signal in that window.
var Hook func(stage string)

func hook(stage string) {
	if Hook != nil {
		Hook(stage)
	}
}

// PromptHidden is promptHidden: one line read from the terminal without
// echoing it (see HiddenInput), say writing on standard error. The signal
// handler is in place before the terminal enters raw mode, and the
// terminal is restored before anything more is written and before signal
// delivery stops, however the prompt ends: Enter, Ctrl-D, Ctrl-C
// (Cancelled, exit 130), a signal (SIGINT, SIGTERM, SIGHUP, SIGQUIT: the
// terminal restored, then the signal's default action, as Node.js restores
// its standard streams on a fatal signal), a read error, or a panic. Enter
// or Ctrl-D on an empty line means no value.
func PromptHidden(input *os.File, say func(text string), question string) (value string, err error) {
	fd := int(input.Fd())
	var (
		mu    sync.Mutex
		state *term.State
		done  bool
	)
	restore := func() {
		mu.Lock()
		defer mu.Unlock()
		if state != nil && !done {
			done = true
			_ = term.Restore(fd, state)
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, fatalSignals...)
	defer func() {
		// The terminal first, then signal delivery: a signal that arrives
		// in between still finds the terminal restored.
		restore()
		signal.Stop(signals)
		close(signals)
	}()
	defer func() {
		if p := recover(); p != nil {
			restore()
			panic(p)
		}
	}()
	go func() {
		if sig, ok := <-signals; ok {
			restore()
			reraise(sig)
		}
	}()
	hook("signals")
	// Under the lock, so a signal handled meanwhile waits for the state it restores.
	mu.Lock()
	state, err = term.MakeRaw(fd)
	mu.Unlock()
	if err != nil {
		return "", err
	}
	hook("raw")

	// Raw mode first, then the question: nothing typed after it is echoed.
	say(question)
	finish := func() {
		restore()
		say("\n")
	}
	var typed HiddenInput
	var pending []byte // an incomplete UTF-8 sequence, kept for the next read (Node's StringDecoder)
	buf := make([]byte, 4096)
	for {
		n, readErr := input.Read(buf)
		if n > 0 {
			data := decodeChunk(&pending, buf[:n])
			if strings.ContainsRune(data, 0x03) {
				finish()
				say("varlatch: cancelled; nothing was stored\n")
				return "", Cancelled{}
			}
			if value, done := typed.Feed(data); done {
				finish()
				if value == "" {
					return "", &Error{Message: "no value entered; nothing was stored"}
				}
				if !IsWellFormed(value) {
					return "", &Error{Message: "the value entered is not well-formed Unicode text; nothing was stored"}
				}
				return value, nil
			}
		}
		if readErr != nil {
			// The terminal went away before Enter: nothing was entered.
			finish()
			return "", &Error{Message: "no value entered; nothing was stored"}
		}
	}
}

// decodeChunk decodes bytes read from the terminal as Node's StringDecoder
// does for setEncoding("utf8"): an incomplete sequence at the end waits
// for the next read, and each ill-formed subsequence becomes U+FFFD.
func decodeChunk(pending *[]byte, chunk []byte) string {
	b := append(*pending, chunk...)
	cut := len(b)
	// At most the last three bytes can start a sequence still incomplete.
	for back := 1; back <= 3 && back <= len(b); back++ {
		c := b[len(b)-back]
		if c < 0x80 {
			break
		}
		if c >= 0xc0 {
			need := 0
			switch {
			case c >= 0xf0:
				need = 4
			case c >= 0xe0:
				need = 3
			default:
				need = 2
			}
			if need > back && !utf8.FullRune(b[len(b)-back:]) {
				cut = len(b) - back
			}
			break
		}
	}
	*pending = append([]byte(nil), b[cut:]...)
	return jsval.DecodeUTF8(b[:cut])
}
