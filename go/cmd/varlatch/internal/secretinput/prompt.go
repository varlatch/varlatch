// SPDX-License-Identifier: Apache-2.0

package secretinput

import (
	"io"
	"os"
	"os/signal"
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

// PromptHidden is promptHidden: one line read from the terminal without
// echoing it (see HiddenInput). The terminal is in raw mode while the line
// is typed and restored before anything more is written, whatever ends
// the prompt: Enter, Ctrl-D, Ctrl-C (Cancelled, exit 130), or a signal
// (the terminal restored, then the signal's default action, as Node.js
// restores its standard streams on a fatal signal). Enter or Ctrl-D on an
// empty line means no value.
func PromptHidden(input *os.File, output io.Writer, question string) (string, error) {
	fd := int(input.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	var once sync.Once
	restore := func() { once.Do(func() { _ = term.Restore(fd, state) }) }
	defer restore()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, fatalSignals...)
	defer func() {
		signal.Stop(signals)
		close(signals)
	}()
	go func() {
		if sig, ok := <-signals; ok {
			restore()
			reraise(sig)
		}
	}()

	// Raw mode first, then the question: nothing typed after it is echoed.
	if _, err := io.WriteString(output, question); err != nil {
		return "", err
	}
	finish := func() {
		restore()
		_, _ = io.WriteString(output, "\n")
	}
	var typed HiddenInput
	var pending []byte // an incomplete UTF-8 sequence, kept for the next read (Node's StringDecoder)
	buf := make([]byte, 4096)
	for {
		n, readErr := input.Read(buf)
		if n > 0 {
			data := decodeChunk(&pending, buf[:n])
			for i := 0; i < len(data); i++ {
				if data[i] == 0x03 {
					finish()
					_, _ = io.WriteString(output, "varlatch: cancelled; nothing was stored\n")
					return "", Cancelled{}
				}
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
