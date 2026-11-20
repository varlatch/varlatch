// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
)

// prompter is prompt.ts's Prompter: questions on a terminal (ADR-0058
// Decision 2), a choice from a list, a yes/no, and a line of text. Never
// for a secret value: secretinput's hidden prompt is the only way to type
// one.
type prompter interface {
	// choose is select: the index of the chosen option; preselected answers
	// an empty line.
	choose(question string, options []string, preselected int) (int, error)
	confirm(question string, defaultYes bool) (bool, error)
	// text is a line of text; defaultValue ("" for none) answers an empty
	// line.
	text(question, defaultValue string) (string, error)
	// say is a line of output between questions.
	say(line string) error
}

// errInputEnded is the prompter's error when the input ends before an
// answer ("the input ended before an answer"; an Error, by name).
var errInputEnded = errors.New("the input ended before an answer")

// terminalPrompter is prompt.ts's terminalPrompter: questions written on
// stdout through the fail-safe (Run.out), answers read a line at a time
// from stdin, as readline reads them without a terminal (a line ends at
// \n, \r or \r\n; a last line without one ends at the end of the input),
// each trimmed. Lines typed ahead of a question wait for it.
type terminalPrompter struct {
	r     *Run
	in    *bufio.Reader
	ended bool
	// cr: the last line ended at \r, so a \n right after it ends nothing.
	cr bool
}

func newTerminalPrompter(r *Run) *terminalPrompter {
	return &terminalPrompter{r: r, in: bufio.NewReader(r.Stdin)}
}

// line is the next line, or errInputEnded.
func (p *terminalPrompter) line() (string, error) {
	if p.ended {
		return "", errInputEnded
	}
	var b strings.Builder
	for {
		c, err := p.in.ReadByte()
		if err != nil {
			p.ended = true
			if errors.Is(err, io.EOF) && b.Len() > 0 {
				return b.String(), nil
			}
			return "", errInputEnded
		}
		if c == '\n' && p.cr && b.Len() == 0 {
			p.cr = false
			continue
		}
		p.cr = false
		if c == '\n' || c == '\r' {
			p.cr = c == '\r'
			return b.String(), nil
		}
		b.WriteByte(c)
	}
}

// ask writes question and reads the answer, trimmed as String#trim trims.
func (p *terminalPrompter) ask(question string) (string, error) {
	if err := p.r.out(question); err != nil {
		return "", err
	}
	line, err := p.line()
	if err != nil {
		return "", err
	}
	return strings.TrimFunc(jsval.DecodeUTF8([]byte(line)), isJSWhitespace), nil
}

func (p *terminalPrompter) choose(question string, options []string, preselected int) (int, error) {
	for {
		if err := p.r.out(question + "\n"); err != nil {
			return 0, err
		}
		for i, option := range options {
			mark := ""
			if i == preselected {
				mark = "  (Enter)"
			}
			if err := p.r.out("  [" + strconv.Itoa(i+1) + "] " + option + mark + "\n"); err != nil {
				return 0, err
			}
		}
		answer, err := p.ask("Choice: ")
		if err != nil {
			return 0, err
		}
		if answer == "" {
			return preselected, nil
		}
		// Number(answer): "0x2", "+2", "2.0" and "1e0" count as numbers too.
		n, ok := jsval.ToNumber(jsval.UTF16(answer))
		if ok && n == math.Trunc(n) && !math.IsInf(n, 0) && n >= 1 && n <= float64(len(options)) {
			return int(n) - 1, nil
		}
		if err := p.r.out("Answer with a number from 1 to " + strconv.Itoa(len(options)) + ".\n"); err != nil {
			return 0, err
		}
	}
}

func (p *terminalPrompter) confirm(question string, defaultYes bool) (bool, error) {
	hint := "[y/N]"
	if defaultYes {
		hint = "[Y/n]"
	}
	for {
		answer, err := p.ask(question + " " + hint + " ")
		if err != nil {
			return false, err
		}
		switch jsLowerCase(answer) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		if err := p.r.out("Answer y or n.\n"); err != nil {
			return false, err
		}
	}
}

func (p *terminalPrompter) text(question, defaultValue string) (string, error) {
	shown := question + ": "
	if defaultValue != "" {
		shown = question + " [" + defaultValue + "]: "
	}
	answer, err := p.ask(shown)
	if err != nil {
		return "", err
	}
	if answer == "" {
		return defaultValue, nil
	}
	return answer, nil
}

func (p *terminalPrompter) say(line string) error { return p.r.out(line + "\n") }

// jsLowerCase is String#toLowerCase.
func jsLowerCase(s string) string { return strings.ToLower(s) }
