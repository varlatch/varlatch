// SPDX-License-Identifier: Apache-2.0

package secretinput

// HiddenInput is secretInput.ts's HiddenInput: the value typed into a
// hidden prompt from the terminal's input. Printable characters are kept,
// Backspace removes the last whole character, and other control
// characters and escape sequences (arrow and function keys) are ignored
// rather than stored.
type HiddenInput struct {
	value  string
	escape escapeState
}

type escapeState int

const (
	escNone escapeState = iota
	escStart
	escCSI
	escSS3
)

// Feed takes characters (text already decoded); it returns the value and
// true once Enter or Ctrl-D ends the input, false while it continues.
func (h *HiddenInput) Feed(data string) (string, bool) {
	for _, ch := range data {
		switch h.escape {
		case escStart:
			switch ch {
			case '[':
				h.escape = escCSI
			case 'O':
				h.escape = escSS3
			default:
				h.escape = escNone
			}
			continue
		case escCSI:
			// Parameters and intermediates, then one final byte from @ to ~.
			if ch >= '@' && ch <= '~' {
				h.escape = escNone
			}
			continue
		case escSS3:
			h.escape = escNone
			continue
		}
		switch {
		case ch == 0x1b:
			h.escape = escStart
		case ch == '\r' || ch == '\n' || ch == 0x04:
			return h.value, true
		case ch == 0x7f || ch == '\b':
			h.value = DropLastCharacter(h.value)
		case ch >= ' ':
			h.value += string(ch)
		}
	}
	return "", false
}

// DropLastCharacter is dropLastCharacter: value without its last
// user-perceived character, a whole extended grapheme cluster (an emoji, a
// letter with its combining marks) as Intl.Segmenter finds it, never half
// of one.
func DropLastCharacter(value string) string {
	return value[:lastClusterStart(value)]
}
