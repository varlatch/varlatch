// SPDX-License-Identifier: AGPL-3.0-or-later

package entry

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/varlatch/varlatch/go/server/domainerr"
)

// MaxDescription is how long a description may be, in code points.
const MaxDescription = 280

// maxMarks is how many combining marks may follow one another.
const maxMarks = 3

var (
	// scheme is a URL's beginning, with or without a host.
	scheme = regexp.MustCompile(`:\s*/\s*/|\bwww\b|\b(?:https?|ftp|mailto|javascript|data|file|tel|sms|vbscript|blob)\s*:`)
	// host is a dotted name whose last label is letters (or an A-label): a
	// name people, and mail clients, read as an address. "e.g." and "v1.2"
	// are none. A space after the dot makes it the end of a sentence.
	host = regexp.MustCompile(`[\p{L}\p{N}](?:[\p{L}\p{N}_-]*)\.(?:xn--[a-z0-9-]+|\p{L}{2,})`)
	// ipv4 is an address in digits.
	ipv4 = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	// address is an email address, or a name at a host.
	address = regexp.MustCompile(`\S@\S`)
	dots    = strings.NewReplacer("\u3002", ".", "\uff0e", ".", "\uff61", ".", "\u2024", ".", "\u2022", ".", "\u2219", ".", "\u2027", ".", "\u2e33", ".", "\ua78f", ".", "\u0660", ".", "\u06d4", ".")
)

func notPlain(why string) error {
	return domainerr.New("VALIDATION_FAILED", "description: "+why)
}

// CheckDescription is the caller's words as the page shows them: one line of
// plain text, with nothing in it that a person could take for a place to go
// (a link, a host, an address) or that could change how the text around it
// reads (markup, control, format and bidirectional characters, blank
// look-alikes). It returns the text as it is stored. The page shows it as
// text all the same: this is against words, not against scripts.
func CheckDescription(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", notPlain("not valid text")
	}
	s := strings.TrimSpace(norm.NFC.String(raw))
	if s == "" {
		return "", notPlain("empty")
	}
	if utf8.RuneCountInString(s) > MaxDescription {
		return "", notPlain("at most 280 characters")
	}
	marks := 0
	for _, r := range s {
		// IsPrint leaves the plain space alone of all spaces, and no control,
		// format, surrogate, private-use or unassigned character.
		if !unicode.IsPrint(r) {
			return "", notPlain("one line of plain text, without control or invisible characters")
		}
		// Letters that show as nothing.
		if strings.ContainsRune("\u115f\u1160\u3164\uffa0\u2800", r) || unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
			return "", notPlain("one line of plain text, without control or invisible characters")
		}
		if r == '<' || r == '>' {
			return "", notPlain("plain text, without < or >")
		}
		if unicode.Is(unicode.M, r) {
			if marks++; marks > maxMarks {
				return "", notPlain("too many combining marks")
			}
			continue
		}
		marks = 0
	}
	// As a person reads it: full-width letters, dots of other scripts.
	read := dots.Replace(strings.ToLower(norm.NFKC.String(dots.Replace(s))))
	if scheme.MatchString(read) || host.MatchString(read) || ipv4.MatchString(read) || address.MatchString(read) {
		return "", notPlain("no links, host names or addresses: the page shows none but Varlatch's own")
	}
	return s, nil
}
