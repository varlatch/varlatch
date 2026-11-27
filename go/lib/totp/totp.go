// SPDX-License-Identifier: Apache-2.0

// Package totp is time-based one-time codes (RFC 6238, over RFC 4226's
// HOTP): a seed read from an otpauth:// URI, normalized, and the code of
// one of its time steps.
//
// A seed is a secret. Nothing here puts one, or any other part of the text
// it was read from, into an error; a Seed formats as "totp.Seed(hidden)"
// and refuses to be encoded as JSON. Only URI writes it out.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The bounds of what is accepted.
const (
	// MaxURIBytes is the longest otpauth:// URI read.
	MaxURIBytes = 4096
	// MinSecretBytes is the shortest secret accepted. RFC 4226 asks for 128
	// bits, and recommends 160, of who issues a secret; issuers that still
	// hand out 80 bits (16 base32 characters) are common, and whoever enrolls
	// cannot choose. Anything shorter can be found from a few observed codes.
	MinSecretBytes = 10
	// MaxSecretBytes is the longest: SHA-512's block, above which HMAC hashes
	// the key anyway.
	MaxSecretBytes = 128
	// MaxLabelRunes bounds the issuer and the account, each.
	MaxLabelRunes = 200
)

// Why a URI is not accepted. Fixed texts: none holds any of the URI.
var (
	ErrNotURI      = errors.New("not an otpauth:// URI")
	ErrTooLong     = fmt.Errorf("longer than %d bytes", MaxURIBytes)
	ErrHOTP        = errors.New("a counter-based code (otpauth://hotp) is not supported, only a time-based one (otpauth://totp)")
	ErrRepeated    = errors.New("a parameter of the otpauth URI is given twice")
	ErrNoSecret    = errors.New("the otpauth URI has no secret")
	ErrSecret      = errors.New("the secret of the otpauth URI is not base32 (RFC 4648: A to Z and 2 to 7)")
	ErrWeak        = fmt.Errorf("the secret of the otpauth URI is too weak: fewer than %d bits, or a single repeated byte", MinSecretBytes*8)
	ErrSecretLong  = fmt.Errorf("the secret of the otpauth URI is longer than %d bytes", MaxSecretBytes)
	ErrAlgorithm   = errors.New("the algorithm of the otpauth URI is not SHA1, SHA256 or SHA512")
	ErrDigits      = errors.New("the digits of the otpauth URI are not 6 or 8")
	ErrPeriod      = errors.New("the period of the otpauth URI is not 30 or 60 seconds")
	ErrEncoder     = errors.New("the otpauth URI asks for codes in another form than RFC 6238's digits, which is not supported")
	ErrLabel       = fmt.Errorf("the issuer and the account of the otpauth URI are at most %d characters each, without control characters, and the issuer without a colon", MaxLabelRunes)
	ErrSecretShown = errors.New("the issuer or the account of the otpauth URI holds its secret: those two are readable, so the URI is refused")
	ErrParams      = errors.New("not the parameters of a one-time code")
)

// Params is what people may read of a seed: whose code it is and how codes
// are made, never the secret.
type Params struct {
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Algorithm string `json:"algorithm"` // SHA1, SHA256 or SHA512
	Digits    int    `json:"digits"`    // 6 or 8
	Period    int64  `json:"period"`    // seconds: 30 or 60
}

// Check is whether p is what Parse can return.
func (p Params) Check() error {
	if _, ok := hashes[p.Algorithm]; !ok || p.Digits != 6 && p.Digits != 8 || p.Period != 30 && p.Period != 60 {
		return ErrParams
	}
	return checkLabel(p.Issuer, p.Account)
}

// Step is the time step t is in (RFC 6238's T, with T0 = 0).
func (p Params) Step(t time.Time) int64 {
	s := t.Unix()
	step := s / p.Period
	if s%p.Period < 0 {
		step--
	}
	return step
}

// Window is when step's code is the current one: from start, until before
// end.
func (p Params) Window(step int64) (start, end time.Time) {
	return time.Unix(step*p.Period, 0), time.Unix((step+1)*p.Period, 0)
}

// Seed is a parsed seed.
type Seed struct {
	Params
	secret *[]byte // a pointer, so formatting a struct that holds a Seed shows an address
}

const hidden = "totp.Seed(hidden)"

func (Seed) String() string               { return hidden }
func (Seed) GoString() string             { return hidden }
func (Seed) MarshalJSON() ([]byte, error) { return nil, errors.New("totp: a seed is not encoded") }

var hashes = map[string]func() hash.Hash{"SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New}

var base32Plain = base32.StdEncoding.WithPadding(base32.NoPadding)

// Parse reads an otpauth:// URI
// (https://github.com/google/google-authenticator/wiki/Key-Uri-Format),
// normalized: defaults filled in (SHA1, 6 digits, 30 seconds), the secret's
// blanks, hyphens, padding and case removed, the issuer taken from its
// parameter before the label. Parameters it does not know (such as image)
// are left out.
func Parse(text string) (Seed, error) {
	text = strings.TrimSpace(text)
	if len(text) > MaxURIBytes {
		return Seed{}, ErrTooLong
	}
	u, err := url.Parse(text) // its error holds the text: not returned
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth") || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return Seed{}, ErrNotURI
	}
	switch strings.ToLower(u.Host) {
	case "totp":
	case "hotp":
		return Seed{}, ErrHOTP
	default:
		return Seed{}, ErrNotURI
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Seed{}, ErrNotURI
	}
	given := map[string]string{}
	for name, values := range query {
		name = strings.ToLower(name)
		if _, twice := given[name]; twice || len(values) > 1 {
			return Seed{}, ErrRepeated
		}
		given[name] = values[0]
	}
	if _, ok := given["encoder"]; ok { // Steam's letters
		return Seed{}, ErrEncoder
	}
	p := Params{Algorithm: "SHA1", Digits: 6, Period: 30}
	label := strings.TrimPrefix(u.Path, "/")
	p.Account = strings.TrimSpace(label)
	if issuer, account, ok := strings.Cut(label, ":"); ok {
		p.Issuer, p.Account = strings.TrimSpace(issuer), strings.TrimSpace(account)
	}
	if issuer := strings.TrimSpace(given["issuer"]); issuer != "" {
		p.Issuer = issuer
	}
	if err := checkLabel(p.Issuer, p.Account); err != nil {
		return Seed{}, err
	}
	if v, ok := given["algorithm"]; ok {
		p.Algorithm = strings.ReplaceAll(strings.ToUpper(v), "-", "")
		if _, known := hashes[p.Algorithm]; !known {
			return Seed{}, ErrAlgorithm
		}
	}
	if v, ok := given["digits"]; ok {
		if v != "6" && v != "8" {
			return Seed{}, ErrDigits
		}
		p.Digits, _ = strconv.Atoi(v)
	}
	if v, ok := given["period"]; ok {
		if v != "30" && v != "60" {
			return Seed{}, ErrPeriod
		}
		p.Period, _ = strconv.ParseInt(v, 10, 64)
	}
	secret, err := decodeSecret(given["secret"])
	if err != nil {
		return Seed{}, err
	}
	s := Seed{Params: p, secret: &secret}
	if s.shown() {
		return Seed{}, ErrSecretShown
	}
	return s, nil
}

// squeeze is text as base32 reads it: upper case, without blanks and
// hyphens (as secrets are printed for typing).
func squeeze(text string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, strings.ToUpper(text))
}

func decodeSecret(text string) ([]byte, error) {
	text = strings.TrimRight(squeeze(text), "=")
	if text == "" {
		return nil, ErrNoSecret
	}
	for i := 0; i < len(text); i++ {
		// encoding/base32 ignores line ends, and its errors hold positions.
		if c := text[i]; (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return nil, ErrSecret
		}
	}
	b, err := base32Plain.DecodeString(text)
	if err != nil || base32Plain.EncodedLen(len(b)) != len(text) {
		return nil, ErrSecret
	}
	switch {
	case len(b) < MinSecretBytes || repeated(b):
		return nil, ErrWeak
	case len(b) > MaxSecretBytes:
		return nil, ErrSecretLong
	}
	return b, nil
}

func repeated(b []byte) bool {
	for _, c := range b {
		if c != b[0] {
			return false
		}
	}
	return true
}

// checkLabel is whether an issuer and an account may be shown, and read
// back from the URI this package writes as the same two.
func checkLabel(issuer, account string) error {
	for _, s := range []string{issuer, account} {
		if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxLabelRunes || s != strings.TrimSpace(s) {
			return ErrLabel
		}
		for _, r := range s {
			switch {
			case unicode.IsControl(r), r == '\u2028', r == '\u2029', r == utf8.RuneError, r == '\ufeff',
				r == '\u061c', r == '\u200e', r == '\u200f', r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069':
				return ErrLabel // what could misrepresent the text around it
			}
		}
	}
	if strings.Contains(issuer, ":") || issuer == "" && strings.Contains(account, ":") {
		return ErrLabel
	}
	return nil
}

// shown is whether the readable part holds the secret, as base32 reads it.
func (s Seed) shown() bool {
	secret := base32Plain.EncodeToString(*s.secret)
	return strings.Contains(squeeze(s.Issuer), secret) || strings.Contains(squeeze(s.Account), secret)
}

// URI is the seed as a normalized otpauth:// URI, every parameter written:
// the seed itself, for the one place it is stored or revealed from.
func (s Seed) URI() string {
	label := url.PathEscape(s.Account)
	query := "secret=" + base32Plain.EncodeToString(*s.secret)
	if s.Issuer != "" {
		label = url.PathEscape(s.Issuer) + ":" + label
		query += "&issuer=" + strings.ReplaceAll(url.QueryEscape(s.Issuer), "+", "%20")
	}
	return "otpauth://totp/" + label + "?" + query + "&algorithm=" + s.Algorithm +
		"&digits=" + strconv.Itoa(s.Digits) + "&period=" + strconv.FormatInt(s.Period, 10)
}

// Code is the code of a time step: RFC 4226's HOTP of it, with the seed's
// hash.
func (s Seed) Code(step int64) string {
	m := hmac.New(hashes[s.Algorithm], *s.secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	m.Write(counter[:])
	sum := m.Sum(nil)
	at := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[at:at+4]) & 0x7fffffff
	modulus := uint32(1_000_000)
	if s.Digits == 8 {
		modulus = 100_000_000
	}
	return fmt.Sprintf("%0*d", s.Digits, n%modulus)
}

// Clear overwrites the secret; the Seed makes no codes of use after it.
func (s Seed) Clear() {
	if s.secret != nil {
		clear(*s.secret)
	}
}
