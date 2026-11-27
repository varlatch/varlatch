// SPDX-License-Identifier: Apache-2.0

package totp

import (
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func encoded(secret string) string { return base32.StdEncoding.EncodeToString([]byte(secret)) }

func mustParse(t testing.TB, uri string) Seed {
	t.Helper()
	s, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// RFC 6238, appendix B, with the secrets of its reference implementation
// (20, 32 and 64 bytes) and 8 digits; its 6-digit codes are the last six of
// the same number, and with a 60-second period the step is half.
func TestRFC6238Vectors(t *testing.T) {
	digits := strings.Repeat("1234567890", 7)
	secret := map[string]string{"SHA1": digits[:20], "SHA256": digits[:32], "SHA512": digits[:64]}
	for _, v := range []struct {
		unix                 int64
		step                 int64
		sha1, sha256, sha512 string
	}{
		{59, 0x1, "94287082", "46119246", "90693936"},
		{1111111109, 0x23523EC, "07081804", "68084774", "25091201"},
		{1111111111, 0x23523ED, "14050471", "67062674", "99943326"},
		{1234567890, 0x273EF07, "89005924", "91819424", "93441116"},
		{2000000000, 0x3F940AA, "69279037", "90698825", "38618901"},
		{20000000000, 0x27BC86AA, "65353130", "77737706", "47863826"},
	} {
		for algorithm, want := range map[string]string{"SHA1": v.sha1, "SHA256": v.sha256, "SHA512": v.sha512} {
			for _, n := range []int{8, 6} {
				for _, period := range []int64{30, 60} {
					s := mustParse(t, fmt.Sprintf("otpauth://totp/x?secret=%s&algorithm=%s&digits=%d&period=%d", encoded(secret[algorithm]), algorithm, n, period))
					at := time.Unix(v.unix*period/30, 0)
					if step := s.Step(at); step != v.step {
						t.Errorf("%s at %d: step %x, want %x", algorithm, v.unix, step, v.step)
					}
					if got := s.Code(s.Step(at)); got != want[8-n:] {
						t.Errorf("%s at %d, %d digits, %d s: %s, want %s", algorithm, v.unix, n, period, got, want[8-n:])
					}
				}
			}
		}
	}
}

// RFC 4226, appendix D: HOTP of counters 0 to 9.
func TestRFC4226Vectors(t *testing.T) {
	s := mustParse(t, "otpauth://totp/x?secret="+encoded("12345678901234567890"))
	for counter, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := s.Code(int64(counter)); got != want {
			t.Errorf("counter %d: %s, want %s", counter, got, want)
		}
	}
}

// A period's first instant is in it and its end is in the next one, down to
// the nanosecond, before 1970 too.
func TestPeriodBoundaries(t *testing.T) {
	for _, period := range []int64{30, 60} {
		p := Params{Algorithm: "SHA1", Digits: 6, Period: period}
		for _, step := range []int64{-2, -1, 0, 1, 58817400} {
			start, end := p.Window(step)
			if end.Sub(start) != time.Duration(period)*time.Second {
				t.Fatalf("step %d lasts %s", step, end.Sub(start))
			}
			for at, want := range map[time.Time]int64{
				start.Add(-time.Nanosecond): step - 1, start: step, start.Add(time.Nanosecond): step,
				end.Add(-time.Nanosecond): step, end: step + 1,
			} {
				// Unix floors, so a time before 1970 with a fraction is in its second.
				if got := p.Step(at); got != want {
					t.Errorf("period %d, %s: step %d, want %d", period, at, got, want)
				}
			}
		}
	}
}

const sixteen = "JBSWY3DPEHPK3PXP" // 80 bits

func TestParse(t *testing.T) {
	for uri, want := range map[string]string{
		"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example": "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
		// Case, blanks, hyphens, padding; a trailing line end.
		"  OTPAUTH://TOTP/bob?SECRET=jbsw%20y3dp-ehpk+3pxp%3D%3D&Digits=8&PERIOD=60&algorithm=sha-256\n": "otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60",
		// The issuer's parameter comes before the label's; blanks after the colon.
		"otpauth://totp/Old%20Name:%20alice?secret=JBSWY3DPEHPK3PXP&issuer=New%20Name&image=https%3A%2F%2Fx.example": "otpauth://totp/New%20Name:alice?secret=JBSWY3DPEHPK3PXP&issuer=New%20Name&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp/Big+Corp%3Aalice%2Fadmin?secret=JBSWY3DPEHPK3PXP&issuer=Big+Corp":                            "otpauth://totp/Big%20Corp:alice%2Fadmin?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corp&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp/?secret=JBSWY3DPEHPK3PXP":                                                                    "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp?secret=JBSWY3DPEHPK3PXP":                                                                     "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp/a:b:c?secret=JBSWY3DPEHPK3PXP":                                                               "otpauth://totp/a:b:c?secret=JBSWY3DPEHPK3PXP&issuer=a&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp/%C3%9Cber:z%C3%BC?secret=JBSWY3DPEHPK3PXP&counter=1":                                         "otpauth://totp/%C3%9Cber:z%C3%BC?secret=JBSWY3DPEHPK3PXP&issuer=%C3%9Cber&algorithm=SHA1&digits=6&period=30",
	} {
		s, err := Parse(uri)
		if err != nil {
			t.Errorf("%s: %v", uri, err)
			continue
		}
		if got := s.URI(); got != want {
			t.Errorf("%s:\n got %s\nwant %s", uri, got, want)
		}
		if err := s.Params.Check(); err != nil {
			t.Errorf("%s: its parameters: %v", uri, err)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	const q = "otpauth://totp/x?secret=" + sixteen
	for uri, want := range map[string]error{
		"":                                       ErrNotURI,
		sixteen:                                  ErrNotURI, // a bare secret
		"https://x":                              ErrNotURI,
		"otpauth:totp/x?secret=" + sixteen:       ErrNotURI,
		"otpauth://other/x?secret=" + sixteen:    ErrNotURI,
		"otpauth://u:p@totp/x?secret=" + sixteen: ErrNotURI,
		"otpauth://totp/x?secret=%zz":            ErrNotURI,
		"otpauth://totp/%zz?secret=" + sixteen:   ErrNotURI,
		q + "#fragment":                          ErrNotURI,
		q + ";issuer=x":                          ErrNotURI,
		"otpauth://hotp/x?counter=1&secret=" + sixteen:           ErrHOTP,
		q + strings.Repeat("x", MaxURIBytes):                     ErrTooLong,
		q + "&secret=" + sixteen:                                 ErrRepeated,
		q + "&Secret=" + sixteen:                                 ErrRepeated,
		q + "&digits=6&digits=8":                                 ErrRepeated,
		q + "&encoder=steam":                                     ErrEncoder,
		"otpauth://totp/x":                                       ErrNoSecret,
		"otpauth://totp/x?secret=":                               ErrNoSecret,
		"otpauth://totp/x?secret=%20-=":                          ErrNoSecret,
		"otpauth://totp/x?secret=JBSWJBSWJBSWJBS1":               ErrSecret,
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP%0AA%21":        ErrSecret,
		"otpauth://totp/x?secret=" + sixteen + "A":               ErrSecret, // no length of whole bytes
		"otpauth://totp/x?secret=JBSW=Y3DPEHPK3PXP":              ErrSecret,
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PÄP":               ErrSecret,
		"otpauth://totp/x?secret=JBSWY3DPEHPK3P":                 ErrSecret,
		"otpauth://totp/x?secret=JBSWY3DPEHPK3":                  ErrWeak, // 8 bytes
		"otpauth://totp/x?secret=" + strings.Repeat("A", 32):     ErrWeak, // all zero
		"otpauth://totp/x?secret=" + strings.Repeat("7", 32):     ErrWeak, // all 0xff
		"otpauth://totp/x?secret=" + strings.Repeat(sixteen, 13): ErrSecretLong,
		q + "&algorithm=MD5":                                     ErrAlgorithm,
		q + "&algorithm=":                                        ErrAlgorithm,
		q + "&digits=7":                                          ErrDigits,
		q + "&digits=06":                                         ErrDigits,
		q + "&digits=%206":                                       ErrDigits,
		q + "&period=0":                                          ErrPeriod,
		q + "&period=-30":                                        ErrPeriod,
		q + "&period=45":                                         ErrPeriod,
		q + "&issuer=a%3Ab":                                      ErrLabel,
		q + "&issuer=a%00b":                                      ErrLabel,
		q + "&issuer=a%E2%80%AEb":                                ErrLabel,
		q + "&issuer=%FF":                                        ErrLabel,
		q + "&issuer=" + strings.Repeat("x", MaxLabelRunes+1):    ErrLabel,
		"otpauth://totp/:a:b?secret=" + sixteen:                  ErrLabel,
		"otpauth://totp/x%0Ay?secret=" + sixteen:                 ErrLabel,
		q + "&issuer=" + sixteen:                                 ErrSecretShown,
		"otpauth://totp/jbsw%20y3dp-ehpk3pxp?secret=" + sixteen:  ErrSecretShown,
	} {
		_, err := Parse(uri)
		if !errors.Is(err, want) {
			t.Errorf("%q: %v, want %v", uri, err, want)
		}
	}
}

// No error holds any of the text it refuses.
func TestErrorsHoldNothingOfTheURI(t *testing.T) {
	const mark = "QZJXQZJXQZJXQZJX"
	for _, uri := range []string{
		mark, "otpauth://totp/x?secret=" + mark + "1", "otpauth://totp/" + mark + "%zz", "otpauth://" + mark, "otpauth://totp/x?" + mark + "=%zz",
		"otpauth://totp/x?secret=" + mark + "&algorithm=" + mark, "otpauth://totp/x?secret=" + mark + "&digits=" + mark,
		"otpauth://totp/x?secret=" + mark + "&period=" + mark, "otpauth://totp/" + mark + ":x?issuer=" + mark + "&secret=" + mark,
		"otpauth://hotp/" + mark, "otpauth://totp/x?secret=" + mark + "&secret=" + mark, "otpauth://totp/x\x7f" + mark, mark + "://x",
	} {
		if _, err := Parse(uri); err == nil {
			t.Errorf("%q: accepted", uri)
		} else if strings.Contains(strings.ToUpper(err.Error()), mark) {
			t.Errorf("the error holds the URI: %v", err)
		}
	}
}

// A parsed seed, however it is formatted or encoded, does not show its
// secret.
func TestASeedIsNotFormatted(t *testing.T) {
	s := mustParse(t, "otpauth://totp/x?secret="+sixteen)
	wrapped := struct{ inner Seed }{s}
	for _, shown := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q", s, s, s, s, s), fmt.Sprintf("%v %+v %#v", wrapped, wrapped, wrapped)} {
		if strings.Contains(shown, sixteen) || strings.Contains(shown, "Hello") || strings.Contains(shown, "72 101 108") || strings.Contains(shown, "0x48, 0x65") {
			t.Errorf("shown: %s", shown)
		}
	}
	if b, err := json.Marshal(map[string]any{"seed": s}); err == nil {
		t.Errorf("encoded: %s", b)
	}
	s.Clear()
	if strings.Contains(s.URI(), sixteen) {
		t.Error("cleared, and still there")
	}
}

// text is an issuer or an account of any shape Parse takes.
func text(r *rand.Rand, colons bool) string {
	const some = "abcXYZ019 .@/?&=#%+-_äß日🙂${}\"'<>\\|"
	runes := []rune(some)
	if colons {
		runes = append(runes, ':')
	}
	var b strings.Builder
	for range r.Intn(12) {
		b.WriteRune(runes[r.Intn(len(runes))])
	}
	return strings.TrimSpace(b.String())
}

// Any seed of accepted parts, written in any accepted way, reads back as
// itself, and what URI writes reads back as the same URI.
func TestParseRoundTrips(t *testing.T) {
	property := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		secret := make([]byte, MinSecretBytes+r.Intn(MaxSecretBytes-MinSecretBytes+1))
		r.Read(secret)
		p := Params{Issuer: text(r, false), Algorithm: []string{"SHA1", "SHA256", "SHA512"}[r.Intn(3)], Digits: []int{6, 8}[r.Intn(2)], Period: []int64{30, 60}[r.Intn(2)]}
		p.Account = text(r, p.Issuer != "")
		if p.Issuer != "" {
			p.Account = strings.TrimSpace(p.Account)
		}
		shown := base32Plain.EncodeToString(secret)
		if r.Intn(2) == 0 {
			shown = strings.ToLower(shown)
		}
		if r.Intn(2) == 0 {
			shown = shown[:4] + " " + shown[4:8] + "-" + shown[8:]
		}
		label := url.PathEscape(p.Account)
		if p.Issuer != "" {
			label = url.PathEscape(p.Issuer) + []string{":", "%3A", "%3a%20"}[r.Intn(3)] + label
		}
		parts := []string{"secret=" + url.QueryEscape(shown), "algorithm=" + strings.ToLower(p.Algorithm), fmt.Sprintf("digits=%d", p.Digits), fmt.Sprintf("period=%d", p.Period), "unknown=1"}
		if p.Issuer != "" && r.Intn(2) == 0 {
			parts = append(parts, "issuer="+url.QueryEscape(p.Issuer))
		}
		r.Shuffle(len(parts), func(i, j int) { parts[i], parts[j] = parts[j], parts[i] })
		s, err := Parse("otpauth://totp/" + label + "?" + strings.Join(parts, "&"))
		if err != nil || s.Params != p || string(*s.secret) != string(secret) {
			t.Logf("%d: %+v, %v; want %+v", seed, s.Params, err, p)
			return false
		}
		again, err := Parse(s.URI())
		return err == nil && again.Params == p && again.URI() == s.URI() && again.Code(7) == s.Code(7)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 5000}); err != nil {
		t.Error(err)
	}
}

// Whatever the text, Parse refuses it with one of its own errors, or
// returns what reads back as itself.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"", "otpauth://totp/x?secret=" + sixteen, "otpauth://totp/a:b?secret=jbsw%20y3dp&issuer=%zz", "otpauth://hotp/x"} {
		f.Add(s)
	}
	known := []error{ErrNotURI, ErrTooLong, ErrHOTP, ErrRepeated, ErrNoSecret, ErrSecret, ErrWeak, ErrSecretLong, ErrAlgorithm, ErrDigits, ErrPeriod, ErrEncoder, ErrLabel, ErrSecretShown}
	f.Fuzz(func(t *testing.T, uri string) {
		s, err := Parse(uri)
		if err != nil {
			for _, k := range known {
				if err == k { //nolint:errorlint // the very error: nothing wraps the text
					return
				}
			}
			t.Fatalf("an error of another kind: %v", err)
		}
		if err := s.Params.Check(); err != nil {
			t.Fatalf("%q: %v", uri, err)
		}
		again, err := Parse(s.URI())
		if err != nil || again.URI() != s.URI() || again.Params != s.Params {
			t.Fatalf("%q: %q reads back as %v, %v", uri, s.URI(), again.Params, err)
		}
		if len(s.Code(s.Step(time.Unix(1, 0)))) != s.Digits {
			t.Fatal("a code of another length")
		}
	})
}
