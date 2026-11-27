// SPDX-License-Identifier: AGPL-3.0-or-later

package entry

import (
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func TestDescriptions(t *testing.T) {
	for _, s := range []string{
		"The key of the model provider's account.",
		"API key, e.g. from your account's settings (read-only, v1.2 or later)",
		"Clé de l'API: voir vos paramètres. Merci !",
		"モデルのAPIキー", "Ключ для отчётов", "مفتاح الواجهة", "مفاتيح ٢٠٢٦", "किराया", "Naïve café", "50 % & more; 3 < is refused"[:13], "🔑 key",
		"Password for the portal. Use the one of the robot account.",
		"col·lecció", "Costs 1.500 a month", "Version 1.2.3",
	} {
		if got, err := CheckDescription(s); err != nil || got == "" {
			t.Errorf("%q: %v", s, err)
		}
	}
	for what, list := range map[string][]string{
		"links": {
			"see https://evil.example/login", "HTTP://X", "hxxp://x", "go to evil.example", "www evil", "www.evil", "evil.com", "Evil.COM now", "xn--e1afmkfd.xn--p1ai", "a.xn--p1ai",
			"пример.рф", "例え.テスト", "evil。com", "evil．com", "evil｡com", "ｅｖｉｌ．ｃｏｍ", "evil․com", "evil․com", "ｈｔｔｐｓ：／／ｘ",
			"mailto:someone", "javascript:alert(1)", "tel:+32", "data:text/html", "a@b", "someone@evil.example", "10.0.0.1", "call 192.168.1.1:80", "x :// y", "file: x", "evil.example.", "(evil.com)",
		},
		"markup":    {"<b>x</b>", "a > b", "<script>", "＜b＞ or <b>"},
		"invisible": {"", "   ", "two\nlines", "a\tb", "a\rb", "a\u0000b", "a\u202eb", "a\u2066b", "a\u200bb", "a\u00a0b", "a\u2028b", "a\u3000b", "a\ufeffb", "a\u00adb", "a\u2800b", "a\u3164b", "a\u115fb", "a\ufe0fb", "a\U000e0041b", "a\ue000b", "a\uffffb", "\x1b[31m", "bad \xff utf-8", "a\xed\xa0\x80b"},
		"marks":     {"e\u0301\u0301\u0301\u0301\u0301", "z" + strings.Repeat("\u0336", 9)},
		"long":      {strings.Repeat("x", 281), strings.Repeat("é", 281)},
	} {
		for _, s := range list {
			if got, err := CheckDescription(s); err == nil {
				t.Errorf("%s: %q is taken as %q", what, s, got)
			} else if strings.Contains(err.Error(), "evil") {
				t.Errorf("%s: %v repeats it", what, err)
			}
		}
	}
	if got, _ := CheckDescription("  cafe\u0301 "); got != "café" {
		t.Errorf("%q", got)
	}
	if _, err := CheckDescription(strings.Repeat("é", 280)); err != nil {
		t.Error(err)
	}
}

// Whatever is taken shows as one line of printable text with no < or >, the
// same when checked again, and with nothing that reads as a scheme.
func FuzzDescription(f *testing.F) {
	for _, s := range []string{"plain words", "e.g. v1.2", "https://x", "evil。com", "a\u202eb", "e\u0301", "＜b＞", "ﬀ.ﬁ", "a\u0345.b", "İ.İİ", "x：／／y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := CheckDescription(s)
		if err != nil {
			return
		}
		again, err := CheckDescription(got)
		if err != nil || again != got {
			t.Fatalf("%q: %q, then %q %v", s, got, again, err)
		}
		if utf8.RuneCountInString(got) > MaxDescription || strings.ContainsAny(got, "<>\n\r\t") || strings.Contains(got, "://") {
			t.Fatalf("%q", got)
		}
		for _, r := range got {
			if !unicode.IsPrint(r) {
				t.Fatalf("%q holds %U", got, r)
			}
		}
	})
}

func TestTheLimiterForgets(t *testing.T) {
	var l limiter
	now := time.Unix(1_800_000_000, 0)
	for i := range maxUnknown {
		if l.blocked("a", now) > 0 {
			t.Fatalf("blocked after %d", i)
		}
		l.unknown("a", now)
	}
	if l.blocked("a", now) <= 0 || l.blocked("b", now) > 0 {
		t.Error("the twentieth")
	}
	if l.blocked("a", now.Add(unknownWindow)) > 0 {
		t.Error("blocked past the window")
	}
	for i := range maxAddresses + 10 {
		l.unknown(string(rune('0'+i%10))+strings.Repeat("x", i/10), now)
	}
	if len(l.by) > maxAddresses {
		t.Errorf("%d addresses", len(l.by))
	}
	l.unknown("new", now.Add(2*unknownWindow))
	if len(l.by) != 1 {
		t.Errorf("%d addresses kept", len(l.by))
	}
}
