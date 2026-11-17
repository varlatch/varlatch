// SPDX-License-Identifier: Apache-2.0

package clientctx

import "testing"

func TestMaskUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"not a url":                  "not a url",
		"https://a.example/team":     "https://a.example/team",
		"http://u:p@h:1/x@y":         "http://[redacted]@h:1/x@y",
		"u:p@h":                      "[redacted]@h",
		"http://a@b@c?d@e":           "http://[redacted]@c?d@e",
		"http://h/path@x":            "http://h/path@x",
		"@h":                         "@h",
		"https://:secret@[::1/v1/me": "https://[redacted]@[::1/v1/me",
	} {
		if got := MaskUserinfo(in); got != want {
			t.Errorf("MaskUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskUserinfoInText(t *testing.T) {
	in := "3:  server = \"https://u:p@a@h.example/x@y\" # and http://k@h2\n"
	want := "3:  server = \"https://[redacted]@h.example/x@y\" # and http://[redacted]@h2\n"
	if got := MaskUserinfoInText(in); got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if plain := "server = \"https://h.example\" # mail@example.com"; MaskUserinfoInText(plain) != plain {
		t.Errorf("changed text with no URL credentials: %q", MaskUserinfoInText(plain))
	}
}
