// SPDX-License-Identifier: Apache-2.0

package clientctx

import "testing"

func TestHasUserinfo(t *testing.T) {
	for server, want := range map[string]bool{
		"https://u:PW@host.example":             true,
		"https://u@host.example":                true,
		"https://:PW@host.example":              true,
		"https://[redacted]@host.example":       true,
		"https://[redacted]:x@host.example":     true,
		"https://u%40x:PW%3A@host.example/base": true,
		`https:\\u:PW@host.example`:             true,
		"https:u:PW@host.example":               true,
		"varlatch+https://u:PW@host.example":    true,
		"https://u:PW@":                         true, // does not parse; holds "@"
		"not a url @ all":                       true,
		"https://host.example":                  false,
		"https://host.example/a@b?c=@#@":        false,
		"https://:@host.example":                false, // new URL gives no user name and no password
		"http://127.0.0.1:8080":                 false,
		"not a url":                             false,
		"":                                      false,
	} {
		if got := HasUserinfo(server); got != want {
			t.Errorf("HasUserinfo(%q) = %v, want %v", server, got, want)
		}
	}
}
