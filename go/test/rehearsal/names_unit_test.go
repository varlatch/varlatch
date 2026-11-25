// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"slices"
	"strings"
	"testing"
)

func TestNamesOfTheCopy(t *testing.T) {
	defer func(of, left map[string]bool) { copyNames.of, copyNames.left = of, left }(copyNames.of, copyNames.left)
	copyNames.of, copyNames.left = nil, nil
	host := "hooks." + "quuxley" + ".example"
	addNames([]string{"Quuxley " + "Works", "https://" + host + "/x?y", "production", "Dev", "", "run 17", "zqx" + "j", "someone@" + host})
	var got []string
	for n := range copyNames.of {
		got = append(got, n)
	}
	slices.Sort(got)
	if want := []string{host, "quuxley " + "works", "someone@" + host, "zqx" + "j"}; !slices.Equal(got, want) {
		t.Errorf("names %q, want %q", got, want)
	}
	if !copyNames.left["production"] || !copyNames.left["run 17"] {
		t.Errorf("left %v", copyNames.left)
	}
	for _, c := range []struct {
		text, name string
		want       bool
	}{
		{"an organization abcd, read", "abcd", true}, {"abcde", "abcd", false}, {"xabcd abcd", "abcd", true}, {`{"name":"abcd"}`, "abcd", true},
		{"abcd", "abcd", true}, {"abcd.example", "abcd", true}, {"", "abcd", false}, {"_abcd", "abcd", false},
	} {
		if got := named(c.text, c.name); got != c.want {
			t.Errorf("named(%q, %q) = %v", c.text, c.name, got)
		}
	}
	if !strings.Contains(strings.Join(nameColumns, "\n"), "organizations") || !ownWords()["varlatch"] {
		t.Error("the harness's own words")
	}
}
