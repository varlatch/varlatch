// SPDX-License-Identifier: Apache-2.0

package release

import "strings"

// ValidVersion is whether version is a release version, as a tag names it
// without its v (1.2.3, 1.2.3-rc.1): versionPattern, no leading zeros.
func ValidVersion(version string) bool { return versionPattern.MatchString(version) }

// Prerelease is whether a release version has a pre-release suffix
// (0.50.0-rc.1).
func Prerelease(version string) bool { return strings.Contains(version, "-") }

// CompareVersions orders two release versions by Semantic Versioning's
// precedence: -1, 0 or 1 as a is lower, equal or higher. A pre-release is
// lower than its release; pre-release identifiers compare numerically when
// both are numbers, a number below a word, and a longer list above its
// prefix. ok is false when either is not a release version.
func CompareVersions(a, b string) (order int, ok bool) {
	if !ValidVersion(a) || !ValidVersion(b) {
		return 0, false
	}
	aCore, aPre, _ := strings.Cut(a, "-")
	bCore, bPre, _ := strings.Cut(b, "-")
	ac, bc := strings.Split(aCore, "."), strings.Split(bCore, ".")
	for i := range 3 {
		if c := compareNumbers(ac[i], bc[i]); c != 0 {
			return c, true
		}
	}
	switch {
	case aPre == "" && bPre == "":
		return 0, true
	case aPre == "":
		return 1, true
	case bPre == "":
		return -1, true
	}
	ap, bp := strings.Split(aPre, "."), strings.Split(bPre, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		an, aNum := number(ap[i])
		bn, bNum := number(bp[i])
		var c int
		switch {
		case aNum && bNum:
			c = compareNumbers(an, bn)
		case aNum:
			c = -1
		case bNum:
			c = 1
		default:
			c = strings.Compare(ap[i], bp[i])
		}
		if c != 0 {
			return c, true
		}
	}
	return compareInts(len(ap), len(bp)), true
}

// number is s without leading zeros when it is all digits.
func number(s string) (string, bool) {
	if strings.Trim(s, "0123456789") != "" {
		return s, false
	}
	t := strings.TrimLeft(s, "0")
	if t == "" {
		t = "0"
	}
	return t, true
}

// compareNumbers orders two decimal numbers without leading zeros, of any
// length.
func compareNumbers(a, b string) int {
	if c := compareInts(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func compareInts(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
