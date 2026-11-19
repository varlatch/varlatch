// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"regexp"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The TypeScript CLI walks the skill directories in the file system's
// order: sorted on Linux and macOS, NTFS's case-insensitive order on
// Windows (references/ before SKILL.md), and the Go CLI walks them the same
// way. A case recorded on Linux and replayed on Windows therefore lists the
// skill's files in another order; such a case compares them as a multiset
// (go/README.md, `skill-order`): each run of consecutive skill-file entries
// is sorted before the comparison, nothing added or dropped. A case
// recorded on Windows is compared exactly.

// skillFile matches a path, or a line, that names one of the skill's files.
var skillFile = regexp.MustCompile(`\.(agents|claude)[/\\]skills[/\\]varlatch[/\\]`)

// SortSkillRuns returns items with each maximal run of consecutive items
// that name a skill file (named(item)) sorted by key(item), byte order.
func SortSkillRuns[T any](items []T, named func(T) bool, key func(T) string) []T {
	out := slices.Clone(items)
	for i := 0; i < len(out); {
		if !named(out[i]) {
			i++
			continue
		}
		j := i
		for j < len(out) && named(out[j]) {
			j++
		}
		slices.SortStableFunc(out[i:j], func(a, b T) int { return strings.Compare(key(a), key(b)) })
		i = j
	}
	return out
}

// NamesSkillFile reports whether a path or a line names a skill file.
func NamesSkillFile(s string) bool { return skillFile.MatchString(s) }

// SkillOrderFree is text with the skill's files in sorted runs: in a JSON
// document exactly as JSON.stringify(doc, null, 2) and a newline write it,
// each run of consecutive "changes" entries whose path names a skill file
// (sorted by path); in any other text, each run of consecutive lines that
// name one. Everything else keeps its bytes and its place.
func SkillOrderFree(text string) string {
	if strings.HasPrefix(text, "{") {
		if doc, err := jsjson.Parse([]byte(text)); err == nil && string(jsjson.StringifyIndent(doc, 2))+"\n" == text {
			return string(jsjson.StringifyIndent(sortChanges(doc), 2)) + "\n"
		}
	}
	lines := strings.Split(text, "\n")
	return strings.Join(SortSkillRuns(lines, NamesSkillFile, func(l string) string { return l }), "\n")
}

// sortChanges sorts the skill-file runs of every "changes" array in v.
func sortChanges(v any) any {
	switch t := v.(type) {
	case jsjson.Object:
		out := make(jsjson.Object, len(t))
		for i, m := range t {
			value := sortChanges(m.Value)
			if list, ok := value.([]any); ok && m.Key == "changes" {
				value = SortSkillChanges(list)
			}
			out[i] = jsjson.Member{Key: m.Key, Value: value}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sortChanges(e)
		}
		return out
	}
	return v
}

// SortSkillChanges is a changes list with each run of consecutive entries
// whose path names a skill file sorted by path.
func SortSkillChanges(list []any) []any {
	return SortSkillRuns(list, func(e any) bool { return NamesSkillFile(changePath(e)) }, changePath)
}

// changePath is a change's "path", or "".
func changePath(e any) string {
	if o, ok := e.(jsjson.Object); ok {
		if p, ok := o.Value("path").(string); ok {
			return p
		}
	}
	return ""
}
