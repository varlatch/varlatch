// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// BaselineFile is BASELINE_FILE, the baseline's name in the project
// directory.
const BaselineFile = "varlatch-scan-baseline.json"

// BaselineError is a baseline that cannot be read; its message is
// BaselineError's.
type BaselineError struct{ Message string }

func (e *BaselineError) Error() string { return e.Message }

// SyntaxPrefix starts the message of a baseline that is not JSON:
// "not valid JSON (<what JSON.parse says>)". What follows it is Go's
// wording, not V8's (go/README.md, `baseline-json-syntax`).
const SyntaxPrefix = "not valid JSON ("

// ParseBaseline is parseBaseline: a baseline file's bytes, read as
// readFileSync(path, "utf8") reads them. It holds path, item name and
// version ID per entry and nothing else: any other field is refused, so
// nothing derived from a value can be kept in it.
func ParseBaseline(raw []byte) ([]BaselineEntry, error) {
	text := jsval.DecodeUTF8(raw)
	var doc any
	var err error
	if strings.HasPrefix(text, "\ufeff") {
		// readFileSync keeps a byte order mark, and JSON.parse refuses it.
		err = jsjson.ErrSyntax
	} else {
		doc, err = jsjson.Parse([]byte(text))
	}
	if err != nil {
		what := "Unexpected token in JSON"
		if strings.TrimFunc(text, jsval.IsWhitespace) == "" {
			what = "Unexpected end of JSON input"
		}
		return nil, &BaselineError{SyntaxPrefix + what + ")"}
	}
	obj, ok := doc.(jsjson.Object)
	if !ok {
		return nil, &BaselineError{"expected an object"}
	}
	if keysOf(obj) != "entries,version" {
		return nil, &BaselineError{`expected exactly the fields "version" and "entries"`}
	}
	if v := obj.Value("version"); v != float64(1) {
		return nil, &BaselineError{"unsupported version " + string(jsjson.Stringify(v)) + "; this CLI reads version 1"}
	}
	entries, ok := obj.Value("entries").([]any)
	if !ok {
		return nil, &BaselineError{`"entries" must be an array`}
	}
	out := []BaselineEntry{}
	for i, raw := range entries {
		n := strconv.Itoa(i + 1)
		entry, ok := raw.(jsjson.Object)
		if !ok {
			return nil, &BaselineError{"entry " + n + " must be an object"}
		}
		if keysOf(entry) != "item,path,versionId" {
			return nil, &BaselineError{"entry " + n + ` must have exactly "path", "item", and "versionId"`}
		}
		path, p := entry.Value("path").(string)
		item, it := entry.Value("item").(string)
		versionID, v := entry.Value("versionId").(string)
		if !p || path == "" || !it || item == "" || !v || versionID == "" {
			return nil, &BaselineError{"entry " + n + `: "path", "item", and "versionId" must be non-empty strings`}
		}
		out = append(out, BaselineEntry{path, item, versionID})
	}
	return out, nil
}

// keysOf is Object.keys(o).sort().join(",").
func keysOf(o jsjson.Object) string {
	keys := make([]string, len(o))
	for i, m := range o {
		keys[i] = m.Key
	}
	slices.SortStableFunc(keys, jsval.CompareUTF16)
	return strings.Join(keys, ",")
}

// FormatBaseline is formatBaseline: the baseline file's text, entries
// deduplicated and sorted (by path, item, then version ID, as JavaScript
// compares strings).
func FormatBaseline(entries []BaselineEntry) string {
	var unique []BaselineEntry
	seen := map[BaselineEntry]bool{}
	for _, e := range entries {
		if !seen[e] {
			seen[e] = true
			unique = append(unique, e)
		}
	}
	slices.SortStableFunc(unique, func(a, b BaselineEntry) int {
		if c := jsval.CompareUTF16(a.Path, b.Path); c != 0 {
			return c
		}
		if c := jsval.CompareUTF16(a.Item, b.Item); c != 0 {
			return c
		}
		return jsval.CompareUTF16(a.VersionID, b.VersionID)
	})
	list := []any{}
	for _, e := range unique {
		list = append(list, jsjson.Object{{Key: "path", Value: e.Path}, {Key: "item", Value: e.Item}, {Key: "versionId", Value: e.VersionID}})
	}
	return string(jsjson.StringifyIndent(jsjson.Object{{Key: "version", Value: float64(1)}, {Key: "entries", Value: list}}, 2)) + "\n"
}
