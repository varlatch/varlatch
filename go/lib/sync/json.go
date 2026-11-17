// SPDX-License-Identifier: Apache-2.0

package sync

import "github.com/varlatch/varlatch/go/lib/jsjson"

// The adapters read platform answers and write request bodies as the
// TypeScript adapters do with JSON.parse and JSON.stringify. The reader and
// writer are lib/jsjson's, which the CLI shares; these names keep the
// adapters' code as it was.

// Member is one property of an Object.
type Member = jsjson.Member

// Object is a JSON object with its properties in JavaScript's order.
type Object = jsjson.Object

var errSyntax = jsjson.ErrSyntax

func parseJSON(text []byte) (any, error) { return jsjson.Parse(text) }
func stringify(v any) []byte             { return jsjson.Stringify(v) }
func jsNumber(x float64) string          { return jsjson.Number(x) }
func jsString(v any) string              { return jsjson.String(v) }
func truthy(v any) bool                  { return jsjson.Truthy(v) }
func isRecord(v any) bool                { return jsjson.IsRecord(v) }
func appendWTF8(b []byte, r rune) []byte { return jsjson.AppendWTF8(b, r) }
func surrogateAt(s string, i int) (rune, bool) {
	return jsjson.SurrogateAt(s, i)
}

// hasKey is "key in o" for an own property.
func hasKey(o Object, key string) bool {
	_, ok := o.Get(key)
	return ok
}
