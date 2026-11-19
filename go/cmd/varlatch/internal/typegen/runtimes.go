// SPDX-License-Identifier: Apache-2.0

package typegen

import (
	_ "embed"
	"encoding/json"
)

// The Typed Accessor runtimes the TypeScript CLI embeds, byte for byte
// (internal docs/design/go-cli.md, decision 7): copied into embedded/ by
// embed-runtimes.mjs from the packages' own build scripts, and checked by
// go.yml's "Generated code is current" step, which fails when a copy is
// stale.
//
//go:generate node embed-runtimes.mjs

// accessorRuntimeSource is ACCESSOR_RUNTIME_SOURCE (@varlatch/accessor):
// one function declaration that returns the runtime's exports.
//
//go:embed embedded/accessor-runtime.js.txt
var accessorRuntimeSource string

// pythonRuntimeSource is PYTHON_RUNTIME_SOURCE (@varlatch/accessor-python).
//
//go:embed embedded/python-runtime.py.txt
var pythonRuntimeSource string

//go:embed embedded/runtimes.json
var runtimesJSON []byte

// runtimeFacts are what the TypeScript generators import beside the
// runtime text, read from the runtimes themselves by embed-runtimes.mjs.
type runtimeFacts struct {
	// AccessorRuntimeName is ACCESSOR_RUNTIME_NAME, the function
	// accessorRuntimeSource declares.
	AccessorRuntimeName string `json:"accessorRuntimeName"`
	// SchemaFormat is the accessor's SCHEMA_FORMAT.
	SchemaFormat int `json:"schemaFormat"`
	// TypeScriptSemanticsVersions is implementedSemanticsVersions().
	TypeScriptSemanticsVersions []int `json:"typescriptSemanticsVersions"`
	// PythonSemanticsVersions is PYTHON_IMPLEMENTED_SEMANTICS_VERSIONS.
	PythonSemanticsVersions []int `json:"pythonSemanticsVersions"`
}

var runtimes = func() runtimeFacts {
	var f runtimeFacts
	if err := json.Unmarshal(runtimesJSON, &f); err != nil || f.AccessorRuntimeName == "" || len(f.TypeScriptSemanticsVersions) == 0 || len(f.PythonSemanticsVersions) == 0 {
		panic("typegen: embedded/runtimes.json is not what embed-runtimes.mjs writes")
	}
	return f
}()
