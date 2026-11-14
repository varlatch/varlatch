// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web is the dashboard varlatchd embeds (ADR-0059 Decision 1;
// varlatchd-core decision 8).
//
// `go generate ./server/web` (build/) builds apps/web with the pinned Node
// and pnpm and stages the output in dist/, with a record of what it was
// built from (dist/.build.json: the sources' hash, see inputs, and the
// commit). dist/ is not committed. Without a build, varlatchd serves a
// placeholder page in its place, so `go build` works in a clean checkout.
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"path"
	"strings"
)

//go:generate go run ./build

//go:embed all:dist
var dist embed.FS

//go:embed placeholder
var placeholder embed.FS

// BuildFile is the record of the build in dist/, never served.
const BuildFile = ".build.json"

// Build is what the generator records about the dashboard it staged.
type Build struct {
	// Inputs is inputs.Hash of the sources it was built from.
	Inputs string `json:"inputs"`
	// Commit is the checkout's commit (git rev-parse HEAD), and Clean
	// whether the sources had no change against it; empty and false where
	// git was not available.
	Commit string `json:"commit"`
	Clean  bool   `json:"clean"`
	// Node and Pnpm are the versions that built it.
	Node string `json:"node"`
	Pnpm string `json:"pnpm"`
}

// Embedded returns the record of the embedded build; false when this
// varlatchd embeds the placeholder.
func Embedded() (Build, bool) {
	b, err := dist.ReadFile("dist/" + BuildFile)
	if err != nil {
		return Build{}, false
	}
	var out Build
	if json.Unmarshal(b, &out) != nil {
		return Build{}, false
	}
	return out, true
}

// FS returns the dashboard to serve: index.html at its root and the files
// it loads. Files whose names start with a dot (the build record,
// .gitkeep) are not part of it.
func FS() fs.FS {
	if _, ok := Embedded(); ok {
		if sub, err := fs.Sub(dist, "dist"); err == nil {
			if _, err := fs.Stat(sub, "index.html"); err == nil {
				return hidden{sub}
			}
		}
	}
	sub, err := fs.Sub(placeholder, "placeholder")
	if err != nil {
		panic(err)
	}
	return hidden{sub}
}

// hidden leaves out every path with a segment that starts with a dot.
type hidden struct{ fs.FS }

func (h hidden) Open(name string) (fs.File, error) {
	for _, seg := range strings.Split(path.Clean(name), "/") {
		if strings.HasPrefix(seg, ".") && seg != "." {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
	}
	return h.FS.Open(name)
}
