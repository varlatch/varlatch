// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
)

// The BEK seal both ways (services/varlatchd/test/go-backup-vectors.test.ts):
// archives the TypeScript server sealed open here, and the manifests have
// zod's verdicts; TestGoVectors writes archives that the TypeScript server
// then opens (go.yml, go-binary job).

var writeGoVectors = flag.String("write-go-vectors", "", "write archives sealed by this code to this file")

type archiveVector struct {
	Name string `json:"name"`
	BEK  struct {
		Kind     string `json:"kind"`
		Material string `json:"material"`
	} `json:"bek"`
	RootKEK    string            `json:"rootKek"`
	Archive    string            `json:"archive"`
	Manifest   json.RawMessage   `json:"manifest"`
	Components map[string]string `json:"components"`
}

type vectors struct {
	Comment   string          `json:"comment"`
	Archives  []archiveVector `json:"archives"`
	Manifests []struct {
		Name  string `json:"name"`
		JSON  string `json:"json"`
		Valid bool   `json:"valid"`
	} `json:"manifests"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (a archiveVector) bek(t *testing.T) BEK {
	t.Helper()
	var b BEK
	var err error
	if a.BEK.Kind == "key" {
		key, _ := hex.DecodeString(a.BEK.Material)
		b, err = KeyBEK(key)
	} else {
		b, err = PassphraseBEK([]byte(a.BEK.Material))
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTSVectors(t *testing.T) {
	v := readVectors(t)
	if len(v.Archives) < 3 || len(v.Manifests) < 30 {
		t.Fatalf("%d archives, %d manifests: incomplete", len(v.Archives), len(v.Manifests))
	}
	for _, a := range v.Archives {
		dir := t.TempDir()
		path := filepath.Join(dir, "archive")
		data, _ := base64.StdEncoding.DecodeString(a.Archive)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		o, err := Open(path, a.bek(t), dir)
		if err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
		want, _ := ParseManifest(a.Manifest)
		if o.Manifest.ArchiveID != want.ArchiveID || o.Manifest.FormatVersion != FormatTSSecretPlane {
			t.Errorf("%s: manifest %+v", a.Name, o.Manifest)
		}
		for name, b64 := range a.Components {
			got, _ := os.ReadFile(o.Path(name))
			if base64.StdEncoding.EncodeToString(got) != b64 {
				t.Errorf("%s: %s differs", a.Name, name)
			}
		}
		root, _ := hex.DecodeString(a.RootKEK)
		if !CheckKeys(o.Manifest, map[int][]byte{1: root}) {
			t.Errorf("%s: its Root KEK does not open the canary", a.Name)
		}
		_ = o.Close()
		data[len(data)-20] ^= 1
		_ = os.WriteFile(path, data, 0o600)
		if _, err := Open(path, a.bek(t), dir); err != ErrIntegrity {
			t.Errorf("%s: a changed byte: %v", a.Name, err)
		}
	}
	for _, m := range v.Manifests {
		_, err := ParseManifest([]byte(m.JSON))
		if (err == nil) != m.Valid {
			t.Errorf("%s: parsed %v, zod says valid %v", m.Name, err, m.Valid)
		}
	}
}

// TestGoVectors writes archives sealed by this code, with format-2
// manifests the TypeScript schema accepts, for the TypeScript server to
// open; without the flag it only seals and opens them here.
func TestGoVectors(t *testing.T) {
	template := readVectors(t).Archives[0].Manifest
	out := vectors{Comment: "Written by go/lib/backup TestGoVectors with the Go code; do not edit."}
	for _, tc := range []struct {
		name, kind string
		size       int
	}{{"a key file BEK", "key", 70_001}, {"a passphrase BEK", "passphrase", 5}, {"an empty component", "passphrase", 0}} {
		dir := t.TempDir()
		data := make([]byte, tc.size)
		rand.Read(data)
		component := filepath.Join(dir, "secret-plane.dump")
		if err := os.WriteFile(component, data, 0o600); err != nil {
			t.Fatal(err)
		}
		root := envelope.GenerateKey()
		canary, err := envelope.NewCanary(root, "inst_vectors")
		if err != nil {
			t.Fatal(err)
		}
		described, err := Describe("secret-plane.dump", component)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(template, &m); err != nil {
			t.Fatal(err)
		}
		id := make([]byte, 16)
		rand.Read(id)
		id[6], id[8] = id[6]&0x0f|0x40, id[8]&0x3f|0x80
		m["archiveId"] = fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
		m["installationId"] = "inst_vectors"
		m["canaries"] = []any{CanaryOf(1, canary)}
		m["components"] = []any{described}
		manifest, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var a archiveVector
		a.Name, a.BEK.Kind, a.RootKEK = tc.name, tc.kind, hex.EncodeToString(root)
		if tc.kind == "key" {
			key := make([]byte, 32)
			rand.Read(key)
			a.BEK.Material = hex.EncodeToString(key)
		} else {
			a.BEK.Material = "a passphrase for " + tc.name
		}
		path := filepath.Join(dir, "archive")
		if err := Seal(path, manifest, []string{component}, a.bek(t), SealOptions{}); err != nil {
			t.Fatal(err)
		}
		sealed, _ := os.ReadFile(path)
		a.Archive = base64.StdEncoding.EncodeToString(sealed)
		a.Manifest = manifest
		a.Components = map[string]string{"secret-plane.dump": base64.StdEncoding.EncodeToString(data)}
		o, err := Open(path, a.bek(t), dir)
		if err != nil || !bytes.Equal(o.ManifestJSON, manifest) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = o.Close()
		out.Archives = append(out.Archives, a)
	}
	if *writeGoVectors != "" {
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(*writeGoVectors, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
