// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
)

// update rewrites testdata/go-sealed.json; writeGoFixture writes a fresh
// one elsewhere, which CI hands to the TypeScript code (node
// testdata/tsfixtures.mjs verify <file>), so it always checks what this
// code seals now.
var (
	update         = flag.Bool("update", false, "rewrite testdata/go-sealed.json")
	writeGoFixture = flag.String("write-go-fixture", "", "write a freshly sealed Go fixture to this path")
)

// The TypeScript fixtures (tsfixtures.mjs generate --ref v<release>), oldest
// first: envelopes every listed release sealed must keep opening in Go.
// tsLatest also supplies the vectors and the shape of go-sealed.json.
var tsFixtures = []string{"testdata/ts-v0.21.0.json", tsLatest}

const tsLatest = "testdata/ts-v0.22.0.json"

// fixture is the shape tsfixtures.mjs writes, and go-sealed.json too.
type fixture struct {
	Comment        string     `json:"comment"`
	Ref            string     `json:"ref"`
	RootKEK        string     `json:"rootKek"`
	InstallationID string     `json:"installationId"`
	Canary         Envelope   `json:"canary"`
	Organizations  []org      `json:"organizations"`
	JWTSigningKeys []jwtKey   `json:"jwtSigningKeys"`
	Canonical      []canonVec `json:"canonical"`
	KEKMaterial    []struct {
		Input string  `json:"input"`
		Key   *string `json:"key"`
	} `json:"kekMaterial,omitempty"`
	NodeBase64 []struct {
		Input json.RawMessage `json:"input"` // may hold lone surrogates
		Hex   string          `json:"hex"`
	} `json:"nodeBase64,omitempty"`
	LooseEnvelopes []struct {
		Name      string   `json:"name"`
		Envelope  Envelope `json:"envelope"`
		Plaintext string   `json:"plaintext"`
	} `json:"looseEnvelopes,omitempty"`
	JSTrimCodeUnits []uint16 `json:"jsTrimCodeUnits,omitempty"`
}

type org struct {
	OrganizationID string   `json:"organizationId"`
	OrgKEK         string   `json:"orgKek"`
	WrappedOrgKEK  Envelope `json:"wrappedOrgKek"`
	Values         []struct {
		SecretID   string   `json:"secretId"`
		VersionID  string   `json:"versionId"`
		Plaintext  string   `json:"plaintext"`
		Payload    Envelope `json:"payload"`
		WrappedDEK Envelope `json:"wrappedDek"`
	} `json:"values"`
	Webhooks []struct {
		WebhookID string   `json:"webhookId"`
		Secret    string   `json:"secret"`
		Envelope  Envelope `json:"envelope"`
	} `json:"webhooks"`
	Connections []struct {
		ConnectionID string   `json:"connectionId"`
		Credential   string   `json:"credential"`
		Envelope     Envelope `json:"envelope"`
	} `json:"connections"`
	GitHubApps []struct {
		GitHubAppID   string   `json:"githubAppId"`
		PrivateKeyPEM string   `json:"privateKeyPem"`
		Envelope      Envelope `json:"envelope"`
	} `json:"githubApps"`
	// Since 0.22.0 (ADR-0056): Envelope under the org KEK, DrainEnvelope
	// under the Root KEK.
	AuditExports []struct {
		ExportID      string   `json:"exportId"`
		Credential    string   `json:"credential"`
		Envelope      Envelope `json:"envelope"`
		DrainEnvelope Envelope `json:"drainEnvelope"`
	} `json:"auditExports,omitempty"`
}

type jwtKey struct {
	KeyID         string   `json:"keyId"`
	PrivateKeyPEM string   `json:"privateKeyPem"`
	Envelope      Envelope `json:"envelope"`
}

type canonVec struct {
	Value     any    `json:"value"`
	Canonical string `json:"canonical"`
}

func load(t *testing.T, path string) fixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // integers in canonical vectors stay exact
	var f fixture
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	return f
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// openAll opens every envelope of a fixture and checks every plaintext.
func openAll(t *testing.T, f fixture) {
	t.Helper()
	root := unhex(t, f.RootKEK)
	if !VerifyCanary(root, f.Canary, f.InstallationID) {
		t.Fatal("canary does not open")
	}
	if VerifyCanary(GenerateKey(), f.Canary, f.InstallationID) || VerifyCanary(root, f.Canary, "ins_other") {
		t.Fatal("canary opened with a wrong key or installation")
	}
	n := 0
	for _, o := range f.Organizations {
		orgKEK, err := UnwrapOrgKEK(root, o.WrappedOrgKEK, o.OrganizationID)
		if err != nil || !bytes.Equal(orgKEK, unhex(t, o.OrgKEK)) {
			t.Fatalf("org KEK %s: %v", o.OrganizationID, err)
		}
		for _, v := range o.Values {
			got, err := DecryptValue(orgKEK, o.OrganizationID, v.SecretID, v.VersionID, EncryptedValue{Payload: v.Payload, WrappedDEK: v.WrappedDEK})
			if err != nil || !bytes.Equal(got, unb64(t, v.Plaintext)) {
				t.Fatalf("value %s: %v", v.SecretID, err)
			}
			n++
		}
		for _, w := range o.Webhooks {
			got, err := Open(orgKEK, w.Envelope, WebhookSecretContext(o.OrganizationID, w.WebhookID))
			if err != nil || string(got) != w.Secret {
				t.Fatalf("webhook %s: %v", w.WebhookID, err)
			}
			n++
		}
		for _, c := range o.Connections {
			got, err := Open(orgKEK, c.Envelope, PlatformCredentialContext(o.OrganizationID, c.ConnectionID))
			if err != nil || string(got) != c.Credential {
				t.Fatalf("connection %s: %v", c.ConnectionID, err)
			}
			n++
		}
		for _, g := range o.GitHubApps {
			got, err := Open(orgKEK, g.Envelope, GitHubAppKeyContext(o.OrganizationID, g.GitHubAppID))
			if err != nil || string(got) != g.PrivateKeyPEM {
				t.Fatalf("GitHub App %s: %v", g.GitHubAppID, err)
			}
			n++
		}
		for _, a := range o.AuditExports {
			got, err := Open(orgKEK, a.Envelope, AuditExportCredentialContext(o.OrganizationID, a.ExportID))
			if err != nil || string(got) != a.Credential {
				t.Fatalf("audit export %s: %v", a.ExportID, err)
			}
			got, err = Open(root, a.DrainEnvelope, AuditExportDrainContext(o.OrganizationID, a.ExportID))
			if err != nil || string(got) != a.Credential {
				t.Fatalf("audit export drain %s: %v", a.ExportID, err)
			}
			n += 2
		}
	}
	for _, k := range f.JWTSigningKeys {
		got, err := Open(root, k.Envelope, JWTSigningKeyContext(k.KeyID))
		if err != nil || string(got) != k.PrivateKeyPEM {
			t.Fatalf("JWT key %s: %v", k.KeyID, err)
		}
		n++
	}
	for _, l := range f.LooseEnvelopes {
		got, err := Open(root, l.Envelope, KEKCanaryContext(f.InstallationID))
		if err != nil || !bytes.Equal(got, unb64(t, l.Plaintext)) {
			t.Fatalf("loose envelope %q: %v", l.Name, err)
		}
		n++
	}
	if n < 15 {
		t.Fatalf("only %d envelopes checked", n)
	}
}

// Envelopes the TypeScript server sealed open in Go, from every release
// with a fixture.
func TestTypeScriptFixtures(t *testing.T) {
	for _, path := range tsFixtures {
		t.Run(path, func(t *testing.T) { openAll(t, load(t, path)) })
	}
	// The latest release seals every purpose Go knows.
	for _, o := range load(t, tsLatest).Organizations {
		if len(o.AuditExports) == 0 {
			t.Fatalf("%s: organization %s has no audit export envelopes", tsLatest, o.OrganizationID)
		}
	}
}

// The AAD encoding matches the TypeScript canonicalJson byte for byte.
func TestCanonicalJSONMatchesTypeScript(t *testing.T) {
	f := load(t, tsLatest)
	if len(f.Canonical) < 5 {
		t.Fatal("no canonical vectors")
	}
	for _, c := range f.Canonical {
		got, err := CanonicalJSON(c.Value)
		if err != nil || got != c.Canonical {
			t.Errorf("got %q, %v\nwant %q", got, err, c.Canonical)
		}
	}
	for _, bad := range []any{1.5, float64(1 << 60), int64(1 << 60), json.Number("1e400"), []byte("x"), "\xff", map[string]any{"a": struct{}{}}} {
		if s, err := CanonicalJSON(bad); err == nil {
			t.Errorf("%#v encoded as %q", bad, s)
		}
	}
}

// Root KEK material parses as Node parses it, and the trim set is Node's.
func TestParseRootKEKMatchesTypeScript(t *testing.T) {
	f := load(t, tsLatest)
	if len(f.KEKMaterial) < 20 {
		t.Fatal("no KEK vectors")
	}
	for _, v := range f.KEKMaterial {
		key, err := ParseRootKEK(v.Input)
		switch {
		case v.Key == nil && err == nil:
			t.Errorf("%q: parsed, Node refused it", v.Input)
		case v.Key != nil && (err != nil || hex.EncodeToString(key) != *v.Key):
			t.Errorf("%q: got %x, %v; want %s", v.Input, key, err, *v.Key)
		}
		if err != nil && strings.Contains(err.Error(), strings.TrimSpace(v.Input)) && strings.TrimSpace(v.Input) != "" {
			t.Errorf("the error echoes the material: %v", err)
		}
	}
	if len(f.NodeBase64) < 20 {
		t.Fatal("no base64 vectors")
	}
	for _, v := range f.NodeBase64 {
		units, ok := jsonStringUnits(v.Input)
		if !ok {
			t.Fatalf("vector %s is not a JSON string", v.Input)
		}
		if got := hex.EncodeToString(nodeBase64Units(units)); got != v.Hex {
			t.Errorf("base64 %s: got %s, want %s", v.Input, got, v.Hex)
		}
	}
	var set []uint16
	for u := range jsTrimSet {
		set = append(set, u)
	}
	slices.Sort(set)
	if !slices.Equal(set, f.JSTrimCodeUnits) {
		t.Fatalf("trim set %x, Node's %x", set, f.JSTrimCodeUnits)
	}
}

// writeGoFixture seals the same kind of hierarchy in Go, for the TypeScript
// code to open.
func sealGoFixture(t *testing.T, path string) {
	t.Helper()
	ts := load(t, tsLatest)
	root := GenerateKey()
	f := fixture{
		Comment:        "Written by the Go tests (go test ./lib/envelope -update); tsfixtures.mjs verify opens it with the TypeScript code.",
		RootKEK:        hex.EncodeToString(root),
		InstallationID: ts.InstallationID,
	}
	var err error
	if f.Canary, err = NewCanary(root, f.InstallationID); err != nil {
		t.Fatal(err)
	}
	for _, src := range ts.Organizations {
		orgKEK, wrapped, err := WrapOrgKEK(root, src.OrganizationID)
		if err != nil {
			t.Fatal(err)
		}
		o := src
		o.OrgKEK, o.WrappedOrgKEK = hex.EncodeToString(orgKEK), wrapped
		for i, v := range o.Values {
			enc, err := EncryptValue(orgKEK, o.OrganizationID, v.SecretID, v.VersionID, unb64(t, v.Plaintext))
			if err != nil {
				t.Fatal(err)
			}
			o.Values[i].Payload, o.Values[i].WrappedDEK = enc.Payload, enc.WrappedDEK
		}
		for i, w := range o.Webhooks {
			o.Webhooks[i].Envelope = must(Seal(orgKEK, []byte(w.Secret), WebhookSecretContext(o.OrganizationID, w.WebhookID)))
		}
		for i, c := range o.Connections {
			o.Connections[i].Envelope = must(Seal(orgKEK, []byte(c.Credential), PlatformCredentialContext(o.OrganizationID, c.ConnectionID)))
		}
		for i, g := range o.GitHubApps {
			o.GitHubApps[i].Envelope = must(Seal(orgKEK, []byte(g.PrivateKeyPEM), GitHubAppKeyContext(o.OrganizationID, g.GitHubAppID)))
		}
		for i, a := range o.AuditExports {
			o.AuditExports[i].Envelope = must(Seal(orgKEK, []byte(a.Credential), AuditExportCredentialContext(o.OrganizationID, a.ExportID)))
			o.AuditExports[i].DrainEnvelope = must(Seal(root, []byte(a.Credential), AuditExportDrainContext(o.OrganizationID, a.ExportID)))
		}
		f.Organizations = append(f.Organizations, o)
	}
	for _, k := range ts.JWTSigningKeys {
		k.Envelope = must(Seal(root, []byte(k.PrivateKeyPEM), JWTSigningKeyContext(k.KeyID)))
		f.JWTSigningKeys = append(f.JWTSigningKeys, k)
	}
	for _, c := range ts.Canonical {
		s, err := CanonicalJSON(c.Value)
		if err != nil {
			t.Fatal(err)
		}
		f.Canonical = append(f.Canonical, canonVec{Value: c.Value, Canonical: s})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func must(e Envelope, err error) Envelope {
	if err != nil {
		panic(err)
	}
	return e
}

// Envelopes Go sealed open in Go; the TypeScript side of this check is
// tsfixtures.mjs verify, which CI runs on the same file.
func TestGoFixtures(t *testing.T) {
	if *update {
		sealGoFixture(t, "testdata/go-sealed.json")
	}
	if *writeGoFixture != "" {
		sealGoFixture(t, *writeGoFixture)
		openAll(t, load(t, *writeGoFixture))
	}
	openAll(t, load(t, "testdata/go-sealed.json"))
}

// An envelope read from JSON and written back is re-encoded in standard
// base64 and still opens: decoding normalizes Node's lenient forms.
func TestLooseEnvelopesRoundTrip(t *testing.T) {
	f := load(t, tsLatest)
	root := unhex(t, f.RootKEK)
	if len(f.LooseEnvelopes) < 4 {
		t.Fatal("no loose envelopes")
	}
	for _, l := range f.LooseEnvelopes {
		data, err := json.Marshal(l.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		var back Envelope
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatal(err)
		}
		if back != l.Envelope || strings.ContainsAny(back.Nonce+back.Ciphertext+back.AuthTag, "-_ \n$") {
			t.Fatalf("%s: not normalized: %+v", l.Name, back)
		}
		if _, err := Open(root, back, KEKCanaryContext(f.InstallationID)); err != nil {
			t.Fatalf("%s: %v", l.Name, err)
		}
	}
}

// Field names match exactly, as JavaScript property lookups do; the last
// of duplicate keys wins, as in JSON.parse.
func TestEnvelopeFieldNamesAreExact(t *testing.T) {
	key := GenerateKey()
	ctx := OrgKEKContext("org_a")
	env, _ := Seal(key, []byte("x"), ctx)
	doc := func(fields ...string) []byte { return []byte("{" + strings.Join(fields, ",") + "}") }
	fv := `"formatVersion":1`
	alg := `"algorithm":"aes-256-gcm"`
	nonce := `"nonce":"` + env.Nonce + `"`
	ct := `"ciphertext":"` + env.Ciphertext + `"`
	tag := `"authTag":"` + env.AuthTag + `"`
	for name, tc := range map[string]struct {
		data  []byte
		opens bool
	}{
		"exact":                          {doc(fv, alg, nonce, ct, tag), true},
		"FORMATVERSION only":             {doc(`"FORMATVERSION":1`, alg, nonce, ct, tag), false},
		"Nonce only":                     {doc(fv, alg, `"Nonce":"`+env.Nonce+`"`, ct, tag), false},
		"exact and a wrong case variant": {doc(fv, `"FormatVersion":2`, alg, nonce, `"NONCE":"AAAA"`, ct, tag), true},
		"duplicate, last wins":           {doc(`"formatVersion":2`, fv, alg, nonce, ct, tag), true},
		"duplicate, last is wrong":       {doc(fv, `"formatVersion":2`, alg, nonce, ct, tag), false},
		"nonce not a string":             {doc(fv, alg, `"nonce":12`, ct, tag), false},
	} {
		var e Envelope
		if err := json.Unmarshal(tc.data, &e); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := Open(key, e, ctx); (err == nil) != tc.opens {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSealOpen(t *testing.T) {
	key := GenerateKey()
	ctx := ValueContext("org_a", "val_b", "ver_c")
	for _, pt := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte{7}, 100_000)} {
		env, err := Seal(key, pt, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(unb64(t, env.Nonce)) != nonceSize || len(unb64(t, env.AuthTag)) != tagSize || len(unb64(t, env.Ciphertext)) != len(pt) {
			t.Fatalf("envelope shape %+v", env)
		}
		got, err := Open(key, env, ctx)
		if err != nil || !bytes.Equal(got, pt) || got == nil {
			t.Fatalf("open: %v", err)
		}
		// A JSON round trip keeps it openable, with the TypeScript field order.
		data, _ := json.Marshal(env)
		if !strings.HasPrefix(string(data), `{"formatVersion":1,"algorithm":"aes-256-gcm","nonce":`) {
			t.Fatalf("JSON %s", data)
		}
		var back Envelope
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(key, back, ctx); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := Seal(key, []byte("same"), ctx)
	b, _ := Seal(key, []byte("same"), ctx)
	if a.Nonce == b.Nonce {
		t.Fatal("nonces repeat")
	}
}

// A ciphertext opens only under its own key and its own context: no purpose
// or identifier can stand in for another.
func TestWrongKeyOrContext(t *testing.T) {
	key := GenerateKey()
	contexts := []Context{
		OrgKEKContext("org_a"), DEKContext("org_a", "val_b", "ver_c"), ValueContext("org_a", "val_b", "ver_c"),
		WebhookSecretContext("org_a", "whk_b"), PlatformCredentialContext("org_a", "pcn_b"), GitHubAppKeyContext("org_a", "gha_b"),
		AuditExportCredentialContext("org_a", "aex_b"), AuditExportDrainContext("org_a", "aex_b"), AuditExportCredentialContext("org_a", "aex_x"),
		KEKCanaryContext("ins_a"), JWTSigningKeyContext("key_a"),
		ValueContext("org_x", "val_b", "ver_c"), ValueContext("org_a", "val_x", "ver_c"), ValueContext("org_a", "val_b", "ver_x"),
		DEKContext("org_a", "ver_c", "val_b"), // identifiers swapped
	}
	for i, c := range contexts {
		env, err := Seal(key, []byte("secret"), c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Open(GenerateKey(), env, c); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("wrong key: %v", err)
		}
		for j, other := range contexts {
			if _, err := Open(key, env, other); (err == nil) != (i == j) {
				t.Fatalf("sealed for %v, opened for %v: %v", c, other, err)
			}
		}
	}
	if _, err := Seal(key, nil, Context{"organizationId": "org_a"}); err == nil {
		t.Fatal("sealed without a purpose")
	}
	if _, err := Seal(key[:16], nil, OrgKEKContext("org_a")); !errors.Is(err, ErrKeySize) {
		t.Fatalf("short key: %v", err)
	}
}

func TestTamperedAndMalformed(t *testing.T) {
	key := GenerateKey()
	ctx := OrgKEKContext("org_a")
	env, _ := Seal(key, []byte("0123456789abcdef"), ctx)
	flip := func(s string) string {
		b := unb64(t, s)
		b[0] ^= 1
		return base64.StdEncoding.EncodeToString(b)
	}
	for name, e := range map[string]Envelope{
		"ciphertext": {FormatVersion: 1, Algorithm: Algorithm, Nonce: env.Nonce, Ciphertext: flip(env.Ciphertext), AuthTag: env.AuthTag},
		"nonce":      {FormatVersion: 1, Algorithm: Algorithm, Nonce: flip(env.Nonce), Ciphertext: env.Ciphertext, AuthTag: env.AuthTag},
		"tag":        {FormatVersion: 1, Algorithm: Algorithm, Nonce: env.Nonce, Ciphertext: env.Ciphertext, AuthTag: flip(env.AuthTag)},
	} {
		if _, err := Open(key, e, ctx); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	short := env
	short.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 8))
	shortTag := env
	shortTag.AuthTag = base64.StdEncoding.EncodeToString(make([]byte, 12))
	wrongAlg := env
	wrongAlg.Algorithm = "aes-128-gcm"
	v2 := env
	v2.FormatVersion = 2
	for name, e := range map[string]Envelope{"short nonce": short, "short tag": shortTag, "algorithm": wrongAlg, "version 2": v2} {
		if _, err := Open(key, e, ctx); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// From JSON, as stored: the TypeScript decrypt accepts the number 1 in
	// any spelling and refuses anything else, and a missing field.
	base := func(version string) string {
		return `{"formatVersion":` + version + `,"algorithm":"aes-256-gcm","nonce":"` + env.Nonce + `","ciphertext":"` + env.Ciphertext + `","authTag":"` + env.AuthTag + `"}`
	}
	for _, v := range []string{"1", "1.0", "1e0"} {
		var e Envelope
		if err := json.Unmarshal([]byte(base(v)), &e); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(key, e, ctx); err != nil {
			t.Errorf("formatVersion %s refused: %v", v, err)
		}
	}
	for _, doc := range []string{base(`"1"`), base("2"), base("null"), strings.Replace(base("1"), `"formatVersion":1,`, "", 1), strings.Replace(base("1"), `"ciphertext":"`+env.Ciphertext+`",`, "", 1)} {
		var e Envelope
		if err := json.Unmarshal([]byte(doc), &e); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(key, e, ctx); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", doc, err)
		}
	}
	// Node decodes base64 leniently; an envelope written unpadded or in the
	// URL alphabet still opens.
	loose := env
	loose.Ciphertext = strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(env.Ciphertext), "=")
	if _, err := Open(key, loose, ctx); err != nil {
		t.Fatalf("lenient base64: %v", err)
	}
}

func TestErrorsHideSecrets(t *testing.T) {
	for _, v := range []any{json.Number("TOPSECRET"), json.Number("123456789012345678901234"), int64(1 << 60), 1.5} {
		bad := Context{"purpose": "test", "x": v}
		_, err := Seal(GenerateKey(), nil, bad)
		_, err2 := Open(GenerateKey(), Envelope{}, bad)
		for _, e := range []error{err, err2} {
			if e == nil || strings.Contains(e.Error(), "TOPSECRET") || strings.ContainsAny(e.Error(), "0123456789") {
				t.Errorf("%v: %v", v, e)
			}
		}
	}
	_, err := ParseRootKEK("0123456789abcdef0123456789abcdef")
	if err == nil || strings.Contains(err.Error(), "0123456789abcdef") {
		t.Fatalf("got %v", err)
	}
	key := GenerateKey()
	env, _ := Seal(key, []byte("TOPSECRET"), OrgKEKContext("org_secretid"))
	_, err = Open(key, env, OrgKEKContext("org_other"))
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") || strings.Contains(err.Error(), "org_") {
		t.Fatalf("got %v", err)
	}
}
