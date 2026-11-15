// SPDX-License-Identifier: AGPL-3.0-or-later

package paritytest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
)

// recorder keeps what a check reports, without failing the test.
type recorder struct {
	testing.TB
	mu   sync.Mutex
	errs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *recorder) Helper() {}

// CheckDigests accepts an answer whose digests are its manifest's and
// reports each that is not, so a masked digest still cannot diverge.
func TestCheckDigests(t *testing.T) {
	manifest := `{"manifestVersion":1,"projectId":"prj_a","environment":{"id":"env_a"},"contract":null,"items":[{"name":"A","source":"self","valueRowId":"val_a","versionId":"ver_a","retiringVersionId":"ver_b"}]}`
	digest := func(canonical string) string {
		sum := sha256.Sum256([]byte(canonical))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	canon := func(v any) string {
		c, err := envelope.CanonicalJSON(v)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	whole := canon(map[string]any{"manifestVersion": 1, "projectId": "prj_a", "environment": map[string]any{"id": "env_a"}, "contract": nil,
		"items": []any{map[string]any{"name": "A", "source": "self", "valueRowId": "val_a", "versionId": "ver_a", "retiringVersionId": "ver_b"}}})
	digests := fmt.Sprintf(`{"environment":%q,"contract":%q,"items":%q,"rotation":%q}`,
		digest(canon(map[string]any{"projectId": "prj_a", "environment": map[string]any{"id": "env_a"}})), digest("null"),
		digest(canon([]any{map[string]any{"name": "A", "source": "self", "valueRowId": "val_a", "versionId": "ver_a"}})),
		digest(canon([]any{map[string]any{"name": "A", "retiringVersionId": "ver_b"}})))
	good := `{"manifest":` + manifest + `,"stateDigest":"` + digest(whole) + `","stateDigests":` + digests + `}`
	r := &recorder{TB: t}
	CheckDigests(r, []byte(good), "good")
	if len(r.errs) != 0 {
		t.Fatalf("a right answer: %v", r.errs)
	}
	for name, bad := range map[string]string{
		"stateDigest":        strings.Replace(good, digest(whole), digest("{}"), 1),
		"stateDigests.items": strings.Replace(good, `"items":"`, `"items":"sha256:00`, 1),
	} {
		r := &recorder{TB: t}
		CheckDigests(r, []byte(bad), name)
		if len(r.errs) == 0 || !strings.Contains(strings.Join(r.errs, " "), name) {
			t.Errorf("%s: a wrong digest passed: %v", name, r.errs)
		}
	}
}
