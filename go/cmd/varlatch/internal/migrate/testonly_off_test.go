// SPDX-License-Identifier: Apache-2.0

//go:build !crashpoint && !rehearsal

package migrate

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// In a build without the test tags, the overrides' variables change
// nothing: the pin is exactly the constants, and the image's user is
// distroless's nonroot. The test runs itself again with both set.
func TestTheOverridesDoNothingWithoutATestTag(t *testing.T) {
	if os.Getenv("VARLATCH_TESTONLY_CHILD") == "1" {
		if testPin != nil {
			t.Fatalf("testPin is %+v", *testPin)
		}
		if ImageUser != (Owner{UID: 65532, GID: 65532}) {
			t.Fatalf("ImageUser is %+v", ImageUser)
		}
		e := &Engine{}
		err := e.pinned(SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "registry.test/varlatchd"})
		// The constants: refused as unpublished until 0.23.0's digest is
		// pinned, then as another image than the pinned one.
		want := "not yet published"
		if LastTypeScriptDigest != "" {
			want = LastTypeScriptRepository + "@" + LastTypeScriptDigest
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the pin is not the constants: %v", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTheOverridesDoNothingWithoutATestTag$", "-test.count=1")
	cmd.Env = append(os.Environ(), "VARLATCH_TESTONLY_CHILD=1",
		"VARLATCH_MIGRATE_PIN=registry.test/varlatchd@sha256:"+strings.Repeat("a", 64), "VARLATCH_MIGRATE_IMAGE_USER=1:1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
