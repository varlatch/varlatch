// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// unit reads varlatchd.service into section -> key -> values (a key may
// repeat).
func unit(t *testing.T) map[string]map[string][]string {
	t.Helper()
	b, err := os.ReadFile("varlatchd.service")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string][]string{}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			section = strings.Trim(line, "[]")
			out[section] = map[string][]string{}
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok || section == "" {
				t.Fatalf("not a unit line: %q", line)
			}
			out[section][k] = append(out[section][k], v)
		}
	}
	return out
}

// The unit's promises (ADR-0059 Decision 8 and the file's own header):
// these settings are what the security review relied on, so a change to
// any of them fails here first. go/install/test-unit.sh checks the
// sandbox's effect at run time.
func TestUnitSettings(t *testing.T) {
	u := unit(t)
	svc := u["Service"]
	want := map[string][]string{
		"ExecStart":               {"/usr/local/bin/varlatchd serve --config /etc/varlatch/varlatchd.conf"},
		"User":                    {"varlatch"},
		"StateDirectory":          {"varlatch"},
		"StateDirectoryMode":      {"0700"},
		"UMask":                   {"0077"},
		"LoadCredential":          {"root-kek:/etc/varlatch/root-kek", "backup-key:/etc/varlatch/backup-key"},
		"AmbientCapabilities":     {"CAP_NET_BIND_SERVICE"},
		"CapabilityBoundingSet":   {"CAP_NET_BIND_SERVICE"},
		"NoNewPrivileges":         {"yes"},
		"ProtectSystem":           {"strict"},
		"ProtectHome":             {"yes"},
		"PrivateTmp":              {"yes"},
		"PrivateDevices":          {"yes"},
		"RestrictAddressFamilies": {"AF_UNIX AF_INET AF_INET6 AF_NETLINK"},
		"SystemCallFilter":        {"@system-service", "~@privileged"},
		"MemoryDenyWriteExecute":  {"yes"},
		"RestrictSUIDSGID":        {"yes"},
		"Restart":                 {"on-failure"},
	}
	for k, v := range want {
		if !slices.Equal(svc[k], v) {
			t.Errorf("%s = %q, want %q", k, svc[k], v)
		}
	}
	// Secrets reach the service only as credentials.
	for _, k := range []string{"Environment", "EnvironmentFile", "SetCredential", "PassEnvironment", "ReadWritePaths", "DynamicUser"} {
		if len(svc[k]) != 0 {
			t.Errorf("%s is set: %q", k, svc[k])
		}
	}
	for _, p := range []string{"/etc/varlatch/varlatchd.conf", "/etc/varlatch/root-kek", "/etc/varlatch/backup-key"} {
		if !slices.Contains(u["Unit"]["AssertPathExists"], p) {
			t.Errorf("the unit does not assert %s exists", p)
		}
	}
	if !slices.Equal(u["Install"]["WantedBy"], []string{"multi-user.target"}) {
		t.Errorf("WantedBy = %q", u["Install"]["WantedBy"])
	}
}
