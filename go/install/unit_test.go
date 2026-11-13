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
			// systemd merges a repeated section; a second one could hide
			// settings from the checks below.
			if _, dup := out[section]; dup {
				t.Fatalf("section [%s] appears twice", section)
			}
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

// The unit's security contract: every setting the review and the run-time
// probe rely on. Any change to one, or any setting added to [Service]
// without being listed here, fails, so it is reviewed as a security change.
var securitySettings = map[string][]string{
	"User":                    {"varlatch"},
	"Group":                   {"varlatch"},
	"UMask":                   {"0077"},
	"StateDirectory":          {"varlatch"},
	"StateDirectoryMode":      {"0700"},
	"LoadCredential":          {"root-kek:/etc/varlatch/root-kek", "backup-key:/etc/varlatch/backup-key"},
	"AmbientCapabilities":     {"CAP_NET_BIND_SERVICE"},
	"CapabilityBoundingSet":   {"CAP_NET_BIND_SERVICE"},
	"NoNewPrivileges":         {"yes"},
	"ProtectSystem":           {"strict"},
	"ProtectHome":             {"yes"},
	"PrivateTmp":              {"yes"},
	"PrivateDevices":          {"yes"},
	"ProtectKernelTunables":   {"yes"},
	"ProtectKernelModules":    {"yes"},
	"ProtectKernelLogs":       {"yes"},
	"ProtectControlGroups":    {"yes"},
	"ProtectClock":            {"yes"},
	"ProtectHostname":         {"yes"},
	"ProtectProc":             {"invisible"},
	"RemoveIPC":               {"yes"},
	"RestrictAddressFamilies": {"AF_UNIX AF_INET AF_INET6 AF_NETLINK"},
	"RestrictNamespaces":      {"yes"},
	"RestrictRealtime":        {"yes"},
	"RestrictSUIDSGID":        {"yes"},
	"LockPersonality":         {"yes"},
	"MemoryDenyWriteExecute":  {"yes"},
	"PrivateUsers":            {"no"},
	"SystemCallArchitectures": {"native"},
	"SystemCallFilter":        {"@system-service", "~@privileged"},
	"SystemCallErrorNumber":   {"EPERM"},
	"DevicePolicy":            {"closed"},
	"KeyringMode":             {"private"},
	"LimitCORE":               {"0"},
}

// How the service starts, stops and restarts.
var lifecycleSettings = map[string][]string{
	"Type":           {"exec"},
	"ExecStart":      {"/usr/local/bin/varlatchd serve --config /etc/varlatch/varlatchd.conf"},
	"Restart":        {"on-failure"},
	"RestartSec":     {"15s"},
	"TimeoutStopSec": {"30s"},
	"LimitNOFILE":    {"65536"},
}

func TestUnitSettings(t *testing.T) {
	u := unit(t)
	svc := u["Service"]
	for _, want := range []map[string][]string{securitySettings, lifecycleSettings} {
		for k, v := range want {
			if !slices.Equal(svc[k], v) {
				t.Errorf("%s = %q, want %q", k, svc[k], v)
			}
		}
	}
	for k := range svc {
		if _, ok := securitySettings[k]; !ok {
			if _, ok := lifecycleSettings[k]; !ok {
				t.Errorf("[Service] has %s, which neither list covers: add it to one, as a reviewed change", k)
			}
		}
	}
	for k, v := range map[string][]string{"StartLimitIntervalSec": {"0"}, "StartLimitBurst": nil} {
		if !slices.Equal(u["Unit"][k], v) {
			t.Errorf("[Unit] %s = %q, want %q", k, u["Unit"][k], v)
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
