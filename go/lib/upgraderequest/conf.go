// SPDX-License-Identifier: Apache-2.0

package upgraderequest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfFile is the host's choice, beside varlatchd.conf
// (/etc/varlatch/web-upgrade.conf): root's, mode 0644, saying whether
// requests from the web app are accepted, and nothing else. `varlatch
// upgrade --enable-web` writes it and `--disable-web` removes it.
const ConfFile = "web-upgrade.conf"

// confKey is the file's one setting.
const confKey = "accept_requests"

// EncodeConf is the file that accepts requests, or refuses them.
func EncodeConf(accept bool) []byte {
	v := "no"
	if accept {
		v = "yes"
	}
	return []byte("# Written by sudo varlatch upgrade --enable-web: whether Installation Admins may ask\n" +
		"# this host to upgrade Varlatch from the web app. sudo varlatch upgrade --disable-web\n" +
		"# removes it, with the units that act on requests.\n" +
		confKey + " = " + v + "\n")
}

// ParseConf reads the file: comments, blank lines, and the one setting,
// once.
func ParseConf(b []byte) (bool, error) {
	seen, accept := false, false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != confKey || seen {
			return false, fmt.Errorf("%s: %q is not %s = yes|no", ConfFile, line, confKey)
		}
		switch strings.TrimSpace(v) {
		case "yes":
			accept = true
		case "no":
		default:
			return false, fmt.Errorf("%s: %q is not %s = yes|no", ConfFile, line, confKey)
		}
		seen = true
	}
	if !seen {
		return false, fmt.Errorf("%s: no %s", ConfFile, confKey)
	}
	return accept, nil
}

// Accepting is whether the file in configDir accepts requests: false when
// there is none.
func Accepting(configDir string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(configDir, ConfFile))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ParseConf(b)
}
