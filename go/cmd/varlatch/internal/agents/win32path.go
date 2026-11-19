// SPDX-License-Identifier: Apache-2.0

package agents

import "strings"

// Node.js's path.win32, which hook.ts's `node:path` is on Windows: its
// isAbsolute, normalize and resolve, as plain string functions so that
// they are tested on every platform (TestWin32Paths, against Node.js's own
// answers). Go's filepath differs from them on one point the hook depends
// on: a path rooted without a drive (`/home/dev/...`, `\top`) is absolute
// to Node.js and not to filepath.IsAbs, so the credential store's
// directories and a path naming them would never meet.

func isSep(c byte) bool { return c == '/' || c == '\\' }

// win32Device is a path's device, "C:" or `\\server\share`, and the rest,
// as Node.js reads them: after the server any run of separators, then the
// share (`//srv//share/x` is `\\srv\share` and `/x`).
func win32Device(p string) (device, rest string) {
	if len(p) >= 2 && isSep(p[0]) && isSep(p[1]) {
		// A UNC root: \\server\share.
		i := 2
		for i < len(p) && !isSep(p[i]) {
			i++
		}
		if i > 2 && i < len(p) {
			j := i + 1
			for j < len(p) && isSep(p[j]) {
				j++
			}
			if j < len(p) {
				k := j
				for k < len(p) && !isSep(p[k]) {
					k++
				}
				return `\\` + p[2:i] + `\` + p[j:k], p[k:]
			}
		}
		return "", p
	}
	if len(p) >= 2 && p[1] == ':' && (p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z') {
		return p[:2], p[2:]
	}
	return "", p
}

// win32IsAbsolute is path.win32.isAbsolute.
func win32IsAbsolute(p string) bool {
	device, rest := win32Device(p)
	if strings.HasPrefix(device, `\\`) {
		return true
	}
	return rest != "" && isSep(rest[0])
}

// win32Tail is a path's names, `.` and `..` resolved; a `..` above the
// root is dropped when the path is rooted, kept when it is not.
func win32Tail(rest string, rooted bool) string {
	var names []string
	for _, n := range strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' }) {
		switch {
		case n == ".":
		case n == ".." && len(names) > 0 && names[len(names)-1] != "..":
			names = names[:len(names)-1]
		case n == ".." && rooted:
		default:
			names = append(names, n)
		}
	}
	return strings.Join(names, `\`)
}

// win32Normalize is path.win32.normalize, but for its trailing separator
// (none here, as filepath.Clean keeps none).
func win32Normalize(p string) string {
	device, rest := win32Device(p)
	rooted := strings.HasPrefix(device, `\\`) || rest != "" && isSep(rest[0])
	tail := win32Tail(rest, rooted)
	switch {
	case rooted:
		return device + `\` + tail
	case tail == "":
		return device + "." // "C:" is "C:.", "" is "."
	}
	return device + tail
}

// win32Resolve is path.win32.resolve(cwd, p) in a process whose working
// directory is wd: the paths from right to left until one is absolute
// with a device; a device-less rooted path takes the device of the path
// left of it, else the working directory's. A drive-relative path on
// another drive than wd's resolves against that drive's root (`D:rel` from
// `E:\wd` is `D:\rel`), as Node.js does without a `=D:` variable.
func win32Resolve(wd, cwd, p string) string {
	resolvedDevice, resolvedTail, resolvedAbsolute := "", "", false
	for i, path := range []string{p, cwd, wd} {
		if path == "" {
			continue
		}
		if i == 2 && resolvedDevice != "" {
			if device, rest := win32Device(path); !strings.EqualFold(device, resolvedDevice) && rest != "" && rest[0] == '\\' {
				path = resolvedDevice + `\`
			}
		}
		device, rest := win32Device(path)
		absolute := strings.HasPrefix(device, `\\`) || rest != "" && isSep(rest[0])
		if device != "" {
			if resolvedDevice != "" && !strings.EqualFold(device, resolvedDevice) {
				continue // another drive's relative path
			}
			if resolvedDevice == "" {
				resolvedDevice = device
			}
		}
		if resolvedAbsolute {
			if resolvedDevice != "" {
				break
			}
			continue
		}
		resolvedTail = rest + `\` + resolvedTail
		resolvedAbsolute = absolute
		if absolute && resolvedDevice != "" {
			break
		}
	}
	tail := win32Tail(resolvedTail, resolvedAbsolute)
	if resolvedAbsolute {
		return resolvedDevice + `\` + tail
	}
	return resolvedDevice + tail
}
