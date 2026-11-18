// SPDX-License-Identifier: Apache-2.0

// Package secretinput is where `values set` and `values rotate` take a
// value from (ADR-0043 Decision 2), a port of apps/cli/src/secretInput.ts:
// the command line, standard input, a file, a generator, or a hidden
// prompt on a terminal. Every path except the command line keeps the value
// out of shell history, process lists, and a coding agent's context.
//
// No message here ever contains a value or any part of one.
package secretinput

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"syscall"
	"unicode/utf8"
)

// Error is secretInput.ts's SecretInputError.
type Error struct {
	Message string
	// Usage: the command line is wrong (exit 64), rather than the input it names.
	Usage bool
}

func (e *Error) Error() string { return e.Message }

// Kind is a value source's kind.
type Kind string

// The value sources.
const (
	Argument Kind = "argument"
	Stdin    Kind = "stdin"
	File     Kind = "file"
	Generate Kind = "generate"
	Prompt   Kind = "prompt"
)

// Source is ValueSource: Value for an argument, Path for a file, Spec for
// a generator.
type Source struct {
	Kind  Kind
	Value string
	Path  string
	Spec  GenerateSpec
}

// GenerateSpec is a generator: Size random bytes for hex and the base64
// forms, characters for alnum.
type GenerateSpec struct {
	Encoding string
	Size     int
}

// At least 128 bits of randomness; at most what fits comfortably in an
// environment.
const (
	minBytes = 16
	minAlnum = 22 // 22 characters of 62 carry about 131 bits
	maxSize  = 4096
)

// GenerateForms names the generators, as the usage errors do.
const GenerateForms = "hex:<bytes>, base64:<bytes>, base64url:<bytes>, or alnum:<characters>"

var generateSpec = regexp.MustCompile(`^(hex|base64|base64url|alnum):([0-9]+)$`)

// ParseGenerateSpec is parseGenerateSpec.
func ParseGenerateSpec(raw string) (GenerateSpec, error) {
	m := generateSpec.FindStringSubmatch(raw)
	if m == nil {
		return GenerateSpec{}, &Error{Message: "--generate expects " + GenerateForms + ", for example hex:32", Usage: true}
	}
	encoding := m[1]
	// Number(digits): any run of digits is a number; a long one is beyond the maximum.
	size, err := strconv.Atoi(m[2])
	if err != nil {
		size = maxSize + 1
	}
	low, unit := minBytes, "bytes"
	if encoding == "alnum" {
		low, unit = minAlnum, "characters"
	}
	if size < low || size > maxSize {
		return GenerateSpec{}, &Error{Message: "--generate " + encoding + ": the size must be from " + strconv.Itoa(low) + " to " + strconv.Itoa(maxSize) + " " + unit, Usage: true}
	}
	return GenerateSpec{Encoding: encoding, Size: size}, nil
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GenerateValue is generateValue: a new random value from the operating
// system's CSPRNG.
func GenerateValue(spec GenerateSpec) (string, error) {
	if spec.Encoding == "alnum" {
		out := make([]byte, spec.Size)
		limit := big.NewInt(int64(len(alnum)))
		for i := range out {
			// Uniform: no modulo bias, as crypto.randomInt.
			n, err := rand.Int(rand.Reader, limit)
			if err != nil {
				return "", err
			}
			out[i] = alnum[n.Int64()]
		}
		return string(out), nil
	}
	random := make([]byte, spec.Size)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	switch spec.Encoding {
	case "hex":
		return hex.EncodeToString(random), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(random), nil
	}
	// Node's base64url has no padding.
	return base64.RawURLEncoding.EncodeToString(random), nil
}

// DescribeGenerated is describeGenerated: the generator only.
func DescribeGenerated(spec GenerateSpec) string {
	unit := "random bytes"
	if spec.Encoding == "alnum" {
		unit = "characters"
	}
	return spec.Encoding + ", " + strconv.Itoa(spec.Size) + " " + unit
}

// Options are valueSourceOf's options: what the command line gave.
type Options struct {
	Value    string
	HasValue bool
	Stdin    bool
	File     string
	HasFile  bool
	Generate string
	HasGen   bool
}

// SourceOf is valueSourceOf: at most one source; none means the hidden
// prompt.
func SourceOf(o Options) (Source, error) {
	var sources []Source
	if o.HasValue {
		sources = append(sources, Source{Kind: Argument, Value: o.Value})
	}
	if o.Stdin {
		sources = append(sources, Source{Kind: Stdin})
	}
	if o.HasFile {
		sources = append(sources, Source{Kind: File, Path: o.File})
	}
	if o.HasGen {
		spec, err := ParseGenerateSpec(o.Generate)
		if err != nil {
			return Source{}, err
		}
		sources = append(sources, Source{Kind: Generate, Spec: spec})
	}
	if len(sources) > 1 {
		return Source{}, &Error{Message: "give the value one way only: as an argument, --stdin, --from-file <path>, or --generate <spec>", Usage: true}
	}
	if len(sources) == 0 {
		return Source{Kind: Prompt}, nil
	}
	return sources[0], nil
}

// FromBytes is valueFromBytes: text read from standard input or a file,
// with one trailing line break (LF or CRLF) removed. The value must be
// valid UTF-8 without NUL bytes, since it is delivered in an environment
// variable, and must not be empty.
func FromBytes(b []byte, from string) (string, error) {
	if bytes.IndexByte(b, 0) >= 0 {
		return "", &Error{Message: from + " contains a NUL byte, which an environment variable cannot hold"}
	}
	// Buffer#toString then Buffer.from: the same bytes only when they are UTF-8.
	if !utf8.Valid(b) {
		return "", &Error{Message: from + " is not valid UTF-8 text"}
	}
	text := string(b)
	switch {
	case len(text) >= 2 && text[len(text)-2:] == "\r\n":
		text = text[:len(text)-2]
	case len(text) >= 1 && text[len(text)-1] == '\n':
		text = text[:len(text)-1]
	}
	if text == "" {
		return "", &Error{Message: from + " is empty; nothing was stored"}
	}
	return text, nil
}

// IsWellFormed is isWellFormedText: no unpaired UTF-16 surrogate (held as
// its WTF-8 bytes), so the text has an exact UTF-8 form.
func IsWellFormed(text string) bool { return utf8.ValidString(text) }

// ReadFile is readValueFile: the file's text, or an error naming the file
// and Node's code for the failure (never its content).
func ReadFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", &Error{Message: "cannot read " + path + " (" + errnoCode(err) + ")"}
	}
	return FromBytes(b, path)
}

// errnoCode is the code Node gives a failed readFileSync ("ENOENT",
// "EACCES", "EISDIR", ...), "an error" when it has none.
func errnoCode(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if name := errnoName(errno); name != "" {
			return name
		}
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "ENOENT"
	case errors.Is(err, fs.ErrPermission):
		return "EACCES"
	}
	return "an error"
}

// errnoName is libuv's name for a system error a file read can meet.
func errnoName(errno syscall.Errno) string {
	switch errno {
	case syscall.ENOENT:
		return "ENOENT"
	case syscall.EACCES:
		return "EACCES"
	case syscall.EPERM:
		return "EPERM"
	case syscall.EISDIR:
		return "EISDIR"
	case syscall.ENOTDIR:
		return "ENOTDIR"
	case syscall.ELOOP:
		return "ELOOP"
	case syscall.ENAMETOOLONG:
		return "ENAMETOOLONG"
	case syscall.EMFILE:
		return "EMFILE"
	case syscall.EIO:
		return "EIO"
	}
	return ""
}
