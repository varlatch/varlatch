// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Ported from V8 14.6.202 (src/date/dateparser.h, dateparser-inl.h,
// dateparser.cc, and ParseDateTimeString and MakeDay in date.cc), the date
// parser of the Node.js that runs the TypeScript CLI. Copyright 2011 the V8
// project authors. All rights reserved. Under the BSD 3-Clause License
// (LICENSE-v8-BSD-3-Clause, next to this file).

package jsval

import (
	"math"
	"time"
)

// DateParse is Date.parse(s) (and new Date(s)) as V8 reads a string: first
// as ECMAScript's date time string format (with V8's extensions: a fraction
// of any length, hhmm offsets, lowercase t and z), and what is left with
// its older parser, which reads forms such as "Nov 17 2026",
// "2026-11-17 10:00:00", "12/31/2020" or "5". false is NaN. A date alone
// in the ISO form is UTC; any other form without an offset is local time.
func DateParse(s string) (float64, bool) {
	var out dateOutput
	if !parseDate(UTF16(s), &out) {
		return 0, false
	}
	day, ok := makeDay(out.year, out.month, out.day)
	if !ok {
		return 0, false
	}
	date := day*msPerDay + float64(out.hour)*3600000 + float64(out.minute)*60000 + float64(out.second)*1000 + float64(out.millisecond)
	if !out.hasOffset {
		if date < -maxTimeBeforeUTC || date > maxTimeBeforeUTC {
			return 0, false
		}
		date = localToUTC(int64(date))
	} else {
		date -= float64(out.offset) * 1000
	}
	if date < -maxTimeMs || date > maxTimeMs {
		return 0, false
	}
	return math.Trunc(date) + 0, true
}

const (
	msPerDay         = 86400000
	maxTimeMs        = 864000000 * 10000000
	maxTimeBeforeUTC = maxTimeMs + msPerDay*30
)

// localToUTC is V8's DateCache::ToUTC: a local wall time, in milliseconds
// as if it were UTC, to the time it names. Where the wall time is ambiguous
// (a clock set back) or skipped (a clock set forward), V8 takes the offset
// in force before the change (ICU's UCAL_TZ_LOCAL_FORMER).
func localToUTC(wall int64) float64 {
	offset := func(utc int64) int64 {
		_, seconds := time.UnixMilli(utc).In(time.Local).Zone()
		return int64(seconds) * 1000
	}
	before, after := offset(wall-msPerDay), offset(wall+msPerDay)
	former := wall - before
	if before != after && offset(former) != before {
		if latter := wall - after; offset(latter) == after {
			return float64(latter)
		}
	}
	return float64(former)
}

// makeDay is date.cc's MakeDay for whole numbers: the day number of a
// year, a 0-based month and a day of the month (which may overflow).
func makeDay(year, month, date int) (float64, bool) {
	if year < -1000000 || year > 1000000 {
		return 0, false
	}
	y := year + month/12
	m := month % 12
	if m < 0 {
		m += 12
		y--
	}
	const yearDelta = 399999
	base := 365*(1970+yearDelta) + (1970+yearDelta)/4 - (1970+yearDelta)/100 + (1970+yearDelta)/400
	dayFromYear := 365*(y+yearDelta) + (y+yearDelta)/4 - (y+yearDelta)/100 + (y+yearDelta)/400 - base
	if y%4 != 0 || y%100 == 0 && y%400 != 0 {
		dayFromYear += [...]int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}[m]
	} else {
		dayFromYear += [...]int{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335}[m]
	}
	return float64(dayFromYear-1) + float64(date), true
}

// kNone is V8's kMaxInt sentinel.
const kNone = math.MaxInt32

type dateOutput struct {
	year, month, day, hour, minute, second, millisecond int
	offset                                              int // seconds east of UTC
	hasOffset                                           bool
}

func between(x, lo, hi int) bool { return uint(x-lo) <= uint(hi-lo) }

// V8's character classes (src/strings/char-predicates.h).
func isWhiteSpace(c uint16) bool {
	switch c {
	case '\t', '\v', '\f', ' ', 0xa0, 0xfeff, 0x1680, 0x202f, 0x205f, 0x3000:
		return true
	}
	return c >= 0x2000 && c <= 0x200a
}

func isWhiteSpaceOrLineTerminator(c uint16) bool {
	return isWhiteSpace(c) || c == '\n' || c == '\r' || c == 0x2028 || c == 0x2029
}

// inputReader is DateParser::InputReader: ch is the current character, 0
// at the end (and for a NUL, which ends the input too).
type inputReader struct {
	buf   []uint16
	index int
	ch    uint16
}

func newInputReader(s []uint16) *inputReader {
	in := &inputReader{buf: s}
	in.next()
	return in
}

func (in *inputReader) position() int { return in.index }

func (in *inputReader) next() {
	if in.index < len(in.buf) {
		in.ch = in.buf[in.index]
	} else {
		in.ch = 0
	}
	in.index++
}

const maxSignificantDigits = 9

func (in *inputReader) readUnsignedNumeral() int {
	n, i := 0, 0
	for in.ch == '0' {
		in.next()
	}
	for in.isDigit() {
		if i < maxSignificantDigits {
			n = n*10 + int(in.ch) - '0'
		}
		i++
		in.next()
	}
	return n
}

func (in *inputReader) readWord(prefix *[3]uint32) int {
	length := 0
	for ; in.isAlphaOrAbove() && !isWhiteSpace(in.ch); in.next() {
		if length < 3 {
			prefix[length] = uint32(in.ch) | 0x20 // AsciiAlphaToLower
		}
		length++
	}
	for i := length; i < 3; i++ {
		prefix[i] = 0
	}
	return length
}

func (in *inputReader) skip(c uint16) bool {
	if in.ch == c {
		in.next()
		return true
	}
	return false
}

func (in *inputReader) isEnd() bool          { return in.ch == 0 }
func (in *inputReader) isDigit() bool        { return in.ch >= '0' && in.ch <= '9' }
func (in *inputReader) isAlphaOrAbove() bool { return in.ch >= 'A' }

func (in *inputReader) skipWhiteSpace() bool {
	if isWhiteSpaceOrLineTerminator(in.ch) {
		in.next()
		return true
	}
	return false
}

func (in *inputReader) skipParentheses() bool {
	if in.ch != '(' {
		return false
	}
	balance := 0
	for {
		if in.ch == ')' {
			balance--
		} else if in.ch == '(' {
			balance++
		}
		in.next()
		if !(balance > 0 && in.ch != 0) {
			break
		}
	}
	return true
}

type keywordType int

const (
	kwInvalid keywordType = iota
	kwMonthName
	kwTimeZoneName
	kwTimeSeparator
	kwAMPM
)

const (
	tagInvalid    = -6
	tagUnknown    = -5
	tagWhiteSpace = -4
	tagNumber     = -3
	tagSymbol     = -2
	tagEndOfInput = -1
)

type dateToken struct {
	tag, length, value int
}

func (t dateToken) isInvalid() bool                  { return t.tag == tagInvalid }
func (t dateToken) isNumber() bool                   { return t.tag == tagNumber }
func (t dateToken) isSymbolAny() bool                { return t.tag == tagSymbol }
func (t dateToken) isWhiteSpace() bool               { return t.tag == tagWhiteSpace }
func (t dateToken) isEndOfInput() bool               { return t.tag == tagEndOfInput }
func (t dateToken) isKeyword() bool                  { return t.tag >= 0 }
func (t dateToken) isSymbol(c byte) bool             { return t.tag == tagSymbol && t.value == int(c) }
func (t dateToken) isKeywordType(k keywordType) bool { return t.tag == int(k) }
func (t dateToken) isFixedLengthNumber(n int) bool   { return t.isNumber() && t.length == n }
func (t dateToken) isAsciiSign() bool {
	return t.tag == tagSymbol && (t.value == '-' || t.value == '+')
}
func (t dateToken) asciiSign() int { return 44 - t.value }
func (t dateToken) isKeywordZ() bool {
	return t.isKeywordType(kwTimeZoneName) && t.length == 1 && t.value == 0
}

var keywords = []struct {
	prefix [3]uint32
	typ    keywordType
	value  int
}{
	{[3]uint32{'j', 'a', 'n'}, kwMonthName, 1},
	{[3]uint32{'f', 'e', 'b'}, kwMonthName, 2},
	{[3]uint32{'m', 'a', 'r'}, kwMonthName, 3},
	{[3]uint32{'a', 'p', 'r'}, kwMonthName, 4},
	{[3]uint32{'m', 'a', 'y'}, kwMonthName, 5},
	{[3]uint32{'j', 'u', 'n'}, kwMonthName, 6},
	{[3]uint32{'j', 'u', 'l'}, kwMonthName, 7},
	{[3]uint32{'a', 'u', 'g'}, kwMonthName, 8},
	{[3]uint32{'s', 'e', 'p'}, kwMonthName, 9},
	{[3]uint32{'o', 'c', 't'}, kwMonthName, 10},
	{[3]uint32{'n', 'o', 'v'}, kwMonthName, 11},
	{[3]uint32{'d', 'e', 'c'}, kwMonthName, 12},
	{[3]uint32{'a', 'm', 0}, kwAMPM, 0},
	{[3]uint32{'p', 'm', 0}, kwAMPM, 12},
	{[3]uint32{'u', 't', 0}, kwTimeZoneName, 0},
	{[3]uint32{'u', 't', 'c'}, kwTimeZoneName, 0},
	{[3]uint32{'z', 0, 0}, kwTimeZoneName, 0},
	{[3]uint32{'g', 'm', 't'}, kwTimeZoneName, 0},
	{[3]uint32{'c', 'd', 't'}, kwTimeZoneName, -5},
	{[3]uint32{'c', 's', 't'}, kwTimeZoneName, -6},
	{[3]uint32{'e', 'd', 't'}, kwTimeZoneName, -4},
	{[3]uint32{'e', 's', 't'}, kwTimeZoneName, -5},
	{[3]uint32{'m', 'd', 't'}, kwTimeZoneName, -6},
	{[3]uint32{'m', 's', 't'}, kwTimeZoneName, -7},
	{[3]uint32{'p', 'd', 't'}, kwTimeZoneName, -7},
	{[3]uint32{'p', 's', 't'}, kwTimeZoneName, -8},
	{[3]uint32{'t', 0, 0}, kwTimeSeparator, 0},
}

// lookupKeyword is KeywordTable::Lookup: a word longer than its keyword
// matches only a month name.
func lookupKeyword(prefix [3]uint32, length int) (keywordType, int) {
	for _, k := range keywords {
		if k.prefix == prefix && (length <= 3 || k.typ == kwMonthName) {
			return k.typ, k.value
		}
	}
	return kwInvalid, 0
}

type tokenizer struct {
	in   *inputReader
	peek dateToken
}

func newTokenizer(in *inputReader) *tokenizer {
	t := &tokenizer{in: in}
	t.peek = t.scan()
	return t
}

func (t *tokenizer) next() dateToken {
	result := t.peek
	t.peek = t.scan()
	return result
}

func (t *tokenizer) skipSymbol(c byte) bool {
	if t.peek.isSymbol(c) {
		t.peek = t.scan()
		return true
	}
	return false
}

func (t *tokenizer) scan() dateToken {
	in := t.in
	pre := in.position()
	if in.isEnd() {
		return dateToken{tagEndOfInput, 0, -1}
	}
	if in.isDigit() {
		n := in.readUnsignedNumeral()
		return dateToken{tagNumber, in.position() - pre, n}
	}
	for _, c := range []uint16{':', '-', '+', '.', ')'} {
		if in.skip(c) {
			return dateToken{tagSymbol, 1, int(c)}
		}
	}
	if in.isAlphaOrAbove() && !isWhiteSpace(in.ch) {
		var prefix [3]uint32
		length := in.readWord(&prefix)
		typ, value := lookupKeyword(prefix, length)
		return dateToken{int(typ), length, value}
	}
	if in.skipWhiteSpace() {
		return dateToken{tagWhiteSpace, in.position() - pre, -1}
	}
	if in.skipParentheses() {
		return dateToken{tagUnknown, 1, -1}
	}
	in.next()
	return dateToken{tagUnknown, 1, -1}
}

func readMilliseconds(token dateToken) int {
	number, length := token.value, token.length
	if length < 3 {
		if length == 1 {
			number *= 100
		} else if length == 2 {
			number *= 10
		}
	} else if length > 3 {
		if length > maxSignificantDigits {
			length = maxSignificantDigits
		}
		factor := 1
		for {
			factor *= 10
			length--
			if length <= 3 {
				break
			}
		}
		number /= factor
	}
	return number
}

type tzComposer struct{ sign, hour, minute int }

func (z *tzComposer) set(offsetHours int) {
	z.sign = 1
	if offsetHours < 0 {
		z.sign = -1
	}
	z.hour = offsetHours * z.sign
	z.minute = 0
}

func (z *tzComposer) setSign(sign int) {
	z.sign = 1
	if sign < 0 {
		z.sign = -1
	}
}

func (z *tzComposer) isExpecting(n int) bool {
	return z.hour != kNone && z.minute == kNone && between(n, 0, 59)
}

func (z *tzComposer) isUTC() bool   { return z.hour == 0 && z.minute == 0 }
func (z *tzComposer) isEmpty() bool { return z.hour == kNone }

func (z *tzComposer) write(out *dateOutput) bool {
	if z.sign != kNone {
		if z.hour == kNone {
			z.hour = 0
		}
		if z.minute == kNone {
			z.minute = 0
		}
		total := uint32(z.hour)*3600 + uint32(z.minute)*60
		if total > 1<<31-1 { // Smi::kMaxValue: Node.js builds V8 with 32-bit Smis
			return false
		}
		seconds := int(total)
		if z.sign < 0 {
			seconds = -seconds
		}
		out.offset, out.hasOffset = seconds, true
	} else {
		out.hasOffset = false
	}
	return true
}

type timeComposer struct {
	comp       [4]int
	index      int
	hourOffset int
}

func (c *timeComposer) isEmpty() bool { return c.index == 0 }

func (c *timeComposer) isExpecting(n int) bool {
	return (c.index == 1 && between(n, 0, 59)) || (c.index == 2 && between(n, 0, 59)) || (c.index == 3 && between(n, 0, 999))
}

func (c *timeComposer) add(n int) bool {
	if c.index < 4 {
		c.comp[c.index] = n
		c.index++
		return true
	}
	return false
}

func (c *timeComposer) addFinal(n int) bool {
	if !c.add(n) {
		return false
	}
	for c.index < 4 {
		c.comp[c.index] = 0
		c.index++
	}
	return true
}

func (c *timeComposer) write(out *dateOutput) bool {
	for c.index < 4 {
		c.comp[c.index] = 0
		c.index++
	}
	hour, minute, second, ms := c.comp[0], c.comp[1], c.comp[2], c.comp[3]
	if c.hourOffset != kNone {
		if !between(hour, 0, 12) {
			return false
		}
		hour %= 12
		hour += c.hourOffset
	}
	if !between(hour, 0, 23) || !between(minute, 0, 59) || !between(second, 0, 59) || !between(ms, 0, 999) {
		if hour != 24 || minute != 0 || second != 0 || ms != 0 {
			return false
		}
	}
	out.hour, out.minute, out.second, out.millisecond = hour, minute, second, ms
	return true
}

type dayComposer struct {
	comp       [3]int
	index      int
	namedMonth int
	isISODate  bool
}

func (d *dayComposer) isEmpty() bool { return d.index == 0 }

func (d *dayComposer) add(n int) bool {
	if d.index < 3 {
		d.comp[d.index] = n
		d.index++
		return true
	}
	return false
}

func isDay(x int) bool { return between(x, 1, 31) }

func (d *dayComposer) write(out *dateOutput) bool {
	if d.index < 1 {
		return false
	}
	for d.index < 3 {
		d.comp[d.index] = 1
		d.index++
	}
	year, month, day := 0, kNone, kNone
	if d.namedMonth == kNone {
		if d.isISODate || d.index == 3 && !isDay(d.comp[0]) {
			year, month, day = d.comp[0], d.comp[1], d.comp[2]
		} else {
			month, day = d.comp[0], d.comp[1]
			if d.index == 3 {
				year = d.comp[2]
			}
		}
	} else {
		month = d.namedMonth
		switch {
		case d.index == 1:
			day = d.comp[0]
		case !isDay(d.comp[0]):
			year, day = d.comp[0], d.comp[1]
		default:
			day, year = d.comp[0], d.comp[1]
		}
	}
	if !d.isISODate {
		if between(year, 0, 49) {
			year += 2000
		} else if between(year, 50, 99) {
			year += 1900
		}
	}
	if !between(month, 1, 12) || !isDay(day) {
		return false
	}
	out.year, out.month, out.day = year, month-1, day
	return true
}

// parseDate is DateParser::Parse.
func parseDate(s []uint16, out *dateOutput) bool {
	in := newInputReader(s)
	scanner := newTokenizer(in)
	tz := &tzComposer{sign: kNone, hour: kNone, minute: kNone}
	tm := &timeComposer{hourOffset: kNone}
	day := &dayComposer{namedMonth: kNone}

	next := parseES5DateTime(scanner, day, tm, tz)
	if next.isInvalid() {
		return false
	}
	hasReadNumber := !day.isEmpty()
	for token := next; !token.isEndOfInput(); token = scanner.next() {
		switch {
		case token.isNumber():
			hasReadNumber = true
			n := token.value
			if scanner.skipSymbol(':') {
				if scanner.skipSymbol(':') {
					if !tm.isEmpty() {
						return false
					}
					tm.add(n)
					tm.add(0)
				} else {
					if !tm.add(n) {
						return false
					}
					if scanner.peek.isSymbol('.') {
						scanner.next()
					}
				}
			} else if scanner.skipSymbol('.') && tm.isExpecting(n) {
				tm.add(n)
				if !scanner.peek.isNumber() {
					return false
				}
				ms := readMilliseconds(scanner.next())
				if ms < 0 {
					return false
				}
				tm.addFinal(ms)
			} else if tz.isExpecting(n) {
				tz.minute = n
			} else if tm.isExpecting(n) {
				tm.addFinal(n)
				peek := scanner.peek
				if !peek.isEndOfInput() && !peek.isWhiteSpace() && !peek.isKeywordZ() && !peek.isAsciiSign() {
					return false
				}
			} else {
				if !day.add(n) {
					return false
				}
				scanner.skipSymbol('-')
			}
		case token.isKeyword():
			typ, value := keywordType(token.tag), token.value
			switch {
			case typ == kwAMPM && !tm.isEmpty():
				tm.hourOffset = value
			case typ == kwMonthName:
				day.namedMonth = value
				scanner.skipSymbol('-')
			case typ == kwTimeZoneName && hasReadNumber:
				tz.set(value)
			default:
				if hasReadNumber {
					return false
				}
				if scanner.peek.isNumber() {
					return false
				}
			}
		case token.isAsciiSign() && (tz.isUTC() || !tm.isEmpty()):
			tz.setSign(token.asciiSign())
			n, length := 0, 0
			if scanner.peek.isNumber() {
				t := scanner.next()
				length, n = t.length, t.value
			}
			hasReadNumber = true
			switch {
			case scanner.peek.isSymbol(':'):
				tz.hour, tz.minute = n, kNone
			case length == 2 || length == 1:
				tz.hour, tz.minute = n, 0
			case length == 4 || length == 3:
				tz.hour, tz.minute = n/100, n%100
			default:
				return false
			}
		case (token.isAsciiSign() || token.isSymbol(')')) && hasReadNumber:
			return false
		}
	}
	return day.write(out) && tm.write(out) && tz.write(out)
}

// parseES5DateTime is DateParser::ParseES5DateTime: as far as the input is
// in the ISO form; the token it could not use goes on to the older parser.
func parseES5DateTime(scanner *tokenizer, day *dayComposer, tm *timeComposer, tz *tzComposer) dateToken {
	invalid := dateToken{tagInvalid, 0, -1}
	if scanner.peek.isAsciiSign() {
		sign := scanner.next()
		if !scanner.peek.isFixedLengthNumber(6) {
			return sign
		}
		year := scanner.next().value
		if sign.asciiSign() < 0 && year == 0 {
			return sign
		}
		day.add(sign.asciiSign() * year)
	} else if scanner.peek.isFixedLengthNumber(4) {
		day.add(scanner.next().value)
	} else {
		return scanner.next()
	}
	if scanner.skipSymbol('-') {
		if !scanner.peek.isFixedLengthNumber(2) || !between(scanner.peek.value, 1, 12) {
			return scanner.next()
		}
		day.add(scanner.next().value)
		if scanner.skipSymbol('-') {
			if !scanner.peek.isFixedLengthNumber(2) || !isDay(scanner.peek.value) {
				return scanner.next()
			}
			day.add(scanner.next().value)
		}
	}
	if !scanner.peek.isKeywordType(kwTimeSeparator) {
		if !scanner.peek.isEndOfInput() {
			return scanner.next()
		}
	} else {
		scanner.next()
		if !scanner.peek.isFixedLengthNumber(2) || !between(scanner.peek.value, 0, 24) {
			return invalid
		}
		hourIs24 := scanner.peek.value == 24
		tm.add(scanner.next().value)
		if !scanner.skipSymbol(':') {
			return invalid
		}
		if !scanner.peek.isFixedLengthNumber(2) || !between(scanner.peek.value, 0, 59) || hourIs24 && scanner.peek.value > 0 {
			return invalid
		}
		tm.add(scanner.next().value)
		if scanner.skipSymbol(':') {
			if !scanner.peek.isFixedLengthNumber(2) || !between(scanner.peek.value, 0, 59) || hourIs24 && scanner.peek.value > 0 {
				return invalid
			}
			tm.add(scanner.next().value)
			if scanner.skipSymbol('.') {
				if !scanner.peek.isNumber() || hourIs24 && scanner.peek.value > 0 {
					return invalid
				}
				tm.add(readMilliseconds(scanner.next()))
			}
		}
		if scanner.peek.isKeywordZ() {
			scanner.next()
			tz.set(0)
		} else if scanner.peek.isSymbol('+') || scanner.peek.isSymbol('-') {
			if scanner.next().value == '+' {
				tz.setSign(1)
			} else {
				tz.setSign(-1)
			}
			if scanner.peek.isFixedLengthNumber(4) {
				hourmin := scanner.next().value
				hour, min := hourmin/100, hourmin%100
				if !between(hour, 0, 23) || !between(min, 0, 59) {
					return invalid
				}
				tz.hour, tz.minute = hour, min
			} else {
				if !scanner.peek.isFixedLengthNumber(2) || !between(scanner.peek.value, 0, 23) {
					return invalid
				}
				tz.hour = scanner.next().value
				if !scanner.skipSymbol(':') {
					return invalid
				}
				if !scanner.peek.isFixedLengthNumber(2) || !between(scanner.peek.value, 0, 59) {
					return invalid
				}
				tz.minute = scanner.next().value
			}
		}
		if !scanner.peek.isEndOfInput() {
			return invalid
		}
	}
	if tz.isEmpty() && tm.isEmpty() {
		tz.set(0)
	}
	day.isISODate = true
	return dateToken{tagEndOfInput, 0, -1}
}
