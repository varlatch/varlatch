// SPDX-License-Identifier: AGPL-3.0-or-later AND PostgreSQL
//
// Package pgtime reads text as PostgreSQL 17 reads a timestamptz
// (timestamptz_in: ParseDateTime, DecodeDateTime and the functions they
// call in src/backend/utils/adt/datetime.c, tm2timestamp in timestamp.c),
// ported to Go, for a session whose TimeZone is UTC and DateStyle the
// default (ISO, MDY), with the Default timezone_abbreviations set (ADR-0059
// step 4.3c: the audit log's cursor time, which the TypeScript server hands
// to PostgreSQL as $3::timestamptz). The text it refuses and the instant it
// reads are PostgreSQL's; zone names come from a tz database directory
// (zone.go).
//
// Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
// Portions Copyright (c) 1994, Regents of the University of California
// (LICENSE-PostgreSQL)
package pgtime

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Time is a timestamptz: microseconds since 2000-01-01 00:00:00 UTC, or
// infinity or -infinity.
type Time struct {
	pg  int64
	inf int
}

// pgEpochUnixMicros is 2000-01-01 00:00:00 UTC in Unix microseconds.
const pgEpochUnixMicros = 946_684_800_000_000

// Infinite is 1 for infinity, -1 for -infinity, else 0.
func (t Time) Infinite() int { return t.inf }

// UnixMicro is the time in Unix microseconds, ordered as PostgreSQL orders
// it against any Unix-microsecond time: infinity, and the finite times
// past what an int64 holds, become math.MaxInt64; -infinity
// math.MinInt64.
func (t Time) UnixMicro() int64 {
	switch {
	case t.inf > 0:
		return math.MaxInt64
	case t.inf < 0:
		return math.MinInt64
	case t.pg > math.MaxInt64-pgEpochUnixMicros:
		return math.MaxInt64
	}
	return t.pg + pgEpochUnixMicros
}

// Error is PostgreSQL's refusal of the text, with its SQLSTATE.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// DateTimeParseError's codes.
const (
	dtErrBadFormat       = -1
	dtErrFieldOverflow   = -2
	dtErrMDFieldOverflow = -3
	dtErrTZDispOverflow  = -5
	dtErrBadTimezone     = -6
	dtErrBadZoneAbbrev   = -7
)

func parseError(dterr int, text string) error {
	switch dterr {
	case dtErrFieldOverflow, dtErrMDFieldOverflow:
		return &Error{"22008", fmt.Sprintf("date/time field value out of range: %q", text)}
	case dtErrTZDispOverflow:
		return &Error{"22009", fmt.Sprintf("time zone displacement out of range: %q", text)}
	case dtErrBadTimezone:
		return &Error{"22023", "time zone not recognized"}
	case dtErrBadZoneAbbrev:
		return &Error{"22023", "time zone abbreviation not recognized"}
	}
	return &Error{"22007", fmt.Sprintf("invalid input syntax for type timestamp with time zone: %q", text)}
}

// Field types (ftype) and DTK values.
const (
	dtkNumber    = 0
	dtkString    = 1
	dtkDate      = 2
	dtkTime      = 3
	dtkTZ        = 4
	dtkSpecial   = 6
	dtkEarly     = 9
	dtkLate      = 10
	dtkEpoch     = 11
	dtkNow       = 12
	dtkYesterday = 13
	dtkToday     = 14
	dtkTomorrow  = 15
	dtkZulu      = 16
	dtkSecond    = 18
	dtkMinute    = 19
	dtkHour      = 20
	dtkDay       = 21
	dtkMonth     = 23
	dtkYear      = 25
	dtkJulian    = 31
	dtkDOW       = 32
	dtkDOY       = 33
	dtkISOYear   = 36
	dtkISODOW    = 37
)

// Token types.
const (
	reservType   = 0
	monthType    = 1
	yearType     = 2
	dayType      = 3
	tzType       = 5
	dtzType      = 6
	dynTZType    = 7
	ignoreType   = 8
	ampmType     = 9
	hourType     = 10
	minuteType   = 11
	secondType   = 12
	msType       = 13
	usType       = 14
	doyType      = 15
	dowType      = 16
	unitsType    = 17
	adbcType     = 18
	isoTimeType  = 23
	dtzModType   = 28
	unknownField = 31
)

func dtkM(t int) int64 { return 1 << t }

var (
	dateM = dtkM(yearType) | dtkM(monthType) | dtkM(dayType)
	timeM = dtkM(hourType) | dtkM(minuteType) | dtkM(secondType) | dtkM(msType) | dtkM(usType)
)

const (
	am   = 0
	pm   = 1
	hr24 = 2
	bcV  = 1

	maxDateLen    = 128
	maxDateFields = 25
	tokMaxLen     = 10

	usecsPerSec  = 1_000_000
	usecsPerDay  = 86_400_000_000
	usecsPerHour = 3_600_000_000
	usecsPerMin  = 60_000_000

	unixEpochJDate     = 2440588
	postgresEpochJDate = 2451545
	minTimestamp       = -211813488000000000
	endTimestamp       = 9223371331200000000
	maxTZDispHour      = 15
)

type token struct {
	kind  int
	value int
	zone  string
}

// datetktbl is datetktbl: date/time keywords.
var datetktbl = map[string]token{
	"+infinity": {kind: reservType, value: dtkLate},
	"-infinity": {kind: reservType, value: dtkEarly},
	"ad":        {kind: adbcType, value: 0},
	"allballs":  {kind: reservType, value: dtkZulu},
	"am":        {kind: ampmType, value: am},
	"apr":       {kind: monthType, value: 4},
	"april":     {kind: monthType, value: 4},
	"at":        {kind: ignoreType},
	"aug":       {kind: monthType, value: 8},
	"august":    {kind: monthType, value: 8},
	"bc":        {kind: adbcType, value: bcV},
	"d":         {kind: unitsType, value: dtkDay},
	"dec":       {kind: monthType, value: 12},
	"december":  {kind: monthType, value: 12},
	"dow":       {kind: unitsType, value: dtkDOW},
	"doy":       {kind: unitsType, value: dtkDOY},
	"dst":       {kind: dtzModType, value: 3600},
	"epoch":     {kind: reservType, value: dtkEpoch},
	"feb":       {kind: monthType, value: 2},
	"february":  {kind: monthType, value: 2},
	"fri":       {kind: dowType, value: 5},
	"friday":    {kind: dowType, value: 5},
	"h":         {kind: unitsType, value: dtkHour},
	"infinity":  {kind: reservType, value: dtkLate},
	"isodow":    {kind: unitsType, value: dtkISODOW},
	"isoyear":   {kind: unitsType, value: dtkISOYear},
	"j":         {kind: unitsType, value: dtkJulian},
	"jan":       {kind: monthType, value: 1},
	"january":   {kind: monthType, value: 1},
	"jd":        {kind: unitsType, value: dtkJulian},
	"jul":       {kind: monthType, value: 7},
	"julian":    {kind: unitsType, value: dtkJulian},
	"july":      {kind: monthType, value: 7},
	"jun":       {kind: monthType, value: 6},
	"june":      {kind: monthType, value: 6},
	"m":         {kind: unitsType, value: dtkMonth},
	"mar":       {kind: monthType, value: 3},
	"march":     {kind: monthType, value: 3},
	"may":       {kind: monthType, value: 5},
	"mm":        {kind: unitsType, value: dtkMinute},
	"mon":       {kind: dowType, value: 1},
	"monday":    {kind: dowType, value: 1},
	"nov":       {kind: monthType, value: 11},
	"november":  {kind: monthType, value: 11},
	"now":       {kind: reservType, value: dtkNow},
	"oct":       {kind: monthType, value: 10},
	"october":   {kind: monthType, value: 10},
	"on":        {kind: ignoreType},
	"pm":        {kind: ampmType, value: pm},
	"s":         {kind: unitsType, value: dtkSecond},
	"sat":       {kind: dowType, value: 6},
	"saturday":  {kind: dowType, value: 6},
	"sep":       {kind: monthType, value: 9},
	"sept":      {kind: monthType, value: 9},
	"september": {kind: monthType, value: 9},
	"sun":       {kind: dowType, value: 0},
	"sunday":    {kind: dowType, value: 0},
	"t":         {kind: isoTimeType, value: dtkTime},
	"thu":       {kind: dowType, value: 4},
	"thur":      {kind: dowType, value: 4},
	"thurs":     {kind: dowType, value: 4},
	"thursday":  {kind: dowType, value: 4},
	"today":     {kind: reservType, value: dtkToday},
	"tomorrow":  {kind: reservType, value: dtkTomorrow},
	"tue":       {kind: dowType, value: 2},
	"tues":      {kind: dowType, value: 2},
	"tuesday":   {kind: dowType, value: 2},
	"wed":       {kind: dowType, value: 3},
	"wednesday": {kind: dowType, value: 3},
	"weds":      {kind: dowType, value: 3},
	"y":         {kind: unitsType, value: dtkYear},
	"yesterday": {kind: reservType, value: dtkYesterday},
}

// search is datebsearch: tokens are compared on their first TOKMAXLEN
// characters, as stored tokens are truncated to that.
func search(tbl map[string]token, key string) (token, bool) {
	if t, ok := tbl[key]; ok {
		return t, true
	}
	if len(key) > tokMaxLen {
		if t, ok := tbl[key[:tokMaxLen]]; ok {
			return t, true
		}
	}
	return token{}, false
}

// The C library's character classes, in the C locale (and for bytes past
// ASCII, PostgreSQL's UTF-8 locales): none of them takes such a byte.
func isSpace(c byte) bool { return c == ' ' || c >= '\t' && c <= '\r' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
func isPunct(c byte) bool { return c > ' ' && c < 0x7f && !isAlnum(c) }
func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// parseDateTime is ParseDateTime: the text in fields, lowercased, each
// with its type; the fields and their terminators share a buffer of
// MAXDATELEN + MAXDATEFIELDS bytes.
func parseDateTime(s string) ([]string, []int, int) {
	const buflen = maxDateLen + maxDateFields
	used := 0
	var fields []string
	var ftypes []int
	at := func(i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	i := 0
	for at(i) != 0 {
		c := at(i)
		if isSpace(c) {
			i++
			continue
		}
		if len(fields) >= maxDateFields {
			return nil, nil, dtErrBadFormat
		}
		var f []byte
		full := false
		app := func(c byte) {
			if used+1 >= buflen {
				full = true
				return
			}
			f = append(f, c)
			used++
		}
		var ft int
		switch {
		case isDigit(c):
			app(c)
			i++
			for isDigit(at(i)) {
				app(at(i))
				i++
			}
			if d := at(i); d == ':' {
				ft = dtkTime
				app(d)
				i++
				for isDigit(at(i)) || at(i) == ':' || at(i) == '.' {
					app(at(i))
					i++
				}
			} else if d == '-' || d == '/' || d == '.' {
				app(d)
				i++
				if isDigit(at(i)) {
					ft = dtkDate
					if d == '.' {
						ft = dtkNumber
					}
					for isDigit(at(i)) {
						app(at(i))
						i++
					}
					if at(i) == d {
						ft = dtkDate
						app(d)
						i++
						for isDigit(at(i)) || at(i) == d {
							app(at(i))
							i++
						}
					}
				} else {
					ft = dtkDate
					for isAlnum(at(i)) || at(i) == d {
						app(lower(at(i)))
						i++
					}
				}
			} else {
				ft = dtkNumber
			}
		case c == '.':
			app(c)
			i++
			for isDigit(at(i)) {
				app(at(i))
				i++
			}
			ft = dtkNumber
		case isAlpha(c):
			ft = dtkString
			app(lower(c))
			i++
			for isAlpha(at(i)) {
				app(lower(at(i)))
				i++
			}
			isDate := false
			if n := at(i); n == '-' || n == '/' || n == '.' {
				isDate = true
			} else if n == '+' || isDigit(n) {
				if _, ok := search(datetktbl, string(f)); !ok {
					isDate = true
				}
			}
			if isDate {
				ft = dtkDate
				for {
					app(lower(at(i)))
					i++
					n := at(i)
					if !(n == '+' || n == '-' || n == '/' || n == '_' || n == '.' || n == ':' || isAlnum(n)) {
						break
					}
				}
			}
		case c == '+' || c == '-':
			app(c)
			i++
			for isSpace(at(i)) {
				i++
			}
			switch n := at(i); {
			case isDigit(n):
				ft = dtkTZ
				app(n)
				i++
				for isDigit(at(i)) || at(i) == ':' || at(i) == '.' || at(i) == '-' {
					app(at(i))
					i++
				}
			case isAlpha(n):
				ft = dtkSpecial
				app(lower(n))
				i++
				for isAlpha(at(i)) {
					app(lower(at(i)))
					i++
				}
			default:
				return nil, nil, dtErrBadFormat
			}
		case isPunct(c):
			i++
			continue
		default:
			return nil, nil, dtErrBadFormat
		}
		if full {
			return nil, nil, dtErrBadFormat
		}
		used++ // the field's terminator
		fields = append(fields, string(f))
		ftypes = append(ftypes, ft)
	}
	return fields, ftypes, 0
}

// strtol is the C library's strtol(s[i:], &end, 10) on a 64-bit long: the
// value, the index just past the number (i itself when there is none) and
// whether it was out of range (the value saturated).
func strtol(s string, i int) (int64, int, bool) {
	start := i
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	if i >= len(s) || !isDigit(s[i]) {
		return 0, start, false
	}
	var v uint64
	over := false
	for i < len(s) && isDigit(s[i]) {
		d := uint64(s[i] - '0')
		if v > (math.MaxUint64-d)/10 {
			over = true
		} else {
			v = v*10 + d
		}
		i++
	}
	switch {
	case !neg && (over || v > math.MaxInt64):
		return math.MaxInt64, i, true
	case neg && (over || v > 1<<63):
		return math.MinInt64, i, true
	case neg:
		return -int64(v), i, false
	}
	return int64(v), i, false
}

// strtoint is PostgreSQL's strtoint: strtol, out of range when the value
// does not fit an int, which it is then truncated to.
func strtoint(s string, i int) (int, int, bool) {
	v, end, rng := strtol(s, i)
	if v != int64(int32(v)) {
		rng = true
	}
	return int(int32(v)), end, rng
}

// atoi is the C library's atoi: (int) strtol(s, NULL, 10).
func atoi(s string) int {
	v, _, _ := strtol(s, 0)
	return int(int32(v))
}

// strtod is strtod on text beginning with '.': the value and how much of
// the text it read (none for a '.' without digits).
func strtod(s string) (float64, int) {
	j := 1
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	if j == 1 {
		return 0, 0
	}
	v, _ := strconv.ParseFloat("0"+s[:j], 64)
	return v, j
}

// parseFraction is ParseFraction: the text, starting with '.', as a
// fraction; all of it must be read.
func parseFraction(s string) (float64, int) {
	if len(s) == 1 {
		return 0, 0
	}
	v, n := strtod(s)
	if n != len(s) {
		return 0, dtErrBadFormat
	}
	return v, 0
}

func parseFractionalSecond(s string) (int64, int) {
	f, dterr := parseFraction(s)
	if dterr != 0 {
		return 0, dterr
	}
	return int64(math.RoundToEven(f * 1_000_000)), 0
}

// pgTm is struct pg_tm's fields the input reads.
type pgTm struct {
	year, mon, mday, hour, min, sec, yday int
}

// date2j is date2j, in int arithmetic that wraps as PostgreSQL's -fwrapv
// build does.
func date2j(year, month, day int) int {
	y, m, d := int32(year), int32(month), int32(day)
	if m > 2 {
		m++
		y += 4800
	} else {
		m += 13
		y += 4799
	}
	century := y / 100
	julian := y*365 - 32167
	julian += y/4 - century + century/4
	julian += 7834*m/256 + d
	return int(julian)
}

// j2date is j2date, in its unsigned arithmetic.
func j2date(jd int) (int, int, int) {
	julian := uint32(int32(jd))
	julian += 32044
	quad := julian / 146097
	extra := (julian-quad*146097)*4 + 3
	julian += 60 + quad*3 + extra/146097
	quad = julian / 1461
	julian -= quad * 1461
	y := int32(julian * 4 / 1461)
	if y != 0 {
		julian = (julian+305)%365 + 123
	} else {
		julian = (julian+306)%366 + 123
	}
	y += int32(quad * 4)
	year := int(y - 4800)
	quad = julian * 2141 / 65536
	day := int(int32(julian - 7834*quad/256))
	month := int((quad+10)%12 + 1)
	return year, month, day
}

func isleap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

var dayTab = [2][13]int{
	{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 0},
	{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 0},
}

func validJulian(y, m, d int) bool {
	return (y > -4713 || (y == -4713 && m >= 11)) && (y < 5874898 || (y == 5874898 && m < 6))
}

// decoder is DecodeDateTime's state.
type decoder struct {
	tm       pgTm
	fsec     int64
	tz       int
	fmask    int64
	is2digit bool
	now      time.Time
	zones    *Zones
}

// Parse is timestamptz_in in a UTC session: now is the transaction's
// start, which now, today, tomorrow and yesterday read; zone names are
// looked up in zones.
func Parse(text string, now time.Time, zones *Zones) (Time, error) {
	if strings.IndexByte(text, 0) >= 0 {
		return Time{}, &Error{"22021", "invalid byte sequence for encoding \"UTF8\": 0x00"}
	}
	fields, ftypes, dterr := parseDateTime(text)
	if dterr != 0 {
		return Time{}, parseError(dterr, text)
	}
	d := decoder{now: now.UTC(), zones: zones}
	dtype, dterr := d.decodeDateTime(fields, ftypes)
	if dterr != 0 {
		return Time{}, parseError(dterr, text)
	}
	switch dtype {
	case dtkEpoch:
		return Time{pg: -pgEpochUnixMicros}, nil
	case dtkLate:
		return Time{inf: 1}, nil
	case dtkEarly:
		return Time{inf: -1}, nil
	}
	ts, ok := tm2timestamp(d.tm, d.fsec, d.tz)
	if !ok {
		return Time{}, &Error{"22008", fmt.Sprintf("timestamp out of range: %q", text)}
	}
	return Time{pg: ts}, nil
}

// tm2timestamp is tm2timestamp with a zone offset (seconds west).
func tm2timestamp(tm pgTm, fsec int64, tz int) (int64, bool) {
	if !validJulian(tm.year, tm.mon, tm.mday) {
		return 0, false
	}
	date := int64(date2j(tm.year, tm.mon, tm.mday)) - postgresEpochJDate
	t := int64(int32((int32(tm.hour)*60+int32(tm.min))*60+int32(tm.sec)))*usecsPerSec + fsec
	result := date*usecsPerDay + t
	if (result-t)/usecsPerDay != date {
		return 0, false
	}
	if (result < 0 && date > 0) || (result > 0 && date < -1) {
		return 0, false
	}
	result += int64(tz) * usecsPerSec
	if !(minTimestamp <= result && result < endTimestamp) {
		return 0, false
	}
	return result, true
}

// currentTm is GetCurrentTimeUsec in a UTC session.
func (d *decoder) currentTm() (pgTm, int64) {
	n := d.now
	return pgTm{year: n.Year(), mon: int(n.Month()), mday: n.Day(), hour: n.Hour(), min: n.Minute(), sec: n.Second()},
		int64(n.Nanosecond() / 1000)
}

func (d *decoder) decodeDateTime(field []string, ftype []int) (int, int) {
	tm := &d.tm
	ptype := 0
	mer := hr24
	haveTextMonth := false
	isjulian := false
	bc := false
	var namedTz, abbrevTz *state
	abbrev := ""
	dtype := dtkDate
	d.fsec, d.tz = 0, 0

	for i := 0; i < len(field); i++ {
		var tmask int64
		f := field[i]
		switch ftype[i] {
		case dtkDate:
			if ptype == dtkJulian {
				jday, cp, rng := strtoint(f, 0)
				if rng || jday < 0 {
					return 0, dtErrFieldOverflow
				}
				tm.year, tm.mon, tm.mday = j2date(jday)
				isjulian = true
				tz, dterr := decodeTimezone(f[cp:])
				if dterr != 0 {
					return 0, dterr
				}
				d.tz = tz
				tmask = dateM | timeM | dtkM(tzType)
				ptype = 0
				break
			}
			if ptype != 0 || d.fmask&(dtkM(monthType)|dtkM(dayType)) == dtkM(monthType)|dtkM(dayType) {
				if isDigit(f[0]) || ptype != 0 {
					if ptype != 0 {
						if ptype != dtkTime {
							return 0, dtErrBadFormat
						}
						ptype = 0
					}
					if d.fmask&timeM == timeM {
						return 0, dtErrBadFormat
					}
					cp := strings.IndexByte(f, '-')
					if cp < 0 {
						return 0, dtErrBadFormat
					}
					tz, dterr := decodeTimezone(f[cp:])
					if dterr != 0 {
						return 0, dterr
					}
					d.tz = tz
					m, dterr := d.decodeNumberField(f[:cp], d.fmask)
					if dterr < 0 {
						return 0, dterr
					}
					tmask = m | dtkM(tzType)
				} else {
					if namedTz = d.zones.tzset(f); namedTz == nil {
						return 0, dtErrBadTimezone
					}
					tmask = dtkM(tzType)
				}
			} else {
				m, dterr := d.decodeDate(f, d.fmask)
				if dterr != 0 {
					return 0, dterr
				}
				tmask = m
			}
		case dtkTime:
			if ptype != 0 {
				if ptype != dtkTime {
					return 0, dtErrBadFormat
				}
				ptype = 0
			}
			h, m, s, fsec, dterr := decodeTime(f)
			if dterr != 0 {
				return 0, dterr
			}
			tm.hour, tm.min, tm.sec, d.fsec = h, m, s, fsec
			tmask = timeM
			if timeOverflows(tm.hour, tm.min, tm.sec, d.fsec) {
				return 0, dtErrFieldOverflow
			}
		case dtkTZ:
			tz, dterr := decodeTimezone(f)
			if dterr != 0 {
				return 0, dterr
			}
			d.tz = tz
			tmask = dtkM(tzType)
		case dtkNumber:
			if ptype != 0 {
				value, cp, rng := strtoint(f, 0)
				if rng {
					return 0, dtErrFieldOverflow
				}
				if c := byteAt(f, cp); c != '.' && c != 0 {
					return 0, dtErrBadFormat
				}
				switch ptype {
				case dtkJulian:
					if value < 0 {
						return 0, dtErrFieldOverflow
					}
					tmask = dateM
					tm.year, tm.mon, tm.mday = j2date(value)
					isjulian = true
					if byteAt(f, cp) == '.' {
						frac, dterr := parseFraction(f[cp:])
						if dterr != 0 {
							return 0, dterr
						}
						t := int64(frac * usecsPerDay)
						tm.hour = int(t / usecsPerHour)
						t -= int64(tm.hour) * usecsPerHour
						tm.min = int(t / usecsPerMin)
						t -= int64(tm.min) * usecsPerMin
						tm.sec = int(t / usecsPerSec)
						d.fsec = t - int64(tm.sec)*usecsPerSec
						tmask |= timeM
					}
				case dtkTime:
					m, dterr := d.decodeNumberField(f, d.fmask|dateM)
					if dterr < 0 {
						return 0, dterr
					}
					tmask = m
					if tmask != timeM {
						return 0, dtErrBadFormat
					}
				default:
					return 0, dtErrBadFormat
				}
				ptype = 0
				dtype = dtkDate
			} else {
				flen := len(f)
				cp := strings.IndexByte(f, '.')
				switch {
				case cp >= 0 && d.fmask&dateM == 0:
					m, dterr := d.decodeDate(f, d.fmask)
					if dterr != 0 {
						return 0, dterr
					}
					tmask = m
				case cp >= 0 && cp > 2:
					m, dterr := d.decodeNumberField(f, d.fmask)
					if dterr < 0 {
						return 0, dterr
					}
					tmask = m
				case flen >= 6 && (d.fmask&dateM == 0 || d.fmask&timeM == 0):
					m, dterr := d.decodeNumberField(f, d.fmask)
					if dterr < 0 {
						return 0, dterr
					}
					tmask = m
				default:
					m, dterr := d.decodeNumber(flen, f, haveTextMonth, d.fmask)
					if dterr != 0 {
						return 0, dterr
					}
					tmask = m
				}
			}
		case dtkString, dtkSpecial:
			typ, val := unknownField, 0
			var valtz *state
			if t, ok := search(abbrevs, f); ok {
				typ = t.kind
				if t.kind == dynTZType {
					if valtz = d.zones.tzset(t.zone); valtz == nil {
						return 0, dtErrBadZoneAbbrev
					}
				} else {
					val = t.value
				}
			}
			if typ == unknownField {
				if t, ok := search(datetktbl, f); ok {
					typ, val = t.kind, t.value
				}
			}
			if typ == ignoreType {
				continue
			}
			tmask = dtkM(typ)
			switch typ {
			case reservType:
				switch val {
				case dtkNow:
					tmask = dateM | timeM | dtkM(tzType)
					dtype = dtkDate
					*tm, d.fsec = d.currentTm()
					d.tz = 0
				case dtkYesterday, dtkToday, dtkTomorrow:
					tmask = dateM
					dtype = dtkDate
					cur, _ := d.currentTm()
					tm.year, tm.mon, tm.mday = j2date(date2j(cur.year, cur.mon, cur.mday) + (val - dtkToday))
				case dtkZulu:
					tmask = timeM | dtkM(tzType)
					dtype = dtkDate
					tm.hour, tm.min, tm.sec = 0, 0, 0
					d.tz = 0
				case dtkEpoch, dtkLate, dtkEarly:
					tmask = dateM | timeM | dtkM(tzType)
					dtype = val
				}
			case monthType:
				if d.fmask&dtkM(monthType) != 0 && !haveTextMonth && d.fmask&dtkM(dayType) == 0 && tm.mon >= 1 && tm.mon <= 31 {
					tm.mday = tm.mon
					tmask = dtkM(dayType)
				}
				haveTextMonth = true
				tm.mon = val
			case dtzModType:
				tmask |= dtkM(dtzType)
				d.tz -= val
			case dtzType:
				tmask |= dtkM(tzType)
				d.tz = -val
			case tzType:
				d.tz = -val
			case dynTZType:
				tmask |= dtkM(tzType)
				abbrevTz = valtz
				abbrev = f
			case ampmType:
				mer = val
			case adbcType:
				bc = val == bcV
			case dowType:
			case unitsType:
				tmask = 0
				if ptype != 0 {
					return 0, dtErrBadFormat
				}
				ptype = val
			case isoTimeType:
				tmask = 0
				if d.fmask&dateM != dateM {
					return 0, dtErrBadFormat
				}
				if ptype != 0 {
					return 0, dtErrBadFormat
				}
				ptype = val
			case unknownField:
				if namedTz = d.zones.tzset(f); namedTz == nil {
					return 0, dtErrBadFormat
				}
				tmask = dtkM(tzType)
			default:
				return 0, dtErrBadFormat
			}
		default:
			return 0, dtErrBadFormat
		}
		if tmask&d.fmask != 0 {
			return 0, dtErrBadFormat
		}
		d.fmask |= tmask
	}
	if ptype != 0 {
		return 0, dtErrBadFormat
	}
	if dtype == dtkDate {
		if dterr := d.validateDate(isjulian, bc); dterr != 0 {
			return 0, dterr
		}
		if mer != hr24 && tm.hour > 12 {
			return 0, dtErrFieldOverflow
		}
		if mer == am && tm.hour == 12 {
			tm.hour = 0
		} else if mer == pm && tm.hour != 12 {
			tm.hour += 12
		}
		if d.fmask&dateM != dateM {
			// A time alone (DecodeDateTime's 1) is refused as bad format too.
			return 0, dtErrBadFormat
		}
		if namedTz != nil {
			if d.fmask&dtkM(dtzModType) != 0 {
				return 0, dtErrBadFormat
			}
			d.tz = determineTimeZoneOffset(tm, namedTz)
		}
		if abbrevTz != nil {
			if d.fmask&dtkM(dtzModType) != 0 {
				return 0, dtErrBadFormat
			}
			d.tz = determineTimeZoneAbbrevOffset(tm, abbrev, abbrevTz)
		}
		if d.fmask&dtkM(tzType) == 0 {
			if d.fmask&dtkM(dtzModType) != 0 {
				return 0, dtErrBadFormat
			}
			// The session's zone is UTC.
			d.tz = 0
		}
	}
	return dtype, 0
}

func byteAt(s string, i int) byte {
	if i >= 0 && i < len(s) {
		return s[i]
	}
	return 0
}

// decodeDate is DecodeDate: a date with delimiters.
func (d *decoder) decodeDate(str string, fmask int64) (int64, int) {
	tm := &d.tm
	var tmask int64
	var fields []string
	i := 0
	for i < len(str) && len(fields) < maxDateFields {
		for i < len(str) && !isAlnum(str[i]) {
			i++
		}
		if i >= len(str) {
			return 0, dtErrBadFormat
		}
		start := i
		if isDigit(str[i]) {
			for i < len(str) && isDigit(str[i]) {
				i++
			}
		} else if isAlpha(str[i]) {
			for i < len(str) && isAlpha(str[i]) {
				i++
			}
		}
		fields = append(fields, str[start:i])
		if i < len(str) {
			i++ // the character after the field becomes its terminator
		}
	}
	haveTextMonth := false
	done := make([]bool, len(fields))
	for k, f := range fields {
		if f != "" && isAlpha(f[0]) {
			t, ok := search(datetktbl, f)
			typ, val := unknownField, 0
			if ok {
				typ, val = t.kind, t.value
			}
			if typ == ignoreType {
				continue
			}
			dmask := dtkM(typ)
			if typ != monthType {
				return 0, dtErrBadFormat
			}
			tm.mon = val
			haveTextMonth = true
			if fmask&dmask != 0 {
				return 0, dtErrBadFormat
			}
			fmask |= dmask
			tmask |= dmask
			done[k] = true
		}
	}
	for k, f := range fields {
		if done[k] {
			continue
		}
		if len(f) <= 0 {
			return 0, dtErrBadFormat
		}
		dmask, dterr := d.decodeNumber(len(f), f, haveTextMonth, fmask)
		if dterr != 0 {
			return 0, dterr
		}
		if fmask&dmask != 0 {
			return 0, dtErrBadFormat
		}
		fmask |= dmask
		tmask |= dmask
	}
	if fmask&^(dtkM(doyType)|dtkM(tzType)) != dateM {
		return 0, dtErrBadFormat
	}
	return tmask, 0
}

// validateDate is ValidateDate.
func (d *decoder) validateDate(isjulian, bc bool) int {
	tm, fmask := &d.tm, d.fmask
	if fmask&dtkM(yearType) != 0 {
		switch {
		case isjulian:
		case bc:
			if tm.year <= 0 {
				return dtErrFieldOverflow
			}
			tm.year = int(-(int32(tm.year) - 1))
		case d.is2digit:
			if tm.year < 0 {
				return dtErrFieldOverflow
			}
			if tm.year < 70 {
				tm.year += 2000
			} else if tm.year < 100 {
				tm.year += 1900
			}
		default:
			if tm.year <= 0 {
				return dtErrFieldOverflow
			}
		}
	}
	if fmask&dtkM(doyType) != 0 {
		tm.year, tm.mon, tm.mday = j2date(int(int32(date2j(tm.year, 1, 1)) + int32(tm.yday) - 1))
	}
	if fmask&dtkM(monthType) != 0 && (tm.mon < 1 || tm.mon > 12) {
		return dtErrMDFieldOverflow
	}
	if fmask&dtkM(dayType) != 0 && (tm.mday < 1 || tm.mday > 31) {
		return dtErrMDFieldOverflow
	}
	if fmask&dateM == dateM {
		leap := 0
		if isleap(tm.year) {
			leap = 1
		}
		if tm.mday > dayTab[leap][tm.mon-1] {
			return dtErrFieldOverflow
		}
	}
	return 0
}

// decodeTime is DecodeTimeCommon and DecodeTime for a timestamp's time:
// hh:mm[:ss[.fff]] or mm:ss.fff.
func decodeTime(str string) (int, int, int, int64, int) {
	hour, cp, rng := strtol(str, 0)
	if rng {
		return 0, 0, 0, 0, dtErrFieldOverflow
	}
	if byteAt(str, cp) != ':' {
		return 0, 0, 0, 0, dtErrBadFormat
	}
	min, cp, rng := strtoint(str, cp+1)
	if rng {
		return 0, 0, 0, 0, dtErrFieldOverflow
	}
	sec := 0
	var fsec int64
	switch byteAt(str, cp) {
	case 0:
	case '.':
		var dterr int
		if fsec, dterr = parseFractionalSecond(str[cp:]); dterr != 0 {
			return 0, 0, 0, 0, dterr
		}
		if hour > math.MaxInt32 || hour < math.MinInt32 {
			return 0, 0, 0, 0, dtErrFieldOverflow
		}
		sec, min, hour = min, int(hour), 0
	case ':':
		var dterr int
		sec, cp, rng = strtoint(str, cp+1)
		if rng {
			return 0, 0, 0, 0, dtErrFieldOverflow
		}
		if byteAt(str, cp) == '.' {
			if fsec, dterr = parseFractionalSecond(str[cp:]); dterr != 0 {
				return 0, 0, 0, 0, dterr
			}
		} else if byteAt(str, cp) != 0 {
			return 0, 0, 0, 0, dtErrBadFormat
		}
	default:
		return 0, 0, 0, 0, dtErrBadFormat
	}
	if hour < 0 || min < 0 || min > 59 || sec < 0 || sec > 60 || fsec < 0 || fsec > usecsPerSec {
		return 0, 0, 0, 0, dtErrFieldOverflow
	}
	if hour > math.MaxInt32 {
		return 0, 0, 0, 0, dtErrFieldOverflow
	}
	return int(hour), min, sec, fsec, 0
}

func timeOverflows(hour, min, sec int, fsec int64) bool {
	if hour < 0 || hour > 24 || min < 0 || min >= 60 || sec < 0 || sec > 60 || fsec < 0 || fsec > usecsPerSec {
		return true
	}
	return ((int64(hour)*60+int64(min))*60+int64(sec))*usecsPerSec+fsec > usecsPerDay
}

// decodeNumber is DecodeNumber: a plain number in the date's context.
func (d *decoder) decodeNumber(flen int, str string, haveTextMonth bool, fmask int64) (int64, int) {
	tm := &d.tm
	var tmask int64
	val, cp, rng := strtoint(str, 0)
	if rng {
		return 0, dtErrFieldOverflow
	}
	if cp == 0 {
		return 0, dtErrBadFormat
	}
	if byteAt(str, cp) == '.' {
		if cp > 2 {
			m, dterr := d.decodeNumberField(str, fmask|dateM)
			if dterr < 0 {
				return 0, dterr
			}
			return m, 0
		}
		fsec, dterr := parseFractionalSecond(str[cp:])
		if dterr != 0 {
			return 0, dterr
		}
		d.fsec = fsec
	} else if byteAt(str, cp) != 0 {
		return 0, dtErrBadFormat
	}
	if flen == 3 && fmask&dateM == dtkM(yearType) && val >= 1 && val <= 366 {
		tm.yday = val
		return dtkM(doyType) | dtkM(monthType) | dtkM(dayType), 0
	}
	switch fmask & dateM {
	case 0:
		// DateStyle's order is MDY.
		if flen >= 3 {
			tmask = dtkM(yearType)
			tm.year = val
		} else {
			tmask = dtkM(monthType)
			tm.mon = val
		}
	case dtkM(yearType):
		tmask = dtkM(monthType)
		tm.mon = val
	case dtkM(monthType):
		if haveTextMonth {
			if flen >= 3 {
				tmask = dtkM(yearType)
				tm.year = val
			} else {
				tmask = dtkM(dayType)
				tm.mday = val
			}
		} else {
			tmask = dtkM(dayType)
			tm.mday = val
		}
	case dtkM(yearType) | dtkM(monthType):
		if haveTextMonth {
			if flen >= 3 && d.is2digit {
				tmask = dtkM(dayType)
				tm.mday = tm.year
				tm.year = val
				d.is2digit = false
			} else {
				tmask = dtkM(dayType)
				tm.mday = val
			}
		} else {
			tmask = dtkM(dayType)
			tm.mday = val
		}
	case dtkM(dayType):
		tmask = dtkM(monthType)
		tm.mon = val
	case dtkM(monthType) | dtkM(dayType):
		tmask = dtkM(yearType)
		tm.year = val
	case dtkM(yearType) | dtkM(monthType) | dtkM(dayType):
		m, dterr := d.decodeNumberField(str, fmask)
		if dterr < 0 {
			return 0, dterr
		}
		return m, 0
	default:
		return 0, dtErrBadFormat
	}
	if tmask == dtkM(yearType) {
		d.is2digit = flen <= 2
	}
	return tmask, 0
}

// decodeNumberField is DecodeNumberField: a run-together date or time.
// Its result is the mask found, or a DTERR code (negative).
func (d *decoder) decodeNumberField(str string, fmask int64) (int64, int) {
	tm := &d.tm
	if cp := strings.IndexByte(str, '.'); cp >= 0 {
		if cp+1 == len(str) {
			d.fsec = 0
		} else {
			frac, _ := strtod(str[cp:])
			d.fsec = int64(math.RoundToEven(frac * 1_000_000))
		}
		str = str[:cp]
	} else if fmask&dateM != dateM {
		if n := len(str); n >= 6 {
			tm.mday = atoi(str[n-2:])
			tm.mon = atoi(str[n-4 : n-2])
			tm.year = atoi(str[:n-4])
			if n-4 == 2 {
				d.is2digit = true
			}
			return dateM, 1
		}
	}
	if fmask&timeM != timeM {
		switch len(str) {
		case 6:
			tm.sec = atoi(str[4:])
			tm.min = atoi(str[2:4])
			tm.hour = atoi(str[:2])
			return timeM, 1
		case 4:
			tm.sec = 0
			tm.min = atoi(str[2:])
			tm.hour = atoi(str[:2])
			return timeM, 1
		}
	}
	return 0, dtErrBadFormat
}

// decodeTimezone is DecodeTimezone: +-hh[:mm[:ss]] or +-hhmm, as seconds
// west of UTC.
func decodeTimezone(str string) (int, int) {
	if c := byteAt(str, 0); c != '+' && c != '-' {
		return 0, dtErrBadFormat
	}
	hr, cp, rng := strtoint(str, 1)
	if rng {
		return 0, dtErrTZDispOverflow
	}
	min, sec := 0, 0
	switch {
	case byteAt(str, cp) == ':':
		if min, cp, rng = strtoint(str, cp+1); rng {
			return 0, dtErrTZDispOverflow
		}
		if byteAt(str, cp) == ':' {
			if sec, cp, rng = strtoint(str, cp+1); rng {
				return 0, dtErrTZDispOverflow
			}
		}
	case cp >= len(str) && len(str) > 3:
		min = hr % 100
		hr = hr / 100
	}
	if hr < 0 || hr > maxTZDispHour || min < 0 || min >= 60 || sec < 0 || sec >= 60 {
		return 0, dtErrTZDispOverflow
	}
	tz := (hr*60+min)*60 + sec
	if str[0] == '-' {
		tz = -tz
	}
	if cp < len(str) {
		return 0, dtErrBadFormat
	}
	return -tz, 0
}

// determineTimeZoneOffsetInternal is DetermineTimeZoneOffsetInternal: the
// zone's offset (seconds west) for the local time, and the UTC time it
// imputes; a time it cannot place is taken as UTC.
func determineTimeZoneOffsetInternal(tm *pgTm, sp *state) (int, int64) {
	if !validJulian(tm.year, tm.mon, tm.mday) {
		return 0, 0
	}
	date := int64(int32(date2j(tm.year, tm.mon, tm.mday)) - unixEpochJDate)
	day := date * secsPerDay
	sec := int64(int32(tm.sec + (tm.min+tm.hour*60)*60))
	mytime := day + sec
	if mytime < 0 && day > 0 {
		return 0, 0
	}
	prevtime := mytime - secsPerDay
	if mytime < 0 && prevtime > 0 {
		return 0, 0
	}
	res, beforeOff, _, boundary, afterOff, _ := nextDSTBoundary(prevtime, sp)
	if res < 0 {
		return 0, 0
	}
	if res == 0 {
		return int(-beforeOff), mytime - beforeOff
	}
	beforetime := mytime - beforeOff
	if (beforeOff > 0 && mytime < 0 && beforetime > 0) || (beforeOff <= 0 && mytime > 0 && beforetime < 0) {
		return 0, 0
	}
	aftertime := mytime - afterOff
	if (afterOff > 0 && mytime < 0 && aftertime > 0) || (afterOff <= 0 && mytime > 0 && aftertime < 0) {
		return 0, 0
	}
	if beforetime < boundary && aftertime < boundary {
		return int(-beforeOff), beforetime
	}
	if beforetime > boundary && aftertime >= boundary {
		return int(-afterOff), aftertime
	}
	if beforetime > aftertime {
		return int(-beforeOff), beforetime
	}
	return int(-afterOff), aftertime
}

func determineTimeZoneOffset(tm *pgTm, sp *state) int {
	off, _ := determineTimeZoneOffsetInternal(tm, sp)
	return off
}

// determineTimeZoneAbbrevOffset is DetermineTimeZoneAbbrevOffset: the
// abbreviation's offset in the zone at the local time, when the zone's
// data uses it, else the zone's.
func determineTimeZoneAbbrevOffset(tm *pgTm, abbr string, sp *state) int {
	zoneOffset, t := determineTimeZoneOffsetInternal(tm, sp)
	up := upper(abbr)
	if len(up) > tzStrlenMax {
		up = up[:tzStrlenMax]
	}
	if gmtoff, ok := interpretAbbrev(up, t, sp); ok {
		return int(-gmtoff)
	}
	return zoneOffset
}
