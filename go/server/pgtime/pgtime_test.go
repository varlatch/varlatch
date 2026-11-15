// SPDX-License-Identifier: AGPL-3.0-or-later

package pgtime

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"testing"
	"time"
)

// testdata/timestamptz-vectors.json is PostgreSQL 17.6's reading of each
// input as text::timestamptz in a UTC session (postgres:17.6, tzdata
// 2025b): microseconds since 2000-01-01 UTC, infinity, -infinity or "ERROR <SQLSTATE>",
// with the transaction's now() (Unix microseconds) the relative inputs
// read. testdata/zoneinfo
// holds that server's tz files for the zones the inputs name, so the
// comparison does not depend on the host's tz database.
type vectors struct {
	Now     string      `json:"now"`
	Vectors [][2]string `json:"vectors"`
}

func render(t Time, err error) string {
	var pe *Error
	switch {
	case errors.As(err, &pe):
		return "ERROR " + pe.Code
	case err != nil:
		return "ERROR " + err.Error()
	case t.Infinite() > 0:
		return "infinity"
	case t.Infinite() < 0:
		return "-infinity"
	}
	return strconv.FormatInt(t.pg, 10)
}

func TestPostgresVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/timestamptz-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	us, err := strconv.ParseInt(v.Now, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMicro(us)
	zones := NewZones("testdata/zoneinfo")
	failed := 0
	for _, c := range v.Vectors {
		got := render(Parse(c[0], now, zones))
		if got != c[1] {
			failed++
			if failed <= 60 {
				t.Errorf("%q: got %s, PostgreSQL %s", c[0], got, c[1])
			}
		}
	}
	if failed > 0 {
		t.Errorf("%d of %d inputs differ", failed, len(v.Vectors))
	}
}

func TestUnixMicroOrdersAsPostgres(t *testing.T) {
	zones := NewZones("testdata/zoneinfo")
	at := func(s string) int64 {
		v, err := Parse(s, time.Unix(0, 0), zones)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		return v.UnixMicro()
	}
	if got := at("epoch"); got != 0 {
		t.Errorf("epoch: %d", got)
	}
	if got := at("2026-01-02 03:04:05.678901+02"); got != time.Date(2026, 1, 2, 1, 4, 5, 678901000, time.UTC).UnixMicro() {
		t.Errorf("an instant: %d", got)
	}
	// Past what Unix microseconds hold in an int64, a time still sorts
	// after every stored one, as infinity does; -infinity before all.
	if got := at("294276-12-31 23:59:59.999999"); got != math.MaxInt64 {
		t.Errorf("the last timestamp: %d", got)
	}
	if got := at("infinity"); got != math.MaxInt64 {
		t.Errorf("infinity: %d", got)
	}
	if got := at("-infinity"); got != math.MinInt64 {
		t.Errorf("-infinity: %d", got)
	}
	if got := at("4714-11-24 00:00:00+00 BC"); got != minTimestamp+pgEpochUnixMicros {
		t.Errorf("the first timestamp: %d", got)
	}
}

func TestRelativeTimesReadTheClock(t *testing.T) {
	now := time.Date(2026, 3, 4, 23, 59, 58, 123456000, time.UTC)
	zones := NewZones("testdata/zoneinfo")
	for in, want := range map[string]time.Time{
		"now":             now,
		"today":           time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC),
		"tomorrow":        time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC),
		"yesterday":       time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC),
		"today 12:00 +02": time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC),
	} {
		v, err := Parse(in, now, zones)
		if err != nil || v.UnixMicro() != want.UnixMicro() {
			t.Errorf("%q: %v %v, want %v", in, v.UnixMicro(), err, want.UnixMicro())
		}
	}
}

func TestTextPostgresCannotReceive(t *testing.T) {
	_, err := Parse("2026-01-02\x00", time.Now(), NewZones("testdata/zoneinfo"))
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != "22021" {
		t.Fatalf("NUL: %v", err)
	}
}

func TestZonesWithoutADatabase(t *testing.T) {
	// No tz database: names are unknown, POSIX zone strings still read.
	zones := NewZones(t.TempDir() + "/none")
	if _, err := Parse("2026-01-02 Europe/Brussels", time.Now(), zones); err == nil {
		t.Error("a zone name read without a database")
	}
	v, err := Parse("2026-01-02 xyz5", time.Now(), zones)
	if err != nil || v.UnixMicro() != time.Date(2026, 1, 2, 5, 0, 0, 0, time.UTC).UnixMicro() {
		t.Errorf("xyz5: %v %v", v.UnixMicro(), err)
	}
}
