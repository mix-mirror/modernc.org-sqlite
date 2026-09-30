// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Comparing the decoded time with Time.Equal is not sufficient: callers also
// bind that time in UPDATE/DELETE predicates, including optimistic queue locks.
func TestTimeParameterRoundTrip(t *testing.T) {
	original := time.Now()
	if !strings.Contains(original.String(), " m=") {
		t.Skip("time.Now does not contain a monotonic reading on this platform")
	}
	for _, columnType := range []string{"DATE", "DATETIME", "TIMESTAMP"} {
		for _, prepared := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/prepared=%t", columnType, prepared), func(t *testing.T) {
				db, err := sql.Open("sqlite", ":memory:?_time_format=string_no_monotonic")
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				db.SetMaxOpenConns(1)
				if _, err := db.Exec("CREATE TABLE events (deadline " + columnType + ", processed INTEGER NOT NULL DEFAULT 0)"); err != nil {
					t.Fatal(err)
				}
				exec := func(query string, args ...any) sql.Result {
					t.Helper()
					var result sql.Result
					var err error
					if prepared {
						var stmt *sql.Stmt
						stmt, err = db.Prepare(query)
						if err == nil {
							defer stmt.Close()
							result, err = stmt.Exec(args...)
						}
					} else {
						result, err = db.Exec(query, args...)
					}
					if err != nil {
						t.Fatal(err)
					}
					return result
				}
				exec("INSERT INTO events(deadline) VALUES (?)", original)
				var decoded time.Time
				if err := db.QueryRow("SELECT deadline FROM events").Scan(&decoded); err != nil {
					t.Fatal(err)
				}
				if !decoded.Equal(original) {
					t.Fatalf("wall time changed: got %v, want %v", decoded, original)
				}
				var stored string
				if err := db.QueryRow("SELECT CAST(deadline AS TEXT) FROM events").Scan(&stored); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(stored, " m=") {
					t.Errorf("stored process-local monotonic clock: %q", stored)
				}
				affected := func(result sql.Result) {
					t.Helper()
					n, err := result.RowsAffected()
					if err != nil {
						t.Fatal(err)
					}
					if n != 1 {
						t.Errorf("round-tripped timestamp matched %d rows, want 1 (stored=%q, decoded=%q)", n, stored, decoded.String())
					}
				}
				affected(exec("UPDATE events SET processed=1 WHERE deadline=?", decoded))
				affected(exec("DELETE FROM events WHERE deadline=?", decoded))
			})
		}
	}
}

func TestTimeDefaultFormatMonotonic(t *testing.T) {
	value := time.Now()
	if !strings.Contains(value.String(), " m=") {
		t.Skip("time.Now does not contain a monotonic reading on this platform")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE events (deadline TEXT UNIQUE)"); err != nil {
		t.Fatal(err)
	}
	// These values have identical wall clocks, but their String representations
	// must remain distinct under the default format.
	if _, err := db.Exec("INSERT INTO events VALUES (?), (?)", value, value.Round(0)); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow("SELECT deadline FROM events WHERE rowid=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != value.String() {
		t.Fatalf("default format changed: got %q, want %q", stored, value.String())
	}
}

func TestTimeStringFormats(t *testing.T) {
	for _, value := range []time.Time{
		time.Now(),
		{},
		time.Date(2021, 1, 2, 16, 39, 17, 123456789, time.UTC),
		time.Date(2021, 1, 2, 16, 39, 17, 123456789, time.FixedZone("CST", 8*60*60)),
		time.Date(2021, 1, 2, 16, 39, 17, 0, time.FixedZone("", -7*60*60)),
	} {
		for _, tc := range []struct {
			format string
			want   string
		}{
			{"", value.String()},
			{writeTimeFormats["string_no_monotonic"], value.Round(0).String()},
		} {
			c := &conn{writeTimeFormat: tc.format}
			if got := c.formatTime(value); got != tc.want {
				t.Errorf("format %q: got %q, want %q", tc.format, got, tc.want)
			}
		}
	}
}

// Existing strings remain readable; reading them must not silently rewrite the
// database. Applications must normalize old values before SQL equality matches.
func TestTimeLegacyMonotonicString(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:?_time_format=string_no_monotonic")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const legacy = "2021-01-02 16:39:17.123456789 +0000 UTC m=+1.234567890"
	if _, err := db.Exec("CREATE TABLE events (deadline DATETIME)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO events VALUES (?)", legacy); err != nil {
		t.Fatal(err)
	}
	var decoded time.Time
	if err := db.QueryRow("SELECT deadline FROM events").Scan(&decoded); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2021, 1, 2, 16, 39, 17, 123456789, time.UTC)
	if !decoded.Equal(want) {
		t.Fatalf("legacy timestamp: got %v, want %v", decoded, want)
	}
	var raw string
	if err := db.QueryRow("SELECT CAST(deadline AS TEXT) FROM events").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != legacy {
		t.Fatalf("reading rewrote a stored value: got %q", raw)
	}
}

func TestTimeStringNoMonotonicOptions(t *testing.T) {
	value := time.Now()
	for _, tc := range []struct {
		query string
		want  any
	}{
		{"_timezone=UTC", value.UTC().String()},
		{"_time_integer_format=unix_nano", value.UnixNano()},
	} {
		t.Run(tc.query, func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:?_time_format=string_no_monotonic&"+tc.query)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var got any
			if err := db.QueryRow("SELECT ?", value).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("stored value = %#v, want %#v", got, tc.want)
			}
		})
	}
}
