// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestColumnTextScan exercises the rows.Scan TEXT-column path that
// (*conn).columnText feeds. The test covers the three branches of that
// function: NULL (returned as empty string), empty string, and non-empty
// values of varying lengths. A regression on the unsafe.String pattern would
// either truncate the result, expose Go-heap garbage, or trip the race
// detector under -race.
func TestColumnTextScan(t *testing.T) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)`); err != nil {
		t.Fatal(err)
	}

	long := strings.Repeat("a1B2c3D4", 256) // 2048 bytes, well past inline storage
	cases := []struct {
		id int64
		s  string
	}{
		{1, "hello"},
		{2, ""},
		{3, "unicode é 中文 \U0001F600"},
		{4, long},
	}
	for _, c := range cases {
		if _, err := db.Exec(`INSERT INTO t(id, s) VALUES (?, ?)`, c.id, c.s); err != nil {
			t.Fatalf("insert id=%d: %v", c.id, err)
		}
	}

	for _, c := range cases {
		var got string
		if err := db.QueryRow(`SELECT s FROM t WHERE id = ?`, c.id).Scan(&got); err != nil {
			t.Fatalf("scan id=%d: %v", c.id, err)
		}
		if got != c.s {
			t.Errorf("id=%d: got %q (len %d), want %q (len %d)", c.id, got, len(got), c.s, len(c.s))
		}
	}

	// Read all rows in a single query so columnText is invoked many times in
	// quick succession; a stale-pointer regression would surface here as the
	// last row's text bleeding into earlier rows.
	rows, err := db.Query(`SELECT s FROM t ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		got = append(got, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := []string{"hello", "", "unicode é 中文 \U0001F600", long}
	if len(got) != len(want) {
		t.Fatalf("row count: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("row %d: got %q (len %d), want %q (len %d)", i, got[i], len(got[i]), want[i], len(want[i]))
		}
	}
}

// benchColumnTextScan exercises the rows.Scan TEXT path many times so the
// per-row cost is dominated by (*conn).columnText, not by statement
// preparation or driver bookkeeping. textLen controls the per-row payload
// size; the default mode in conn.go did one make+one string(b)-copy per
// invocation, which means at small sizes the alloc count dominates and at
// large sizes the memcpy dominates.
func benchColumnTextScan(b *testing.B, textLen int) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (s TEXT)`); err != nil {
		b.Fatal(err)
	}

	payload := strings.Repeat("X", textLen)
	const rows = 1000
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO t (s) VALUES (?)`)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < rows; i++ {
		if _, err := stmt.Exec(payload); err != nil {
			b.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := db.Query(`SELECT s FROM t`)
		if err != nil {
			b.Fatal(err)
		}
		for r.Next() {
			var s string
			if err := r.Scan(&s); err != nil {
				b.Fatal(err)
			}
		}
		if err := r.Err(); err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
}

// BenchmarkColumnTextScanShort measures the rows.Scan TEXT path on a small
// payload where alloc count dominates the cost.
func BenchmarkColumnTextScanShort(b *testing.B) {
	benchColumnTextScan(b, 16)
}

// BenchmarkColumnTextScanMedium measures the rows.Scan TEXT path on a
// medium payload where both alloc count and memcpy contribute.
func BenchmarkColumnTextScanMedium(b *testing.B) {
	benchColumnTextScan(b, 256)
}

// BenchmarkColumnTextScanLong measures the rows.Scan TEXT path on a large
// payload where the second memcpy that the old string(b) conversion forced
// is the dominant cost.
func BenchmarkColumnTextScanLong(b *testing.B) {
	benchColumnTextScan(b, 4096)
}

// TestColumnTypeDatabaseTypeNameCache verifies that the rows decltype cache
// returns the same uppercase declared type for every row of a result set
// (across multiple Next calls) and matches the schema's declared type case-
// insensitively. The result is compared against a Next loop that reads the
// decltype on each row, so a stale or per-row regression would surface as a
// type-name mismatch between the two readers.
func TestColumnTypeDatabaseTypeNameCache(t *testing.T) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Mix declared types in different cases and across all SQLite storage
	// classes. The varied casing exercises the strings.ToUpper path of the
	// cache.
	if _, err := db.Exec(`CREATE TABLE t (a integer, b TEXT, c BlOb, d DATETIME, e Date, f boolean)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES (1, 'x', X'00', '2025-01-15 10:30:00', '2025-01-15', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES (2, 'y', X'01', '2025-01-16 11:00:00', '2025-01-16', 0)`); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query(`SELECT a, b, c, d, e, f FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	types, err := rows.ColumnTypes()
	if err != nil {
		t.Fatal(err)
	}
	wantTypes := []string{"INTEGER", "TEXT", "BLOB", "DATETIME", "DATE", "BOOLEAN"}
	if len(types) != len(wantTypes) {
		t.Fatalf("column count: got %d, want %d", len(types), len(wantTypes))
	}
	for i, ct := range types {
		if got := ct.DatabaseTypeName(); got != wantTypes[i] {
			t.Errorf("column %d: got %q, want %q", i, got, wantTypes[i])
		}
	}

	// Drain rows; reading the cache for every row of a multi-row scan must
	// keep returning the same values for the lifetime of the result set.
	rowCount := 0
	for rows.Next() {
		rowCount++
		for i, ct := range types {
			if got := ct.DatabaseTypeName(); got != wantTypes[i] {
				t.Errorf("row %d column %d: got %q, want %q (cache changed mid-scan)", rowCount, i, got, wantTypes[i])
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if rowCount != 2 {
		t.Errorf("row count: got %d, want 2", rowCount)
	}
}

// benchTextToTimeScan exercises the rows.Next + Scan path under
// _texttotime=1, which fires r.ColumnTypeDatabaseTypeName(i) for every TEXT
// column on every row to decide whether to parse the value as time. Before
// the decltype cache landed, each call did a libc.GoString + strings.ToUpper
// per row per column. With the cache the lookup is a single slice index.
func benchTextToTimeScan(b *testing.B, columnCount int) {
	db, err := sql.Open(driverName, "file::memory:?_texttotime=1")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	var schemaCols, selectCols, insertCols, insertVals []string
	for i := 0; i < columnCount; i++ {
		schemaCols = append(schemaCols, fmt.Sprintf("c%d DATETIME", i))
		selectCols = append(selectCols, fmt.Sprintf("c%d", i))
		insertCols = append(insertCols, fmt.Sprintf("c%d", i))
		insertVals = append(insertVals, "?")
	}
	if _, err := db.Exec(`CREATE TABLE t (` + strings.Join(schemaCols, ", ") + `)`); err != nil {
		b.Fatal(err)
	}

	const rows = 1000
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO t (` + strings.Join(insertCols, ", ") + `) VALUES (` + strings.Join(insertVals, ", ") + `)`)
	if err != nil {
		b.Fatal(err)
	}
	args := make([]any, columnCount)
	for i := 0; i < columnCount; i++ {
		args[i] = "2025-01-15 10:30:00"
	}
	for i := 0; i < rows; i++ {
		if _, err := stmt.Exec(args...); err != nil {
			b.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}

	query := `SELECT ` + strings.Join(selectCols, ", ") + ` FROM t`
	dest := make([]any, columnCount)
	destPtrs := make([]any, columnCount)
	for i := range dest {
		destPtrs[i] = &dest[i]
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := db.Query(query)
		if err != nil {
			b.Fatal(err)
		}
		for r.Next() {
			if err := r.Scan(destPtrs...); err != nil {
				b.Fatal(err)
			}
		}
		if err := r.Err(); err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
}

// BenchmarkTextToTimeScan1Col measures the _texttotime=1 hot path with a
// single DATETIME column, isolating the per-row decltype lookup cost.
func BenchmarkTextToTimeScan1Col(b *testing.B) {
	benchTextToTimeScan(b, 1)
}

// BenchmarkTextToTimeScan5Cols measures the same path with a wider result
// set so the cache savings scale linearly with column count.
func BenchmarkTextToTimeScan5Cols(b *testing.B) {
	benchTextToTimeScan(b, 5)
}

// TestColumnTypeScanTypeDecltypeCache locks down the ColumnTypeScanType comparison logic
// that was rewritten from a lowercase decltype switch to the cached uppercase
// switch. Each of the four arms that look at the cache (INTEGER -> BOOLEAN,
// INTEGER -> DATE/DATETIME/TIME/TIMESTAMP, TEXT default, TEXT under
// _texttotime -> DATE/DATETIME/TIME/TIMESTAMP) gets a column with a
// mixed-case declared type so a regression on the case-folding path would
// surface as a wrong reflect.Type for that column.
func TestColumnTypeScanTypeDecltypeCache(t *testing.T) {
	// Each case inserts one row before querying so ColumnTypeScanType sees
	// the actual storage class (sqlite3_column_type), not SQLITE_NULL.
	cases := []struct {
		dsn   string
		col   string
		value any
		want  reflect.Type
		label string
	}{
		// INTEGER + BOOLEAN decltype (case-insensitive) always returns bool.
		{"file::memory:", "b BoOlEaN", int64(1), reflect.TypeOf(false), "BOOLEAN INTEGER default"},
		{"file::memory:?_texttotime=1", "b boolean", int64(0), reflect.TypeOf(false), "BOOLEAN INTEGER + _texttotime"},

		// INTEGER + DATE/DATETIME/TIME/TIMESTAMP decltype always returns
		// time.Time independent of any DSN flag (the cache-driven switch
		// has no flag gate on the INTEGER arm).
		{"file::memory:", "d Date", int64(1736899200), reflect.TypeOf(time.Time{}), "DATE INTEGER default"},
		{"file::memory:", "dt datetime", int64(1736941800), reflect.TypeOf(time.Time{}), "DATETIME INTEGER default"},
		{"file::memory:", "tm TIME", int64(37800), reflect.TypeOf(time.Time{}), "TIME INTEGER default"},
		{"file::memory:", "ts TimeStamp", int64(1736941800), reflect.TypeOf(time.Time{}), "TIMESTAMP INTEGER default"},

		// INTEGER without a recognised decltype falls back to int64.
		{"file::memory:", "n integer", int64(42), reflect.TypeOf(int64(0)), "plain INTEGER default"},
		{"file::memory:", "x BIGINT", int64(42), reflect.TypeOf(int64(0)), "unrecognised INTEGER decltype"},

		// TEXT default returns string, even for DATETIME-shaped decltypes,
		// because the textToTime opt-in is off.
		{"file::memory:", "s TEXT", "hello", reflect.TypeOf(""), "plain TEXT default"},
		{"file::memory:", "dt DateTime", "2025-01-15 10:30:00", reflect.TypeOf(""), "DATETIME TEXT default (no textToTime)"},

		// TEXT under _texttotime=1 returns time.Time for the four recognised
		// decltypes (mixed case), and string for everything else.
		{"file::memory:?_texttotime=1", "d Date", "2025-01-15", reflect.TypeOf(time.Time{}), "DATE TEXT + _texttotime"},
		{"file::memory:?_texttotime=1", "dt DateTime", "2025-01-15 10:30:00", reflect.TypeOf(time.Time{}), "DATETIME TEXT + _texttotime"},
		{"file::memory:?_texttotime=1", "tm time", "10:30:00", reflect.TypeOf(time.Time{}), "TIME TEXT + _texttotime"},
		{"file::memory:?_texttotime=1", "ts TIMESTAMP", "2025-01-15 10:30:00", reflect.TypeOf(time.Time{}), "TIMESTAMP TEXT + _texttotime"},
		{"file::memory:?_texttotime=1", "s TEXT", "hello", reflect.TypeOf(""), "plain TEXT + _texttotime"},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			db, err := sql.Open(driverName, c.dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			if _, err := db.Exec(`CREATE TABLE t (` + c.col + `)`); err != nil {
				t.Fatalf("create table: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO t VALUES (?)`, c.value); err != nil {
				t.Fatalf("insert: %v", err)
			}
			rows, err := db.Query(`SELECT * FROM t`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			if !rows.Next() {
				t.Fatal("expected one row")
			}

			types, err := rows.ColumnTypes()
			if err != nil {
				t.Fatal(err)
			}
			if len(types) != 1 {
				t.Fatalf("column count: got %d, want 1", len(types))
			}
			if got := types[0].ScanType(); got != c.want {
				t.Errorf("ScanType: got %v, want %v", got, c.want)
			}
		})
	}
}

// TestParseTimeFormatCache verifies that the per-rows-per-column format-index
// hint reused by (*conn).parseTime keeps returning correct parsed time values
// across many rows of a steady-format column, and that a column whose format
// switches mid-result-set still parses correctly via the fallthrough path.
func TestParseTimeFormatCache(t *testing.T) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, dt DATETIME)`); err != nil {
		t.Fatal(err)
	}

	// First three rows use the same canonical SQLite TEXT format (matches
	// format index 2 of parseTimeFormats: "2006-01-02 15:04:05.999999999").
	// Row 4 uses the ISO-T format (matches index 3). Row 5 uses the
	// date-only fallback (index 6). After the cache stabilises on row 1, the
	// hinted format helps rows 2 and 3 directly and rows 4-5 fall through.
	values := []string{
		"2025-01-15 10:30:00",
		"2025-01-15 11:00:00",
		"2025-01-15 11:30:00",
		"2025-01-16T08:15:00",
		"2025-01-17",
	}
	for i, v := range values {
		if _, err := db.Exec(`INSERT INTO t(id, dt) VALUES (?, ?)`, i+1, v); err != nil {
			t.Fatalf("insert id=%d: %v", i+1, err)
		}
	}

	rows, err := db.Query(`SELECT dt FROM t ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	wantTimes := []time.Time{
		time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		time.Date(2025, 1, 15, 11, 0, 0, 0, time.UTC),
		time.Date(2025, 1, 15, 11, 30, 0, 0, time.UTC),
		time.Date(2025, 1, 16, 8, 15, 0, 0, time.UTC),
		time.Date(2025, 1, 17, 0, 0, 0, 0, time.UTC),
	}
	i := 0
	for rows.Next() {
		if i >= len(wantTimes) {
			t.Fatalf("too many rows; want %d", len(wantTimes))
		}
		var got time.Time
		if err := rows.Scan(&got); err != nil {
			t.Fatalf("row %d scan: %v", i, err)
		}
		if !got.Equal(wantTimes[i]) {
			t.Errorf("row %d: got %v, want %v", i, got, wantTimes[i])
		}
		i++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if i != len(wantTimes) {
		t.Fatalf("row count: got %d, want %d", i, len(wantTimes))
	}
}

// benchParseTimeScan exercises the rows.Next + Scan path on a DATETIME TEXT
// column. With the parseTime format-index cache, every row after the first
// hits the hinted format directly; without the cache, every row re-walks
// the parseTimeFormats list until it finds a match.
func benchParseTimeScan(b *testing.B) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (dt DATETIME)`); err != nil {
		b.Fatal(err)
	}

	const rows = 1000
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO t (dt) VALUES (?)`)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < rows; i++ {
		// Canonical SQLite TEXT datetime format (index 2 of
		// parseTimeFormats).
		if _, err := stmt.Exec("2025-01-15 10:30:00"); err != nil {
			b.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := db.Query(`SELECT dt FROM t`)
		if err != nil {
			b.Fatal(err)
		}
		var got time.Time
		for r.Next() {
			if err := r.Scan(&got); err != nil {
				b.Fatal(err)
			}
		}
		if err := r.Err(); err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
}

// BenchmarkParseTimeScan measures the rows.Next DATETIME TEXT path with the
// format-index cache active.
func BenchmarkParseTimeScan(b *testing.B) {
	benchParseTimeScan(b)
}

// Closing a connection must forget the hooks registered for its handle: the
// handle value can be reused by a connection opened later.
func TestHooksCloseCleanup(t *testing.T) {
	c, err := newConn(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db := c.db
	c.RegisterPreUpdateHook(func(SQLitePreUpdateData) {})
	c.RegisterCommitHook(func() int32 { return 0 })
	c.RegisterRollbackHook(func() {})
	registered := func() (preUpdate, commit, rollback bool) {
		xPreUpdateHandlers.mu.RLock()
		_, preUpdate = xPreUpdateHandlers.m[db]
		xPreUpdateHandlers.mu.RUnlock()
		xCommitHandlers.mu.RLock()
		_, commit = xCommitHandlers.m[db]
		xCommitHandlers.mu.RUnlock()
		xRollbackHandlers.mu.RLock()
		_, rollback = xRollbackHandlers.m[db]
		xRollbackHandlers.mu.RUnlock()
		return preUpdate, commit, rollback
	}
	if p, c, r := registered(); !p || !c || !r {
		t.Fatalf("hooks registered: pre-update %v, commit %v, rollback %v, want all true", p, c, r)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if p, c, r := registered(); p || c || r {
		t.Fatalf("closed connection retained hooks: pre-update %v, commit %v, rollback %v", p, c, r)
	}
}
