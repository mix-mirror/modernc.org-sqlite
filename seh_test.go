// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite // import "modernc.org/sqlite"

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sqlite3 "modernc.org/sqlite/lib"
)

// sehOpenWAL opens a WAL mode database on a single connection with some
// content, so that the -shm file exists and is mapped.
func sehOpenWAL(t *testing.T) (db *sql.DB, path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "seh.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}

	db.SetMaxOpenConns(1)
	for _, q := range []string{"CREATE TABLE t(x)", "INSERT INTO t VALUES(1),(2),(3)"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(path + "-shm"); err != nil || fi.Size() < 32768 {
		t.Fatalf("-shm: %v %v", fi, err)
	}

	return db, path
}

// sehWantInPage checks that err is the driver's rendering of
// SQLITE_IOERR_IN_PAGE: an *Error whose primary code is SQLITE_IOERR - the
// code is the extended one when the connection reports extended codes - and
// whose message is SQLite's "disk I/O error".
func sehWantInPage(t *testing.T, err error) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %T %v, want *sqlite.Error", err, err)
	}

	if c := e.Code(); c != sqlite3.SQLITE_IOERR && c != sqlite3.SQLITE_IOERR_IN_PAGE {
		t.Fatalf("got code %d (%v), want SQLITE_IOERR or SQLITE_IOERR_IN_PAGE", c, err)
	}

	if !strings.Contains(err.Error(), "disk I/O error") {
		t.Fatalf("got %v, want a disk I/O error", err)
	}
}

// sehEmulated reports whether the vendored library carries the SEH emulation
// (internal/sqlite_issue221.patch in modernc.org/libsqlite3): only then does a
// WAL read pass any SEH_INJECT_FAULT site.
func sehEmulated(db *sql.DB) bool {
	sqlite3.SehInject(1)
	defer sqlite3.SehInject(0)
	var n int
	db.QueryRow("SELECT count(*) FROM t").Scan(&n)
	return sqlite3.SehPending() == 0
}

// TestSEHTruncatedShm truncates the -shm file under the live mapping: the next
// access to the wal-index faults, which the SEH emulation must report as
// SQLITE_IOERR_IN_PAGE instead of crashing the process; once the file is
// restored the connection recovers.
func TestSEHTruncatedShm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a mapped file cannot be truncated on windows")
	}

	db, path := sehOpenWAL(t)
	defer db.Close()

	if !sehEmulated(db) {
		t.Skip("the vendored library has no SEH emulation")
	}

	shm := path + "-shm"
	if err := os.Truncate(shm, 0); err != nil {
		t.Fatal(err)
	}

	var n int
	sehWantInPage(t, db.QueryRow("SELECT count(*) FROM t").Scan(&n))

	if err := os.Truncate(shm, 32768); err != nil {
		t.Fatal(err)
	}

	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil || n != 3 {
		t.Fatalf("after restoring the -shm: n=%d err=%v", n, err)
	}

	if _, err := db.Exec("INSERT INTO t VALUES(4)"); err != nil {
		t.Fatal(err)
	}
}

// TestSEHInjectedFault raises a simulated fault at every SEH_INJECT_FAULT site
// that a read, a write and a checkpoint reach, one at a time, and checks that
// each surfaces as SQLITE_IOERR_IN_PAGE and that the connection works
// normally afterwards.
func TestSEHInjectedFault(t *testing.T) {
	db, _ := sehOpenWAL(t)
	defer db.Close()

	if !sehEmulated(db) {
		t.Skip("the vendored library has no SEH emulation")
	}

	for _, q := range []string{
		"SELECT count(*) FROM t",
		"INSERT INTO t VALUES(4)",
		"PRAGMA wal_checkpoint(PASSIVE)",
		"PRAGMA wal_checkpoint(TRUNCATE)",
	} {
		sites := 0
		for n := int32(1); ; n++ {
			sqlite3.SehInject(n)
			_, err := db.Exec(q)
			pending := sqlite3.SehPending()
			sqlite3.SehInject(0)
			if pending > 0 { // fewer than n sites reached: the statement ran to completion
				if err != nil {
					t.Fatalf("%s with %d pending sites: %v", q, pending, err)
				}

				break
			}

			sites++
			if err == nil {
				t.Fatalf("%s, simulated fault at site %d: no error", q, n)
			}

			sehWantInPage(t, err)
			var cnt int
			if err := db.QueryRow("SELECT count(*) FROM t").Scan(&cnt); err != nil {
				t.Fatalf("%s, after the simulated fault at site %d: %v", q, n, err)
			}
		}
		if sites == 0 {
			t.Fatalf("%s: no SEH_INJECT_FAULT site reached", q)
		}

		t.Logf("%-32s %d sites", q, sites)
	}
}
