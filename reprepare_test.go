// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"strings"
	"testing"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

// TestCachedStmtNotReprepared runs a cached statement repeatedly through both
// the exec and the query paths and checks SQLite never re-prepares it. Since
// SQLite 3.54, sqlite3_clear_bindings expires a statement whose plan depends
// on a parameter value, as a "col = ?" term of a join or an ORDER BY query
// does, which made every execution parse and plan the statement again.
//
// https://gitlab.com/cznic/sqlite/-/issues/264
func TestCachedStmtNotReprepared(t *testing.T) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	sc, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	if _, err := sc.ExecContext(ctx, `
		CREATE TABLE a(id INTEGER PRIMARY KEY, v);
		CREATE TABLE b(x, aid);
		CREATE INDEX b_x ON b(x);
		INSERT INTO a VALUES (1, 'one'), (2, 'two');
		INSERT INTO b VALUES (5, 1), (5, 2), (6, 2);
	`); err != nil {
		t.Fatal(err)
	}

	for _, query := range []string{
		"SELECT a.v FROM a JOIN b ON b.aid = a.id WHERE b.x = ?",
		"SELECT aid FROM b WHERE x = ? ORDER BY aid",
		"SELECT aid FROM b WHERE x = ?",
	} {
		t.Run(query, func(t *testing.T) {
			if err := sc.Raw(func(driverConn any) error {
				c := driverConn.(*conn)
				ds, err := c.Prepare(query)
				if err != nil {
					return err
				}
				defer ds.Close()

				s := ds.(*stmt)
				if s.pstmt == 0 {
					t.Fatal("statement is not cached")
				}

				const runs = 10
				args := []driver.NamedValue{{Ordinal: 1, Value: int64(5)}}
				for i := 0; i < runs; i++ {
					if _, err := s.ExecContext(ctx, args); err != nil {
						return err
					}

					r, err := s.QueryContext(ctx, args)
					if err != nil {
						return err
					}
					dest := make([]driver.Value, 1)
					n := 0
					for ; ; n++ {
						if err := r.Next(dest); err == io.EOF {
							break
						} else if err != nil {
							return err
						}
					}
					if err := r.Close(); err != nil {
						return err
					}
					if n != 2 {
						t.Fatalf("run %d: got %d rows, want 2", i, n)
					}
				}

				if n := sqlite3.Xsqlite3_stmt_status(c.tls, s.pstmt, sqlite3.SQLITE_STMTSTATUS_REPREPARE, 0); n != 0 {
					t.Errorf("re-prepared %d times in %d executions", n, 2*runs)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// runCached runs the cached statement s once through exec and once through
// query with args, draining the rows, and returns an error from either.
func runCached(ctx context.Context, s *stmt, args []driver.NamedValue) error {
	if _, err := s.ExecContext(ctx, args); err != nil {
		return err
	}
	r, err := s.QueryContext(ctx, args)
	if err != nil {
		return err
	}
	dest := make([]driver.Value, 1)
	for {
		if err := r.Next(dest); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	return r.Close()
}

func reprepareCount(c *conn, s *stmt) int32 {
	return sqlite3.Xsqlite3_stmt_status(c.tls, s.pstmt, sqlite3.SQLITE_STMTSTATUS_REPREPARE, 0)
}

// expandedSQL returns sqlite3_expanded_sql of pstmt, the SQL with the bound
// values in place of its parameters.
func expandedSQL(c *conn, pstmt uintptr) string {
	p := sqlite3.Xsqlite3_expanded_sql(c.tls, pstmt)
	defer sqlite3.Xsqlite3_free(c.tls, p)
	return libc.GoString(p)
}

// TestCachedStmtNotRepreparedSmallInt is TestCachedStmtNotReprepared with the
// values 0 and 1, which SQLite 3.54 treats specially: binding a "col = ?"
// parameter of a join or of an ORDER BY query to 0 or 1 when it was anything
// else, NULL included, re-prepares the statement, and so does the reverse. The
// first execution may re-prepare once, as the value replaces the NULL the
// statement was planned with; the driver keeps integer bindings in place
// between executions, so none of the later ones does.
func TestCachedStmtNotRepreparedSmallInt(t *testing.T) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	sc, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	if _, err := sc.ExecContext(ctx, `
		CREATE TABLE a(id INTEGER PRIMARY KEY, v);
		CREATE TABLE b(x, aid);
		CREATE INDEX b_x ON b(x);
		INSERT INTO a VALUES (1, 'one'), (2, 'two');
		INSERT INTO b VALUES (0, 1), (1, 2), (5, 2);
	`); err != nil {
		t.Fatal(err)
	}

	for _, query := range []string{
		"SELECT a.v FROM a JOIN b ON b.aid = a.id WHERE b.x = ?",
		"SELECT aid FROM b WHERE x = ? ORDER BY aid",
		"SELECT aid FROM b WHERE x = ?",
	} {
		t.Run(query, func(t *testing.T) {
			if err := sc.Raw(func(driverConn any) error {
				c := driverConn.(*conn)
				ds, err := c.Prepare(query)
				if err != nil {
					return err
				}
				defer ds.Close()

				s := ds.(*stmt)
				arg := func(v int64) []driver.NamedValue { return []driver.NamedValue{{Ordinal: 1, Value: v}} }
				if err := runCached(ctx, s, arg(1)); err != nil {
					return err
				}
				before := reprepareCount(c, s)
				if before > 1 {
					t.Errorf("the first execution re-prepared %d times, want at most 1", before)
				}

				const runs = 10
				for i := 0; i < runs; i++ {
					if err := runCached(ctx, s, arg(int64(i&1))); err != nil {
						return err
					}
				}
				if n := reprepareCount(c, s) - before; n != 0 {
					t.Errorf("re-prepared %d times in %d executions", n, 2*runs)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCachedStmtTextUnbound checks that a text argument's buffer is unbound
// from a cached statement once the statement has run, so the statement never
// points into memory the driver has freed, and that unbinding it does not
// re-prepare the statement. An integer argument stays bound, which is what
// keeps TestCachedStmtNotRepreparedSmallInt from re-preparing.
func TestCachedStmtTextUnbound(t *testing.T) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	sc, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	if _, err := sc.ExecContext(ctx, `
		CREATE TABLE c(k TEXT, n);
		INSERT INTO c VALUES ('a', 1), ('b', 2);
	`); err != nil {
		t.Fatal(err)
	}

	if err := sc.Raw(func(driverConn any) error {
		c := driverConn.(*conn)
		ds, err := c.Prepare("SELECT n FROM c WHERE k = ? AND n = ? ORDER BY n")
		if err != nil {
			return err
		}
		defer ds.Close()

		s := ds.(*stmt)
		args := []driver.NamedValue{{Ordinal: 1, Value: "a"}, {Ordinal: 2, Value: int64(1)}}
		// The first execution re-prepares once: n = 1 replaces the NULL the
		// statement was planned with, see TestCachedStmtNotRepreparedSmallInt.
		if err := runCached(ctx, s, args); err != nil {
			return err
		}
		before := reprepareCount(c, s)
		const runs = 10
		for i := 0; i < runs; i++ {
			if _, err := s.ExecContext(ctx, args); err != nil {
				return err
			}
			if got := expandedSQL(c, s.pstmt); !strings.Contains(got, "k = NULL AND n = 1 ") {
				t.Fatalf("after exec %d: %q", i, got)
			}
			if err := runCached(ctx, s, args); err != nil {
				return err
			}
			if got := expandedSQL(c, s.pstmt); !strings.Contains(got, "k = NULL AND n = 1 ") {
				t.Fatalf("after query %d: %q", i, got)
			}
		}
		if n := reprepareCount(c, s) - before; n != 0 {
			t.Errorf("re-prepared %d times in %d executions", n, 3*runs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
