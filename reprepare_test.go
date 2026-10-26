// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"testing"

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
