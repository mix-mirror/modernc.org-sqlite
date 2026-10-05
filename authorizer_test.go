// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	sqlite3 "modernc.org/sqlite/lib"
)

func authorizerConn(t *testing.T) (*sql.DB, *sql.Conn) {
	t.Helper()
	db, err := sql.Open(driverName, filepath.Join(t.TempDir(), "authorizer.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('one')`); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	return db, conn
}

func registerAuthorizer(t *testing.T, conn *sql.Conn, fn AuthorizerFn) {
	t.Helper()
	if err := conn.Raw(func(driverConn any) error {
		registerer, ok := driverConn.(AuthorizerRegisterer)
		if !ok {
			return fmt.Errorf("driver connection does not implement AuthorizerRegisterer")
		}
		return registerer.RegisterAuthorizer(fn)
	}); err != nil {
		t.Fatal(err)
	}
}

func requireAuthorizerError(t *testing.T, err error) {
	t.Helper()
	var sqliteErr *Error
	if !errors.As(err, &sqliteErr) {
		t.Fatalf("error = %v (%T), want *Error", err, err)
	}
	if got := sqliteErr.Code(); got != sqlite3.SQLITE_AUTH {
		t.Fatalf("error code = %d, want SQLITE_AUTH (%d): %v", got, sqlite3.SQLITE_AUTH, err)
	}
}

func TestAuthorizerInstallReplaceRemove(t *testing.T) {
	_, conn := authorizerConn(t)

	var firstCalls, replacementCalls atomic.Int64
	registerAuthorizer(t, conn, func(action AuthorizerActionCode, _, _, _, _ string) AuthorizerReturnCode {
		firstCalls.Add(1)
		if action == AuthSelect || action == AuthRead {
			return AuthorizerOK
		}
		return AuthorizerDeny
	})

	var got string
	if err := conn.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got); err != nil {
		t.Fatalf("allowed SELECT: %v", err)
	}
	if got != "one" {
		t.Fatalf("SELECT returned %q, want one", got)
	}
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO t VALUES ('two')`); err == nil {
		t.Fatal("INSERT succeeded under a read-only authorizer")
	}

	registerAuthorizer(t, conn, func(AuthorizerActionCode, string, string, string, string) AuthorizerReturnCode {
		replacementCalls.Add(1)
		return AuthorizerDeny
	})
	firstBefore := firstCalls.Load()
	if err := conn.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got); err == nil {
		t.Fatal("SELECT succeeded after replacing the authorizer with deny-all")
	}
	if firstCalls.Load() != firstBefore {
		t.Fatal("replaced authorizer was called")
	}
	if replacementCalls.Load() == 0 {
		t.Fatal("replacement authorizer was not called")
	}

	registerAuthorizer(t, conn, nil)
	if err := conn.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got); err != nil {
		t.Fatalf("SELECT after removing authorizer: %v", err)
	}
}

func TestAuthorizerReturnCodes(t *testing.T) {
	_, conn := authorizerConn(t)

	registerAuthorizer(t, conn, func(action AuthorizerActionCode, _, _, _, _ string) AuthorizerReturnCode {
		if action == AuthRead {
			return AuthorizerIgnore
		}
		return AuthorizerOK
	})
	var got sql.NullString
	if err := conn.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got.Valid {
		t.Fatalf("ignored column returned %q, want NULL", got.String)
	}

	registerAuthorizer(t, conn, func(AuthorizerActionCode, string, string, string, string) AuthorizerReturnCode {
		return AuthorizerReturnCode(9999)
	})
	if err := conn.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got); err == nil {
		t.Fatal("invalid authorizer return code did not fail statement preparation")
	}
}

func TestAuthorizerCallbackArguments(t *testing.T) {
	_, conn := authorizerConn(t)
	if _, err := conn.ExecContext(context.Background(), `
		CREATE TABLE audit(v TEXT);
		CREATE TRIGGER t_after_insert AFTER INSERT ON t BEGIN
			INSERT INTO audit(v) VALUES (new.v);
		END;
	`); err != nil {
		t.Fatal(err)
	}

	type authorizerCall struct {
		action                      AuthorizerActionCode
		arg1, arg2                  string
		databaseName, triggerOrView string
	}
	var calls []authorizerCall
	registerAuthorizer(t, conn, func(action AuthorizerActionCode, arg1, arg2, databaseName, triggerOrView string) AuthorizerReturnCode {
		calls = append(calls, authorizerCall{action, arg1, arg2, databaseName, triggerOrView})
		return AuthorizerOK
	})
	hasCall := func(want authorizerCall) bool {
		for _, got := range calls {
			if got == want {
				return true
			}
		}
		return false
	}

	var got string
	if err := conn.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	// SQLite supplies NULL for triggerOrView on a direct read. The public API
	// deliberately represents it as the empty string.
	if want := (authorizerCall{AuthRead, "t", "v", "main", ""}); !hasCall(want) {
		t.Fatalf("direct read calls = %#v, want %#v", calls, want)
	}

	calls = nil
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO t VALUES ('two')`); err != nil {
		t.Fatal(err)
	}
	// SQLite supplies NULL for arg2 on INSERT. The public API deliberately
	// represents it as the empty string.
	if want := (authorizerCall{AuthInsert, "audit", "", "main", "t_after_insert"}); !hasCall(want) {
		t.Fatalf("trigger calls = %#v, want %#v", calls, want)
	}
}

func TestAuthorizerPreparedAndRepreparedStatement(t *testing.T) {
	db, conn := authorizerConn(t)
	allow := func(AuthorizerActionCode, string, string, string, string) AuthorizerReturnCode {
		return AuthorizerOK
	}
	deny := func(AuthorizerActionCode, string, string, string, string) AuthorizerReturnCode {
		return AuthorizerDeny
	}
	stmt, err := conn.PrepareContext(context.Background(), `SELECT v FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()

	var got string
	if err := stmt.QueryRowContext(context.Background()).Scan(&got); err != nil {
		t.Fatalf("prepared statement before installing authorizer: %v", err)
	}

	// sqlite3_set_authorizer expires prepared statements unconditionally.
	// Installation, replacement, and removal must therefore transparently
	// reprepare this same statement and apply the then-current policy.
	registerAuthorizer(t, conn, deny)
	if err := stmt.QueryRowContext(context.Background()).Scan(&got); err == nil {
		t.Fatal("prepared statement succeeded after installing deny-all authorizer")
	} else {
		requireAuthorizerError(t, err)
	}
	registerAuthorizer(t, conn, allow)
	if err := stmt.QueryRowContext(context.Background()).Scan(&got); err != nil {
		t.Fatalf("prepared statement after replacing authorizer with allow-all: %v", err)
	}
	registerAuthorizer(t, conn, deny)
	if err := stmt.QueryRowContext(context.Background()).Scan(&got); err == nil {
		t.Fatal("prepared statement succeeded after replacing authorizer with deny-all")
	} else {
		requireAuthorizerError(t, err)
	}
	registerAuthorizer(t, conn, nil)
	if err := stmt.QueryRowContext(context.Background()).Scan(&got); err != nil {
		t.Fatalf("prepared statement after removing authorizer: %v", err)
	}

	var denyReprepare atomic.Bool
	var reprepareReadCalls atomic.Int64
	registerAuthorizer(t, conn, func(action AuthorizerActionCode, _, _, _, _ string) AuthorizerReturnCode {
		if action == AuthRead {
			reprepareReadCalls.Add(1)
			if denyReprepare.Load() {
				return AuthorizerDeny
			}
		}
		return AuthorizerOK
	})
	reprepared, err := conn.PrepareContext(context.Background(), `SELECT v FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	defer reprepared.Close()
	if err := reprepared.QueryRowContext(context.Background()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	denyReprepare.Store(true)
	readCallsBefore := reprepareReadCalls.Load()
	if err := reprepared.QueryRowContext(context.Background()).Scan(&got); err != nil {
		t.Fatalf("prepared statement was reauthorized without schema change: %v", err)
	}
	if readCalls := reprepareReadCalls.Load(); readCalls != readCallsBefore {
		t.Fatalf("prepared statement made %d authorizer read calls without schema change, want 0", readCalls-readCallsBefore)
	}

	db.SetMaxOpenConns(2)
	if _, err := db.Exec(`ALTER TABLE t ADD COLUMN extra`); err != nil {
		t.Fatal(err)
	}
	readCallsBefore = reprepareReadCalls.Load()
	if err := reprepared.QueryRowContext(context.Background()).Scan(&got); err == nil {
		t.Fatal("statement succeeded after schema invalidation required reauthorization")
	}
	if readCalls := reprepareReadCalls.Load(); readCalls <= readCallsBefore {
		t.Fatal("schema-invalidated statement did not invoke the installed authorizer")
	}
}

func TestAuthorizerDriverTransactionStatements(t *testing.T) {
	_, conn := authorizerConn(t)

	var beginSeen atomic.Bool
	registerAuthorizer(t, conn, func(action AuthorizerActionCode, arg1, _, _, _ string) AuthorizerReturnCode {
		if action == AuthTransaction && arg1 == "BEGIN" {
			beginSeen.Store(true)
			return AuthorizerDeny
		}
		return AuthorizerOK
	})
	if _, err := conn.BeginTx(context.Background(), nil); err == nil {
		t.Fatal("BeginTx succeeded when the authorizer denied BEGIN")
	} else {
		requireAuthorizerError(t, err)
	}
	if !beginSeen.Load() {
		t.Fatal("driver-issued BEGIN did not reach the authorizer")
	}

	registerAuthorizer(t, conn, func(AuthorizerActionCode, string, string, string, string) AuthorizerReturnCode {
		return AuthorizerOK
	})
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var commitSeen, rollbackSeen atomic.Bool
	registerAuthorizer(t, conn, func(action AuthorizerActionCode, arg1, _, _, _ string) AuthorizerReturnCode {
		if action != AuthTransaction {
			return AuthorizerOK
		}
		switch arg1 {
		case "COMMIT":
			commitSeen.Store(true)
			return AuthorizerDeny
		case "ROLLBACK":
			rollbackSeen.Store(true)
		}
		return AuthorizerOK
	})
	if err := tx.Commit(); err == nil {
		t.Fatal("Commit succeeded when the authorizer denied COMMIT")
	} else {
		requireAuthorizerError(t, err)
	}
	if !commitSeen.Load() {
		t.Fatal("driver-issued COMMIT did not reach the authorizer")
	}
	if !rollbackSeen.Load() {
		t.Fatal("failed Commit did not issue the cleanup ROLLBACK")
	}
}

func TestAuthorizerConnectionPoolReuse(t *testing.T) {
	db, conn := authorizerConn(t)
	var calls atomic.Int64
	registerAuthorizer(t, conn, func(AuthorizerActionCode, string, string, string, string) AuthorizerReturnCode {
		calls.Add(1)
		return AuthorizerDeny
	})
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	reused, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reused.Close()
	var got string
	if err := reused.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got); err == nil {
		t.Fatal("pooled connection lost its authorizer")
	}
	if calls.Load() == 0 {
		t.Fatal("authorizer was not invoked after pool reuse")
	}
}

func TestAuthorizerRegisterConnectionHookPool(t *testing.T) {
	const n = 4
	d := &Driver{}
	var opened atomic.Int64
	d.RegisterConnectionHook(func(driverConn ExecQuerierContext, _ string) error {
		opened.Add(1)
		registerer, ok := driverConn.(AuthorizerRegisterer)
		if !ok {
			return fmt.Errorf("driver connection does not implement AuthorizerRegisterer")
		}
		return registerer.RegisterAuthorizer(func(action AuthorizerActionCode, _, _, _, _ string) AuthorizerReturnCode {
			if action == AuthSelect {
				return AuthorizerDeny
			}
			return AuthorizerOK
		})
	})

	name := uniqueDriverName(t)
	sql.Register(name, d)
	db, err := sql.Open(name, filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(n)
	t.Cleanup(func() { db.Close() })

	connections := make([]*sql.Conn, 0, n)
	for i := 0; i < n; i++ {
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	t.Cleanup(func() {
		for _, conn := range connections {
			conn.Close()
		}
	})
	if got := opened.Load(); got != n {
		t.Fatalf("connection hooks called %d times, want %d distinct physical connections", got, n)
	}

	for i, conn := range connections {
		var got int
		err := conn.QueryRowContext(context.Background(), `SELECT 1`).Scan(&got)
		if err == nil {
			t.Fatalf("connection %d allowed forbidden SELECT", i)
		}
		requireAuthorizerError(t, err)
	}
}

func TestAuthorizerCloseCleanup(t *testing.T) {
	c, err := newConn(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db := c.db
	if err := c.RegisterAuthorizer(func(AuthorizerActionCode, string, string, string, string) AuthorizerReturnCode {
		return AuthorizerOK
	}); err != nil {
		t.Fatal(err)
	}
	xAuthorizers.mu.RLock()
	_, registered := xAuthorizers.m[db]
	xAuthorizers.mu.RUnlock()
	if !registered {
		t.Fatal("authorizer was not registered")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	xAuthorizers.mu.RLock()
	_, registered = xAuthorizers.m[db]
	xAuthorizers.mu.RUnlock()
	if registered {
		t.Fatal("closed connection retained its authorizer")
	}
	if got := authorizerTrampoline(nil, db, sqlite3.SQLITE_SELECT, 0, 0, 0, 0); got != sqlite3.SQLITE_DENY {
		t.Fatalf("late callback returned %d, want SQLITE_DENY", got)
	}
}

func TestAuthorizerConcurrentConnections(t *testing.T) {
	const n = 8
	type testConn struct {
		conn  *sql.Conn
		table string
	}
	connections := make([]testConn, 0, n)
	for i := 0; i < n; i++ {
		table := fmt.Sprintf("t_%d", i)
		db, err := sql.Open(driverName, ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(fmt.Sprintf(`CREATE TABLE %s(v TEXT); INSERT INTO %s VALUES ('value-%d')`, table, table, i)); err != nil {
			db.Close()
			t.Fatal(err)
		}
		conn, err := db.Conn(context.Background())
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			conn.Close()
			db.Close()
		})
		connections = append(connections, testConn{conn, table})
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for i, tc := range connections {
		wg.Add(1)
		go func(i int, tc testConn) {
			defer wg.Done()
			<-start
			var seen atomic.Bool
			if err := tc.conn.Raw(func(driverConn any) error {
				registerer, ok := driverConn.(AuthorizerRegisterer)
				if !ok {
					return fmt.Errorf("driver connection does not implement AuthorizerRegisterer")
				}
				return registerer.RegisterAuthorizer(func(action AuthorizerActionCode, arg1, arg2, databaseName, triggerOrView string) AuthorizerReturnCode {
					if action == AuthRead {
						if arg1 != tc.table || arg2 != "v" || databaseName != "main" || triggerOrView != "" {
							return AuthorizerDeny
						}
						seen.Store(true)
					}
					return AuthorizerOK
				})
			}); err != nil {
				errs <- fmt.Errorf("connection %d register: %w", i, err)
				return
			}
			var got string
			if err := tc.conn.QueryRowContext(context.Background(), fmt.Sprintf(`SELECT v FROM %s`, tc.table)).Scan(&got); err != nil {
				errs <- fmt.Errorf("connection %d query: %w", i, err)
				return
			}
			if want := fmt.Sprintf("value-%d", i); got != want {
				errs <- fmt.Errorf("connection %d value = %q, want %q", i, got, want)
				return
			}
			if !seen.Load() {
				errs <- fmt.Errorf("connection %d authorizer was not invoked", i)
			}
		}(i, tc)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
