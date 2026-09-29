// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// TestArgFinder checks that argFinder.find returns what scanArgs, the linear
// scan it replaces, returns, for arguments ordered as database/sql passes
// them, where find takes its fast path, and for arguments that are not.
func TestArgFinder(t *testing.T) {
	names := []string{
		"", "?1", "?2", "?3", "?17", "?40", "?41", "?05", "?0",
		"?99999999999999999999", "?9223372036854775807",
		"$1", "$3", "$20", "$01", "$0", "$1a", "$a", "$b", "$05", "$x",
		":a", ":b", ":1", ":05", ":1a", ":missing", "@a", "@x",
	}
	argNames := []string{"", "", "", "a", "b", "1", "3", "17", "20", "05", "1a", "x"}
	rng := rand.New(rand.NewSource(42))
	for _, n := range []int{0, 1, 2, 3, 16, 17, 40} {
		for round := 0; round < 50; round++ {
			args := make([]driver.NamedValue, n)
			for j := range args {
				args[j] = driver.NamedValue{Name: argNames[rng.Intn(len(argNames))], Ordinal: j + 1, Value: int64(j)}
			}
			if round%2 == 1 && n != 0 {
				// Not how database/sql passes arguments: find must fall
				// back to the scan.
				switch rng.Intn(3) {
				case 0:
					rng.Shuffle(n, func(i, j int) { args[i].Ordinal, args[j].Ordinal = args[j].Ordinal, args[i].Ordinal })
				case 1:
					args[rng.Intn(n)].Ordinal = rng.Intn(n + 2)
				case 2:
					for j := range args {
						args[j].Ordinal = j
					}
				}
			}
			f := newArgFinder(args)
			for i := 1; i <= n+2; i++ {
				for _, name := range names {
					gotV, gotOK := f.find(name, i)
					wantV, wantOK := scanArgs(args, name, i)
					if gotV != wantV || gotOK != wantOK {
						t.Fatalf("n=%d round=%d find(%q, %d) = %+v, %v, want %+v, %v\nargs: %+v", n, round, name, i, gotV, gotOK, wantV, wantOK, args)
					}
				}
			}
		}
	}
}

// TestBindManyParameters binds statements with many parameters of each kind
// and checks every argument arrives at its parameter.
//
// https://github.com/modernc-org/sqlite/issues/8
func TestBindManyParameters(t *testing.T) {
	db, err := sql.Open(driverName, "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const n = 2000
	for _, kind := range []string{"?", "?N", "$N", ":name", "@name", "$name"} {
		t.Run(kind, func(t *testing.T) {
			args := make([]any, n)
			rows := make([]string, n)
			for i := range args {
				args[i] = int64(3*i + 1)
				var param string
				switch kind {
				case "?":
					param = "?"
				case "?N", "$N":
					param = fmt.Sprintf("%c%d", kind[0], i+1)
				default:
					param = fmt.Sprintf("%cp%d", kind[0], i)
					args[i] = sql.Named(fmt.Sprintf("p%d", i), args[i])
				}
				// Except for ?, whose position is its index, list the
				// parameters backwards, so SQLite numbers them in the
				// reverse order of their arguments.
				k := i
				if kind != "?" {
					k = n - 1 - i
				}
				rows[k] = fmt.Sprintf("(%d, %s)", i, param)
			}
			r, err := db.Query("select column1, column2 from (values "+strings.Join(rows, ",")+")", args...)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()

			seen := 0
			for r.Next() {
				var i, v int64
				if err := r.Scan(&i, &v); err != nil {
					t.Fatal(err)
				}
				if v != 3*i+1 {
					t.Fatalf("parameter %d bound to %d, want %d", i, v, 3*i+1)
				}
				seen++
			}
			if err := r.Err(); err != nil {
				t.Fatal(err)
			}
			if seen != n {
				t.Fatalf("got %d rows, want %d", seen, n)
			}
		})
	}
}

// BenchmarkBindManyParameters measures binding a multi-row INSERT with about
// 20k positional parameters, which was quadratic in the number of parameters.
//
// https://github.com/modernc-org/sqlite/issues/8
func BenchmarkBindManyParameters(b *testing.B) {
	for _, n := range []int{10, 1000, 20000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			db, err := sql.Open(driverName, "file::memory:")
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()

			if _, err := db.Exec("create table t(a, b, c, d, e, f, g, h, i, j)"); err != nil {
				b.Fatal(err)
			}

			q := "insert into t values " + strings.TrimSuffix(strings.Repeat("(?,?,?,?,?,?,?,?,?,?),", n/10), ",")
			stmt, err := db.Prepare(q)
			if err != nil {
				b.Fatal(err)
			}
			defer stmt.Close()

			args := make([]any, n)
			for i := range args {
				args[i] = int64(i)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := stmt.Exec(args...); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/param")
		})
	}
}
