// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build none
// +build none

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testTag    = "v1.60.0"
	testCommit = "0123456789abcdef0123456789abcdef01234567"
	testZip    = "h1:X1es1GpqBlS/5T+vbM4HLUdaa8OtQx468DF2vrx+38A="
	testGoMod  = "h1:+paeT2A3iPRHkQDwG7oA6Tk0zQd5woMEI8q7orfry8k="
)

var testProject = project{module: "modernc.org/sqlite", path: "cznic/sqlite", id: "9241019"}

func goodDownloads() (direct, proxied *modInfo) {
	direct = &modInfo{
		Path: "modernc.org/sqlite", Version: testTag, Sum: testZip, GoModSum: testGoMod,
		Origin: &origin{VCS: "git", URL: "https://gitlab.com/cznic/sqlite", Hash: testCommit, Ref: "refs/tags/" + testTag},
	}
	proxied = &modInfo{Path: "modernc.org/sqlite", Version: testTag, Sum: testZip, GoModSum: testGoMod}
	return direct, proxied
}

func TestCompare(t *testing.T) {
	if d, p := goodDownloads(); testProject.compare(testTag, testCommit, d, p) != nil {
		t.Fatal("refused a good pair")
	}
	if d, p := goodDownloads(); func() error {
		d.Origin.URL += ".git"
		return testProject.compare(testTag, testCommit, d, p)
	}() != nil {
		t.Fatal("refused the repository URL with .git, as GitLab's go-import tag gives it")
	}
	for _, tc := range []struct {
		name string
		edit func(d, p *modInfo)
	}{
		{"direct path", func(d, p *modInfo) { d.Path = "example.com/sqlite" }},
		{"proxy version", func(d, p *modInfo) { p.Version = "v1.59.0" }},
		{"no zip hash", func(d, p *modInfo) { d.Sum, p.Sum = "", "" }},
		{"malformed zip hash", func(d, p *modInfo) { d.Sum, p.Sum = "h1:short=", "h1:short=" }},
		{"malformed go.mod hash", func(d, p *modInfo) { d.GoModSum, p.GoModSum = "sha256:x", "sha256:x" }},
		{"no origin", func(d, p *modInfo) { d.Origin = nil }},
		{"origin vcs", func(d, p *modInfo) { d.Origin.VCS = "hg" }},
		{"origin url", func(d, p *modInfo) { d.Origin.URL = "https://gitlab.com/someone/sqlite" }},
		{"origin url with .git", func(d, p *modInfo) { d.Origin.URL = "https://gitlab.com/someone/sqlite.git" }},
		{"origin url with more than .git", func(d, p *modInfo) { d.Origin.URL = "https://gitlab.com/cznic/sqlite.git/x" }},
		{"origin subdir", func(d, p *modInfo) { d.Origin.Subdir = "v2" }},
		{"origin ref", func(d, p *modInfo) { d.Origin.Ref = "refs/heads/" + testTag }},
		{"origin commit", func(d, p *modInfo) { d.Origin.Hash = strings.Repeat("f", 40) }},
		{"zip differs", func(d, p *modInfo) { p.Sum = "h1:" + strings.Repeat("A", 43) + "=" }},
		{"go.mod differs", func(d, p *modInfo) { p.GoModSum = "h1:" + strings.Repeat("B", 43) + "=" }},
	} {
		d, p := goodDownloads()
		tc.edit(d, p)
		if err := testProject.compare(testTag, testCommit, d, p); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestGoEnv(t *testing.T) {
	for k, v := range map[string]string{
		"GOFLAGS": "-mod=mod", "GOPROXY": "https://evil.example", "GONOSUMDB": "*",
		"GOPRIVATE": "modernc.org", "GOWORK": "/tmp/go.work", "GOSUMDB": "off",
		"GIT_CONFIG_GLOBAL": "/tmp/gitconfig", "GOMODCACHE": "/tmp/shared",
	} {
		t.Setenv(k, v)
	}
	root := t.TempDir()
	env, err := goEnv(root, "GOPROXY=direct", "GOSUMDB=off")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Errorf("%s set twice", k)
		}
		got[k] = v
	}
	for k, want := range map[string]string{
		"GOFLAGS": "-modcacherw", "GOPROXY": "direct", "GONOSUMDB": "", "GOPRIVATE": "",
		"GOWORK": "off", "GOENV": "off", "GIT_CONFIG_GLOBAL": os.DevNull,
		"GOMODCACHE": filepath.Join(root, "modcache"),
	} {
		if got[k] != want {
			t.Errorf("%s=%q, want %q", k, got[k], want)
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "work", "go.mod")); err != nil || !strings.HasPrefix(string(b), "module ") {
		t.Errorf("no scratch module in %s: %v", filepath.Join(root, "work"), err)
	}
	for k := range got {
		switch k {
		case "PATH", "HOME", "GOENV", "GOFLAGS", "GOWORK", "GOTOOLCHAIN", "GOPATH", "GOMODCACHE", "GOCACHE",
			"GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE", "GOVCS",
			"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GOPROXY", "GOSUMDB":
		default:
			t.Errorf("unexpected variable %s", k)
		}
	}
}

func TestNotYet(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&downloadError{"reading https://proxy.golang.org/modernc.org/sqlite/@v/v1.60.0.info: 404 Not Found"}, true},
		{&downloadError{"reading https://proxy.golang.org/modernc.org/sqlite/@v/v1.60.0.zip: 410 Gone"}, true},
		{&downloadError{"verifying modernc.org/sqlite@v1.60.0: checksum mismatch"}, false},
		{fmt.Errorf("go mod download: exit status 1: 404 Not Found"), false},
	} {
		if got := notYet(tc.err); got != tc.want {
			t.Errorf("notYet(%q) = %v", tc.err, got)
		}
	}
}

func TestSiblings(t *testing.T) {
	lib, vec := strings.Repeat("d", 40), strings.Repeat("3", 40)
	write := func(sources string) string {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "vendor.json"), []byte(`{"go": "go1.27.1", "sources": [`+sources+`]}`), 0o644)
		return dir
	}
	good := `{"module": "modernc.org/libsqlite3", "into": "lib", "commit": "` + lib + `"},
		{"module": "modernc.org/libsqlite_vec", "into": "vec", "commit": "` + vec + `"}`
	var out strings.Builder
	if err := siblings(write(good), &out); err != nil {
		t.Fatal(err)
	}
	want := "https://gitlab.com/cznic/libsqlite3.git " + lib + " ../libsqlite3\n" +
		"https://gitlab.com/cznic/libsqlite_vec.git " + vec + " ../libsqlite_vec\n"
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
	for name, sources := range map[string]string{
		"one source":    `{"module": "modernc.org/libsqlite3", "into": "lib", "commit": "` + lib + `"}`,
		"swapped":       `{"module": "modernc.org/libsqlite_vec", "into": "vec", "commit": "` + vec + `"}, {"module": "modernc.org/libsqlite3", "into": "lib", "commit": "` + lib + `"}`,
		"other module":  strings.Replace(good, "modernc.org/libsqlite_vec", "example.com/libsqlite_vec", 1),
		"other dir":     strings.Replace(good, `"into": "vec"`, `"into": "lib2"`, 1),
		"short commit":  strings.Replace(good, lib, lib[:12], 1),
		"branch commit": strings.Replace(good, lib, "master", 1),
	} {
		out.Reset()
		if err := siblings(write(sources), &out); err == nil || out.Len() != 0 {
			t.Errorf("%s: err %v, printed %q", name, err, out.String())
		}
	}
	if err := siblings(t.TempDir(), &out); err == nil {
		t.Error("no vendor.json: accepted")
	}
}

// ---- observe, with a scripted download and a real git repository

func gitRepo(t *testing.T, tag string) (dir, commit string) {
	t.Helper()
	dir = t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"},
		{"tag", tag},
	} {
		if _, err := runGit(dir, args...); err != nil {
			t.Fatal(err)
		}
	}
	commit, err := revParse(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor.json"), []byte("{\n\t\"go\": \"go1.27.1\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, commit
}

func runGit(dir string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

type script struct {
	mu    sync.Mutex
	calls []string
	reply func(proxy string, n int) (*modInfo, error)
}

func (s *script) download(module, version, dir string, env []string) (*modInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var proxy string
	seen := map[string]bool{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if seen[k] {
			return nil, fmt.Errorf("%s set twice", k)
		}
		seen[k] = true
		if k == "GOPROXY" {
			proxy = v
		}
	}
	s.calls = append(s.calls, proxy+" "+dir)
	return s.reply(proxy, len(s.calls))
}

func TestObserve(t *testing.T) {
	dir, commit := gitRepo(t, testTag)
	reply := func(proxy string, n int) (*modInfo, error) {
		d, p := goodDownloads()
		d.Origin.Hash = commit
		if proxy == "direct" {
			return d, nil
		}
		return p, nil
	}
	out := filepath.Join(t.TempDir(), docName)

	s := &script{reply: reply}
	o := observer{p: testProject, retries: 3, download: s.download}
	if err := o.observe(dir, testTag, commit, out); err != nil {
		t.Fatal(err)
	}
	if len(s.calls) != 2 || !strings.HasPrefix(s.calls[0], "direct ") || !strings.HasPrefix(s.calls[1], proxyURL+" ") {
		t.Fatalf("downloads %q, want direct then proxy", s.calls)
	}
	if strings.Fields(s.calls[0])[1] == strings.Fields(s.calls[1])[1] {
		t.Fatalf("both downloads ran in %s", strings.Fields(s.calls[0])[1])
	}
	d, err := readDocument(out, testProject, testTag)
	if err != nil {
		t.Fatal(err)
	}
	vendor, _ := os.ReadFile(filepath.Join(dir, "vendor.json"))
	sum := sha256.Sum256(vendor)
	if d.Commit != commit || d.ZipH1 != testZip || d.GoModH1 != testGoMod || d.VendorSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("document %+v", d)
	}

	t.Run("HEAD elsewhere", func(t *testing.T) {
		if _, err := runGit(dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "y"); err != nil {
			t.Fatal(err)
		}
		defer runGit(dir, "reset", "-q", "--hard", commit)
		s := &script{reply: reply}
		o := observer{p: testProject, retries: 3, download: s.download}
		if err := o.observe(dir, testTag, commit, out); err == nil || len(s.calls) != 0 {
			t.Fatalf("HEAD off the tag: err %v, %d downloads", err, len(s.calls))
		}
	})
	t.Run("tag elsewhere", func(t *testing.T) {
		// HEAD stays on the commit; only the tag moves to a child of it.
		if _, err := runGit(dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit-tree", "-p", commit, "-m", "z", commit+"^{tree}"); err != nil {
			t.Fatal(err)
		}
		child, err := runGit(dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit-tree", "-p", commit, "-m", "z", commit+"^{tree}")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runGit(dir, "tag", "-f", testTag, child); err != nil {
			t.Fatal(err)
		}
		defer runGit(dir, "tag", "-f", testTag, commit)
		if head, _ := revParse(dir, "HEAD"); head != commit {
			t.Fatalf("HEAD moved to %s", head)
		}
		s := &script{reply: reply}
		o := observer{p: testProject, retries: 3, download: s.download}
		if err := o.observe(dir, testTag, commit, out); err == nil || len(s.calls) != 0 {
			t.Fatalf("tag off HEAD: err %v, %d downloads", err, len(s.calls))
		}
	})
	t.Run("downloads disagree", func(t *testing.T) {
		s := &script{reply: func(proxy string, n int) (*modInfo, error) {
			m, err := reply(proxy, n)
			if proxy != "direct" {
				m.Sum = "h1:" + strings.Repeat("Z", 43) + "="
			}
			return m, err
		}}
		o := observer{p: testProject, retries: 3, download: s.download}
		os.Remove(out)
		if err := o.observe(dir, testTag, commit, out); err == nil {
			t.Fatal("accepted a proxy hash that differs from the origin's")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("wrote %s anyway", out)
		}
	})
	t.Run("proxy late", func(t *testing.T) {
		s := &script{reply: func(proxy string, n int) (*modInfo, error) {
			if proxy != "direct" && n < 4 {
				return nil, &downloadError{"reading https://proxy.golang.org/x: 404 Not Found"}
			}
			return reply(proxy, n)
		}}
		o := observer{p: testProject, retries: 3, download: s.download}
		if err := o.observe(dir, testTag, commit, out); err != nil || len(s.calls) != 4 {
			t.Fatalf("err %v after %d downloads, want success after 4", err, len(s.calls))
		}
	})
	t.Run("proxy never", func(t *testing.T) {
		s := &script{reply: func(proxy string, n int) (*modInfo, error) {
			if proxy != "direct" {
				return nil, &downloadError{"reading https://proxy.golang.org/x: 404 Not Found"}
			}
			return reply(proxy, n)
		}}
		o := observer{p: testProject, retries: 3, download: s.download}
		if err := o.observe(dir, testTag, commit, out); err == nil || len(s.calls) != 4 {
			t.Fatalf("err %v after %d downloads, want failure after 1+3", err, len(s.calls))
		}
	})
	t.Run("proxy mismatch is not retried", func(t *testing.T) {
		s := &script{reply: func(proxy string, n int) (*modInfo, error) {
			if proxy != "direct" {
				return nil, &downloadError{"verifying modernc.org/sqlite@v1.60.0: checksum mismatch"}
			}
			return reply(proxy, n)
		}}
		o := observer{p: testProject, retries: 3, download: s.download}
		if err := o.observe(dir, testTag, commit, out); err == nil || len(s.calls) != 2 {
			t.Fatalf("err %v after %d downloads, want failure after 2", err, len(s.calls))
		}
	})
	t.Run("bad inputs", func(t *testing.T) {
		for _, tc := range [][2]string{{"v1.60", commit}, {"1.60.0", commit}, {testTag, commit[:12]}, {testTag, strings.ToUpper(commit)}} {
			s := &script{reply: reply}
			o := observer{p: testProject, retries: 3, download: s.download}
			if err := o.observe(dir, tc[0], tc[1], out); err == nil || len(s.calls) != 0 {
				t.Errorf("observe(%q, %q): err %v, %d downloads", tc[0], tc[1], err, len(s.calls))
			}
		}
	})
}

// ---- documents and certificates

func writeDocument(t *testing.T, edit func(d map[string]any)) string {
	t.Helper()
	d := map[string]any{
		"schema": schemaV1, "module": "modernc.org/sqlite", "version": testTag, "commit": testCommit,
		"zip_h1": testZip, "gomod_h1": testGoMod, "vendor_json_sha256": strings.Repeat("a", 64),
		"vendor":   map[string]any{"go": "go1.27.1"},
		"observed": map[string]any{"start": "", "end": "", "origin": "", "proxy": "", "sumdb": ""},
		"builder":  map[string]any{"pipeline": "", "job": "", "go": ""},
	}
	if edit != nil {
		edit(d)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), docName)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadDocument(t *testing.T) {
	if _, err := readDocument(writeDocument(t, nil), testProject, testTag); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(d map[string]any){
		"schema":        func(d map[string]any) { d["schema"] = "modernc.org/sqlite/attestation/v2" },
		"module":        func(d map[string]any) { d["module"] = "modernc.org/libc" },
		"version":       func(d map[string]any) { d["version"] = "v1.59.0" },
		"short commit":  func(d map[string]any) { d["commit"] = testCommit[:12] },
		"zip hash":      func(d map[string]any) { d["zip_h1"] = "sha256:abc" },
		"no vendor sum": func(d map[string]any) { delete(d, "vendor_json_sha256") },
		"no vendor":     func(d map[string]any) { delete(d, "vendor") },
		"unknown field": func(d map[string]any) { d["dirty"] = true },
	} {
		if _, err := readDocument(writeDocument(t, edit), testProject, testTag); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := writeDocument(t, nil)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, []byte(`{"schema":"x"}`)...), 0o644)
	if _, err := readDocument(p, testProject, testTag); err == nil {
		t.Error("trailing document: accepted")
	}
}

type ext struct {
	oid   asn1.ObjectIdentifier
	value any
}

func goodExtensions(commit string) []ext {
	return []ext{
		{oidIssuer, "https://gitlab.com"},
		{oidBuildSignerURI, "https://gitlab.com/cznic/sqlite//.gitlab-ci.yml@refs/tags/" + testTag},
		{oidBuildSignerDigest, commit},
		{oidRunnerEnvironment, "gitlab-hosted"},
		{oidSourceRepositoryURI, "https://gitlab.com/cznic/sqlite"},
		{oidSourceRepositoryDigest, commit},
		{oidSourceRepositoryRef, "refs/tags/" + testTag},
		{oidSourceRepositoryIdentity, "9241019"},
		{oidBuildTrigger, "push"},
	}
}

// certificate makes a self-signed certificate shaped like Fulcio's for a
// GitLab job: the subject in a URI SAN, the claims in UTF8String extensions.
func certificate(t *testing.T, san string, exts []ext) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * time.Minute),
		URIs:         []*url.URL{u},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	for _, e := range exts {
		var v []byte
		switch x := e.value.(type) {
		case string:
			v, err = asn1.MarshalWithParams(x, "utf8")
		default:
			v, err = asn1.Marshal(x)
		}
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: e.oid, Value: v})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCheckCertificate(t *testing.T) {
	san := testProject.identity(testTag)
	if err := testProject.checkCertificate(certificate(t, san, goodExtensions(testCommit)), testTag, testCommit); err != nil {
		t.Fatal(err)
	}
	wrong := map[string]string{
		oidIssuer.String():                   "https://token.actions.githubusercontent.com",
		oidBuildSignerURI.String():           "https://gitlab.com/cznic/sqlite//.gitlab-ci.yml@refs/heads/" + testTag,
		oidBuildSignerDigest.String():        strings.Repeat("e", 40),
		oidRunnerEnvironment.String():        "self-hosted",
		oidSourceRepositoryURI.String():      "https://gitlab.com/Deln0r/sqlite",
		oidSourceRepositoryDigest.String():   strings.Repeat("f", 40),
		oidSourceRepositoryRef.String():      "refs/heads/" + testTag,
		oidSourceRepositoryIdentity.String(): "12345",
		oidBuildTrigger.String():             "web",
	}
	// A repeated extension is not tried: crypto/x509 refuses to parse such a
	// certificate, so leafCertificate never returns one.
	for i, e := range goodExtensions(testCommit) {
		for _, mode := range []string{"wrong", "missing", "not a string"} {
			exts := goodExtensions(testCommit)
			switch mode {
			case "wrong":
				exts[i].value = wrong[e.oid.String()]
			case "missing":
				exts = append(exts[:i], exts[i+1:]...)
			case "not a string":
				exts[i].value = 7
			}
			if err := testProject.checkCertificate(certificate(t, san, exts), testTag, testCommit); err == nil {
				t.Errorf("%v %s: accepted", e.oid, mode)
			}
		}
	}
	for _, s := range []string{
		"https://gitlab.com/cznic/sqlite//.gitlab-ci.yml@refs/heads/master",
		"https://gitlab.com/Deln0r/sqlite//.gitlab-ci.yml@refs/tags/" + testTag,
	} {
		if err := testProject.checkCertificate(certificate(t, s, goodExtensions(testCommit)), testTag, testCommit); err == nil {
			t.Errorf("subject %s: accepted", s)
		}
	}
	// The commit the document names must be the commit in the certificate.
	if err := testProject.checkCertificate(certificate(t, san, goodExtensions(testCommit)), testTag, strings.Repeat("1", 40)); err == nil {
		t.Error("certificate for another commit: accepted")
	}
}

func TestLeafCertificate(t *testing.T) {
	cert := certificate(t, testProject.identity(testTag), goodExtensions(testCommit))
	raw := base64.StdEncoding.EncodeToString(cert.Raw)
	for name, bundle := range map[string]string{
		"v0.3": `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"` + raw + `"}}}`,
		"v0.1": `{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.1","verificationMaterial":{"x509CertificateChain":{"certificates":[{"rawBytes":"` + raw + `"}]}}}`,
	} {
		got, err := leafCertificate([]byte(bundle))
		if err != nil || !got.Equal(cert) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bundle := range map[string]string{
		"key only": `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"publicKey":{"hint":"x"}}}`,
		"legacy":   `{"base64Signature":"x","cert":"x","rekorBundle":{}}`,
		"garbage":  `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"!!"}}}`,
	} {
		if _, err := leafCertificate([]byte(bundle)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignedTimestamps(t *testing.T) {
	for bundle, want := range map[string]bool{
		`{"verificationMaterial":{"timestampVerificationData":{"rfc3161Timestamps":[{"signedTimestamp":"MII="}]}}}`: true,
		`{"verificationMaterial":{"timestampVerificationData":{"rfc3161Timestamps":[]}}}`:                           false,
		`{"verificationMaterial":{"tlogEntries":[{"integratedTime":"1790000000"}]}}`:                                false,
		`not json`: false,
	} {
		if got := signedTimestamps([]byte(bundle)); got != want {
			t.Errorf("signedTimestamps(%s) = %v", bundle, got)
		}
	}
}

func TestCheckModule(t *testing.T) {
	dir := t.TempDir()
	vendor := []byte("{\n\t\"go\": \"go1.27.1\"\n}\n")
	os.WriteFile(filepath.Join(dir, "vendor.json"), vendor, 0o644)
	sum := sha256.Sum256(vendor)
	good := func() (*document, *modInfo) {
		return &document{Module: "modernc.org/sqlite", Version: testTag, ZipH1: testZip, GoModH1: testGoMod,
				VendorSHA256: hex.EncodeToString(sum[:]), Vendor: json.RawMessage(`{"go":"go1.27.1"}`)},
			&modInfo{Path: "modernc.org/sqlite", Version: testTag, Sum: testZip, GoModSum: testGoMod, Dir: dir}
	}
	if d, m := good(); checkModule(d, m) != nil {
		t.Fatal("refused a matching module")
	}
	for name, edit := range map[string]func(*document, *modInfo){
		"version":      func(d *document, m *modInfo) { m.Version = "v1.59.0" },
		"zip":          func(d *document, m *modInfo) { m.Sum = testGoMod },
		"go.mod":       func(d *document, m *modInfo) { m.GoModSum = testZip },
		"vendor sum":   func(d *document, m *modInfo) { d.VendorSHA256 = strings.Repeat("0", 64) },
		"vendor copy":  func(d *document, m *modInfo) { d.Vendor = json.RawMessage(`{"go":"go1.26.3"}`) },
		"no vendor":    func(d *document, m *modInfo) { m.Dir = t.TempDir() },
		"vendor wrong": func(d *document, m *modInfo) { d.Vendor = json.RawMessage(`[`) },
	} {
		d, m := good()
		edit(d, m)
		if checkModule(d, m) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- ID token claims

func token(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(b) + "." + enc([]byte("sig"))
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss": "https://gitlab.com", "aud": "sigstore", "project_id": "9241019", "project_path": "cznic/sqlite",
		"ref": testTag, "ref_type": "tag", "sha": testCommit, "pipeline_source": "push",
		"runner_environment": "gitlab-hosted", "ci_config_ref_uri": "gitlab.com/cznic/sqlite//.gitlab-ci.yml@refs/tags/" + testTag,
		"ci_config_sha": testCommit, "user_login": "cznic",
	}
}

func TestCheckClaims(t *testing.T) {
	if err := testProject.checkClaims(token(goodClaims()), testTag, testCommit); err != nil {
		t.Fatal(err)
	}
	c := goodClaims()
	c["project_id"] = json.Number("9241019") // a number rather than a string
	if err := testProject.checkClaims(token(c), testTag, testCommit); err != nil {
		t.Fatalf("numeric project_id: %v", err)
	}
	for claim, bad := range map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "gitlab", "project_id": "12345",
		"project_path": "Deln0r/sqlite", "ref": "master", "ref_type": "branch", "sha": strings.Repeat("f", 40),
		"pipeline_source": "web", "runner_environment": "self-hosted",
		"ci_config_ref_uri": "gitlab.com/cznic/sqlite//.gitlab-ci.yml@refs/heads/master", "ci_config_sha": strings.Repeat("e", 40),
	} {
		for _, mode := range []string{"wrong", "missing"} {
			c := goodClaims()
			if mode == "wrong" {
				c[claim] = bad
			} else {
				delete(c, claim)
			}
			err := testProject.checkClaims(token(c), testTag, testCommit)
			if err == nil {
				t.Errorf("%s %s: accepted", claim, mode)
			} else if strings.Contains(err.Error(), token(c)) {
				t.Errorf("%s %s: error prints the token", claim, mode)
			}
		}
	}
	for _, tok := range []string{"", "a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		if testProject.checkClaims(tok, testTag, testCommit) == nil {
			t.Errorf("token %q: accepted", tok)
		}
	}
}

// ---- verify, with a stand-in for cosign

// fakeCosign writes a script that records its arguments and exits with the
// status in $FAKE_COSIGN_EXIT.
func fakeCosign(t *testing.T) (path, argsFile string) {
	dir := t.TempDir()
	path, argsFile = filepath.Join(dir, "cosign"), filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nexit ${FAKE_COSIGN_EXIT:-0}\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func verifyFixture(t *testing.T, commit string, exts []ext, tsa bool) (v verifier, doc, bundle, argsFile string, mod *modInfo) {
	t.Helper()
	modDir := t.TempDir()
	vendor := []byte("{\n\t\"go\": \"go1.27.1\"\n}\n")
	os.WriteFile(filepath.Join(modDir, "vendor.json"), vendor, 0o644)
	sum := sha256.Sum256(vendor)
	doc = writeDocument(t, func(d map[string]any) {
		d["commit"] = commit
		d["vendor_json_sha256"] = hex.EncodeToString(sum[:])
	})
	cert := certificate(t, testProject.identity(testTag), exts)
	vm := map[string]any{"certificate": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(cert.Raw)}}
	if tsa {
		vm["timestampVerificationData"] = map[string]any{"rfc3161Timestamps": []any{map[string]any{"signedTimestamp": "MII="}}}
	}
	b, _ := json.Marshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": vm})
	bundle = filepath.Join(t.TempDir(), bundleName)
	os.WriteFile(bundle, b, 0o644)
	cosign, argsFile := fakeCosign(t)
	mod = &modInfo{Path: "modernc.org/sqlite", Version: testTag, Sum: testZip, GoModSum: testGoMod, Dir: modDir}
	v = verifier{p: testProject, cosign: cosign, download: func(module, version, dir string, env []string) (*modInfo, error) {
		if module != "modernc.org/sqlite" || version != testTag {
			return nil, fmt.Errorf("download of %s@%s", module, version)
		}
		for _, kv := range env {
			if kv == "GOPROXY=direct" {
				return nil, errors.New("verification must use the proxy")
			}
		}
		return mod, nil
	}}
	return v, doc, bundle, argsFile, mod
}

func TestVerify(t *testing.T) {
	v, doc, bundle, argsFile, _ := verifyFixture(t, testCommit, goodExtensions(testCommit), false)
	if err := v.verify(testTag, doc, bundle); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(argsFile)
	want := strings.Join([]string{"verify-blob", "--bundle", bundle,
		"--certificate-identity", "https://gitlab.com/cznic/sqlite//.gitlab-ci.yml@refs/tags/" + testTag,
		"--certificate-oidc-issuer", "https://gitlab.com", doc}, "\n") + "\n"
	if string(args) != want {
		t.Fatalf("cosign called with\n%s\nwant\n%s", args, want)
	}

	t.Run("signed timestamps", func(t *testing.T) {
		v, doc, bundle, argsFile, _ := verifyFixture(t, testCommit, goodExtensions(testCommit), true)
		if err := v.verify(testTag, doc, bundle); err != nil {
			t.Fatal(err)
		}
		if args, _ := os.ReadFile(argsFile); !strings.Contains(string(args), "\n--use-signed-timestamps\n") {
			t.Fatalf("cosign called without --use-signed-timestamps:\n%s", args)
		}
	})
	t.Run("cosign refuses", func(t *testing.T) {
		v, doc, bundle, _, _ := verifyFixture(t, testCommit, goodExtensions(testCommit), false)
		t.Setenv("FAKE_COSIGN_EXIT", "1")
		if v.verify(testTag, doc, bundle) == nil {
			t.Fatal("accepted what cosign refused")
		}
	})
	t.Run("certificate for another commit", func(t *testing.T) {
		other := strings.Repeat("1", 40)
		v, doc, bundle, _, _ := verifyFixture(t, testCommit, goodExtensions(other), false)
		if v.verify(testTag, doc, bundle) == nil {
			t.Fatal("accepted a certificate for another commit")
		}
	})
	t.Run("module differs", func(t *testing.T) {
		v, doc, bundle, _, mod := verifyFixture(t, testCommit, goodExtensions(testCommit), false)
		mod.Sum = "h1:" + strings.Repeat("Q", 43) + "="
		if v.verify(testTag, doc, bundle) == nil {
			t.Fatal("accepted a document the proxy's module contradicts")
		}
	})
	t.Run("download fails", func(t *testing.T) {
		v, doc, bundle, _, _ := verifyFixture(t, testCommit, goodExtensions(testCommit), false)
		v.download = func(module, version, dir string, env []string) (*modInfo, error) { return nil, errors.New("offline") }
		if v.verify(testTag, doc, bundle) == nil {
			t.Fatal("accepted without the module")
		}
	})
	t.Run("document for another tag", func(t *testing.T) {
		v, doc, bundle, argsFile, _ := verifyFixture(t, testCommit, goodExtensions(testCommit), false)
		if v.verify("v1.60.1", doc, bundle) == nil {
			t.Fatal("accepted a document for another tag")
		}
		if _, err := os.Stat(argsFile); err == nil {
			t.Fatal("ran cosign on a document that names another tag")
		}
	})
}

// ---- publish against a fake GitLab API

type fakeGitLab struct {
	t        *testing.T
	mu       sync.Mutex
	files    map[string][][]byte // file name -> stored copies
	release  *struct{ links []link }
	requests []string
	// createConflict makes the first release creation answer 409, as when the
	// release was created by someone else in between.
	createConflict bool
	pageSize       int    // listing page size; 0 means 100
	hidden         bool   // the package is listed only with status=hidden
	packages       int    // number of "attestation" packages for the tag once files exist; 0 means 1
	noNextHeader   bool   // listings carry no X-Next-Page
	storage        string // when set, file downloads redirect here
}

func (f *fakeGitLab) list(w http.ResponseWriter, r *http.Request, items []map[string]any) {
	size := f.pageSize
	if size == 0 {
		size = 100
	}
	page := 1
	fmt.Sscan(r.URL.Query().Get("page"), &page)
	lo := min((page-1)*size, len(items))
	hi := min(lo+size, len(items))
	if !f.noNextHeader {
		next := ""
		if hi < len(items) {
			next = fmt.Sprint(page + 1)
		}
		w.Header().Set("X-Next-Page", next)
	}
	out := items[lo:hi]
	if out == nil {
		out = []map[string]any{}
	}
	json.NewEncoder(w).Encode(out)
}

func (f *fakeGitLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("JOB-TOKEN") != "tok" {
		http.Error(w, "unauthorized", 401)
		return
	}
	path := r.URL.EscapedPath()
	f.requests = append(f.requests, r.Method+" "+path)
	const base = "/api/v4/projects/cznic%2Fsqlite"
	gen := base + "/packages/generic/attestation/" + testTag + "/"
	switch {
	case r.Method == "GET" && path == base+"/packages":
		q := r.URL.Query()
		if q.Get("package_name") != "attestation" || q.Get("package_version") != testTag || q.Get("package_type") != "generic" {
			f.t.Errorf("package query %s", r.URL.RawQuery)
		}
		pkgs := []map[string]any{{"id": 99, "name": "attestation-old", "version": testTag}}
		if len(f.files) != 0 && f.hidden == (q.Get("status") == "hidden") {
			n := max(f.packages, 1)
			for i := 0; i < n; i++ {
				pkgs = append(pkgs, map[string]any{"id": 7 + i, "name": "attestation", "version": testTag})
			}
		}
		f.list(w, r, pkgs)
	case r.Method == "GET" && (path == base+"/packages/7/package_files" || path == base+"/packages/8/package_files"):
		names := []string{docName, bundleName, "notes.txt"}
		if f.packages == 2 { // the document in one package, the bundle in the other
			names = []string{docName}
			if strings.Contains(path, "/8/") {
				names = []string{bundleName}
			}
		}
		var pfs []map[string]any
		for _, name := range names {
			for range f.files[name] {
				pfs = append(pfs, map[string]any{"file_name": name})
			}
		}
		f.list(w, r, pfs)
	case r.Method == "GET" && path == base+"/packages/99/package_files":
		f.t.Error("listed files of a package with another name")
	case r.Method == "PUT" && strings.HasPrefix(path, gen):
		b, _ := io.ReadAll(r.Body)
		name := strings.TrimPrefix(path, gen)
		f.files[name] = append(f.files[name], b)
		w.WriteHeader(201)
		fmt.Fprint(w, `{"message":"201 Created"}`)
	case r.Method == "GET" && strings.HasPrefix(path, gen):
		name := strings.TrimPrefix(path, gen)
		copies := f.files[name]
		if len(copies) == 0 {
			http.NotFound(w, r)
			return
		}
		if f.storage != "" {
			http.Redirect(w, r, f.storage+"/"+name, http.StatusFound)
			return
		}
		w.Write(copies[len(copies)-1])
	case r.Method == "GET" && path == base+"/releases/"+testTag:
		if f.release == nil {
			http.Error(w, `{"message":"404 Not Found"}`, 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"assets": map[string]any{"links": f.release.links}})
	case r.Method == "POST" && path == base+"/releases":
		if f.createConflict {
			f.createConflict = false
			f.release = &struct{ links []link }{}
			http.Error(w, `{"message":"Release already exists"}`, 409)
			return
		}
		var body struct {
			TagName string `json:"tag_name"`
			Assets  struct{ Links []link }
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.TagName != testTag {
			f.t.Errorf("release for %q", body.TagName)
		}
		f.release = &struct{ links []link }{body.Assets.Links}
		w.WriteHeader(201)
		fmt.Fprint(w, `{}`)
	case r.Method == "POST" && path == base+"/releases/"+testTag+"/assets/links":
		var l link
		json.NewDecoder(r.Body).Decode(&l)
		f.release.links = append(f.release.links, l)
		w.WriteHeader(201)
		fmt.Fprint(w, `{}`)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, path)
		http.Error(w, "unexpected", 500)
	}
}

func publishFixture(t *testing.T) (*fakeGitLab, *registry, string, string) {
	f := &fakeGitLab{t: t, files: map[string][][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	r := &registry{api: srv.URL + "/api/v4", project: "cznic/sqlite", token: "tok", client: newClient(srv.Client())}
	dir := t.TempDir()
	doc, bundle := filepath.Join(dir, docName), filepath.Join(dir, bundleName)
	os.WriteFile(doc, []byte("new document"), 0o644)
	os.WriteFile(bundle, []byte("new bundle"), 0o644)
	return f, r, doc, bundle
}

func wantLinks(r *registry) []link {
	return []link{
		{docName, r.fileURL(testTag, docName), "other"},
		{bundleName, r.fileURL(testTag, bundleName), "other"},
	}
}

func verifyOK(tag, doc, bundle string) error { return nil }

func onlyGets(t *testing.T, name string, f *fakeGitLab) {
	t.Helper()
	for _, req := range f.requests {
		if !strings.HasPrefix(req, "GET ") {
			t.Errorf("%s: made %s", name, req)
		}
	}
}

func TestPublishFresh(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	var verified []string
	verify := func(tag, d, b string) error {
		verified = append(verified, d)
		return nil
	}
	if err := publish(r, testTag, doc, bundle, verify); err != nil {
		t.Fatal(err)
	}
	if len(verified) != 1 || verified[0] != doc {
		t.Fatalf("verified %q before storing, want the new document once", verified)
	}
	if string(f.files[docName][0]) != "new document" || string(f.files[bundleName][0]) != "new bundle" || len(f.files) != 2 {
		t.Fatalf("stored %v", f.files)
	}
	if fmt.Sprint(f.release.links) != fmt.Sprint(wantLinks(r)) {
		t.Fatalf("links %v", f.release.links)
	}
	if !strings.HasSuffix(wantLinks(r)[0].URL, "/api/v4/projects/cznic%2Fsqlite/packages/generic/attestation/v1.60.0/provenance.json") {
		t.Fatalf("link URL %s", wantLinks(r)[0].URL)
	}
}

func TestPublishRefusesBadDocument(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	err := publish(r, testTag, doc, bundle, func(tag, d, b string) error { return errors.New("bad signature") })
	if err == nil || len(f.files) != 0 || f.release != nil {
		t.Fatalf("err %v, stored %v, release %v", err, f.files, f.release)
	}
}

func storedPair(f *fakeGitLab) {
	f.files[docName] = [][]byte{[]byte("stored document")}
	f.files[bundleName] = [][]byte{[]byte("stored bundle")}
}

func recordStored(seen *[]string) func(tag, d, b string) error {
	return func(tag, d, b string) error {
		x, _ := os.ReadFile(d)
		y, _ := os.ReadFile(b)
		*seen = append(*seen, string(x)+"+"+string(y))
		return nil
	}
}

func TestPublishRetry(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	storedPair(f)
	f.release = &struct{ links []link }{} // created by hand, no links yet
	var seen []string
	if err := publish(r, testTag, doc, bundle, recordStored(&seen)); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "stored document+stored bundle" {
		t.Fatalf("verified %q, want the stored pair", seen)
	}
	if len(f.files[docName]) != 1 || len(f.files[bundleName]) != 1 {
		t.Fatalf("stored again: %v", f.files)
	}
	if fmt.Sprint(f.release.links) != fmt.Sprint(wantLinks(r)) {
		t.Fatalf("links %v", f.release.links)
	}
	// A third run changes nothing.
	f.requests = nil
	if err := publish(r, testTag, doc, bundle, recordStored(&seen)); err != nil {
		t.Fatal(err)
	}
	onlyGets(t, "third run", f)
}

// The stored pair is spread over two pages; reading only the first would
// see a document without its bundle.
func TestPublishReadsEveryPage(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	storedPair(f)
	f.pageSize = 1
	var seen []string
	if err := publish(r, testTag, doc, bundle, recordStored(&seen)); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || len(f.files[docName]) != 1 {
		t.Fatalf("verified %q, stored %v", seen, f.files)
	}
}

func TestPublishHiddenPackage(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	storedPair(f)
	f.hidden = true
	var seen []string
	if err := publish(r, testTag, doc, bundle, recordStored(&seen)); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || len(f.files[docName]) != 1 {
		t.Fatalf("a hidden stored pair was not found: verified %q, stored %v", seen, f.files)
	}
}

func TestPublishRefusesUnreadableListing(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	storedPair(f)
	f.noNextHeader = true
	if err := publish(r, testTag, doc, bundle, verifyOK); err == nil {
		t.Fatal("decided on a listing without pagination headers")
	}
	onlyGets(t, "no X-Next-Page", f)
}

func TestPublishRefusesOddPackages(t *testing.T) {
	for name, setup := range map[string]func(f *fakeGitLab){
		"two packages": func(f *fakeGitLab) { storedPair(f); f.packages = 2 },
		"foreign file": func(f *fakeGitLab) { f.files["notes.txt"] = [][]byte{[]byte("n")} },
	} {
		f, r, doc, bundle := publishFixture(t)
		setup(f)
		if err := publish(r, testTag, doc, bundle, verifyOK); err == nil {
			t.Errorf("%s: accepted", name)
		}
		onlyGets(t, name, f)
	}
}

func TestPublishStoredPairFailsVerification(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	storedPair(f)
	err := publish(r, testTag, doc, bundle, func(tag, d, b string) error {
		if x, _ := os.ReadFile(d); string(x) == "stored document" {
			return errors.New("bad signature")
		}
		return nil
	})
	if err == nil || f.release != nil {
		t.Fatalf("err %v, release %v", err, f.release)
	}
}

func TestPublishPartial(t *testing.T) {
	for name, files := range map[string]map[string][][]byte{
		"document only": {docName: {[]byte("d")}},
		"bundle only":   {bundleName: {[]byte("b")}},
		"two documents": {docName: {[]byte("d"), []byte("d2")}, bundleName: {[]byte("b")}},
	} {
		f, r, doc, bundle := publishFixture(t)
		f.files = files
		if err := publish(r, testTag, doc, bundle, verifyOK); err == nil {
			t.Errorf("%s: accepted", name)
		}
		onlyGets(t, name, f)
	}
}

func TestPublishReleaseRace(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	f.createConflict = true
	if err := publish(r, testTag, doc, bundle, verifyOK); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.release.links) != fmt.Sprint(wantLinks(r)) {
		t.Fatalf("links %v", f.release.links)
	}
}

func TestPublishForeignLink(t *testing.T) {
	f, r, doc, bundle := publishFixture(t)
	f.release = &struct{ links []link }{[]link{{docName, "https://example.com/other.json", "other"}}}
	if err := publish(r, testTag, doc, bundle, verifyOK); err == nil {
		t.Fatal("accepted a release that links provenance.json elsewhere")
	}
	if len(f.release.links) != 1 {
		t.Fatalf("links changed: %v", f.release.links)
	}
}

// GitLab answers a package download with a redirect to object storage; the
// job token must not follow it there.
func TestRedirectKeepsTokenHome(t *testing.T) {
	var leaked []string
	var mu sync.Mutex
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if tok := r.Header.Get("JOB-TOKEN"); tok != "" {
			leaked = append(leaked, r.URL.Path)
		}
		fmt.Fprintf(w, "stored %s", strings.TrimPrefix(r.URL.Path, "/"))
	}))
	defer storage.Close()
	f, r, doc, bundle := publishFixture(t)
	storedPair(f)
	f.storage = storage.URL
	var seen []string
	if err := publish(r, testTag, doc, bundle, recordStored(&seen)); err != nil {
		t.Fatal(err)
	}
	if len(leaked) != 0 {
		t.Fatalf("JOB-TOKEN sent to the storage origin for %v", leaked)
	}
	if len(seen) != 1 || seen[0] != "stored provenance.json+stored provenance.json.sigstore.json" {
		t.Fatalf("read %q through the redirect", seen)
	}
}

func TestRedirectRefusesDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()
	c := newClient(tlsSrv.Client())
	if resp, err := c.Get(tlsSrv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("followed a redirect from https to http")
	}
}
