// Copyright 2026 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build none
// +build none

// Command attestgen writes, checks and publishes the signed provenance
// document of a release. It runs in the attest job of .gitlab-ci.yml, in the
// pipeline GitLab starts when a vX.Y.Z tag is pushed. VERIFYING.md says how to
// check a release, with this program or by hand.
//
// Usage:
//
//	cd attestgen && go build -tags none -o ../attest .
//	./attest -observe [-C dir] [-o provenance.json]
//	./attest -verify  provenance.json provenance.json.sigstore.json
//	./attest -publish provenance.json provenance.json.sigstore.json
//
// -tag and -commit default to $CI_COMMIT_TAG and $CI_COMMIT_SHA.
//
// -observe checks that HEAD and the tag are the commit, then downloads the
// module twice, each time into its own empty cache and with none of the
// caller's Go or git settings: once straight from gitlab.com, once from
// proxy.golang.org checked against sum.golang.org. It writes the document
// only if the direct download came from the commit and both downloads have
// the same hashes.
//
// cosign signs the document between -observe and -verify.
//
// -verify runs cosign verify-blob for the identity of this project's tag
// pipeline, then checks what cosign has no flags for on GitLab: that the
// certificate was issued to a pipeline started by the push of that tag, on a
// GitLab-hosted runner, in this project, for the commit the document names.
// Last it downloads the module through the proxy and compares it with the
// document.
//
// -publish stores the document and its bundle in the project's generic
// package registry and links both from the GitLab release of the tag, which
// it creates if there is none. It never overwrites: when both files are
// already stored, as after a retried job, it verifies those and links them.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	schemaV1    = "modernc.org/sqlite/attestation/v1"
	issuer      = "https://gitlab.com"
	packageName = "attestation"
	docName     = "provenance.json"
	bundleName  = "provenance.json.sigstore.json"
	proxyURL    = "https://proxy.golang.org"
	sumDB       = "sum.golang.org"
)

// project is what the document and the certificate are checked against. The
// defaults are this repository; the flags exist to rehearse the job in
// another project.
type project struct {
	module string // Go module path
	path   string // GitLab project path
	id     string // GitLab project ID, which survives a rename and is never reused
}

func (p project) origin() string { return issuer + "/" + p.path }

// identity is the certificate subject GitLab's tokens carry for a pipeline on
// tag: the project, the CI configuration file, and the ref it was read from.
func (p project) identity(tag string) string {
	return issuer + "/" + p.path + "//.gitlab-ci.yml@refs/tags/" + tag
}

var (
	tagRE    = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	h1RE     = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)
	sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

	now = func() time.Time { return time.Now().UTC() }
)

type document struct {
	Schema       string          `json:"schema"`
	Module       string          `json:"module"`
	Version      string          `json:"version"`
	Commit       string          `json:"commit"`
	ZipH1        string          `json:"zip_h1"`
	GoModH1      string          `json:"gomod_h1"`
	VendorSHA256 string          `json:"vendor_json_sha256"`
	Vendor       json.RawMessage `json:"vendor"`
	Observed     observed        `json:"observed"`
	Builder      builder         `json:"builder"`
}

// observed says where the hashes came from and when, by the signer's clock.
// The time of the signature itself is in the bundle.
type observed struct {
	Start  string `json:"start"`
	End    string `json:"end"`
	Origin string `json:"origin"`
	Proxy  string `json:"proxy"`
	SumDB  string `json:"sumdb"`
}

type builder struct {
	Pipeline string `json:"pipeline"`
	Job      string `json:"job"`
	Go       string `json:"go"`
}

type origin struct {
	VCS    string
	URL    string
	Hash   string
	Ref    string
	Subdir string
}

// modInfo is the part of `go mod download -json` output used here.
type modInfo struct {
	Path     string
	Version  string
	Error    string
	Dir      string
	Sum      string
	GoModSum string
	Origin   *origin
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, " ") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	log.SetFlags(0)
	log.SetPrefix("attestgen: ")
	var (
		oObserve = flag.Bool("observe", false, "check the tag and the module, write the document")
		oVerify  = flag.Bool("verify", false, "verify a document and its bundle")
		oPublish = flag.Bool("publish", false, "store a document and its bundle, link them from the release")
		oTag     = flag.String("tag", os.Getenv("CI_COMMIT_TAG"), "release tag")
		oCommit  = flag.String("commit", os.Getenv("CI_COMMIT_SHA"), "commit the tag names")
		oDir     = flag.String("C", ".", "repository checkout (-observe)")
		oOut     = flag.String("o", docName, "document to write (-observe)")
		oRetries = flag.Int("retries", 10, "attempts at the proxy while it does not know the version yet")
		oWait    = flag.Duration("wait", time.Minute, "pause between those attempts")
		oCosign  = flag.String("cosign", "cosign", "cosign binary (-verify, -publish)")
		oModule  = flag.String("module", "modernc.org/sqlite", "module path")
		oProject = flag.String("project", "cznic/sqlite", "GitLab project path")
		oID      = flag.String("project-id", "9241019", "GitLab project ID")
		oToken   = flag.String("check-token", "", "name of the variable holding the job's ID token, whose claims -observe checks before anything is signed")
	)
	var insecure multiFlag
	flag.Var(&insecure, "insecure-cosign-arg", "extra cosign verify-blob argument, for tests with a private trust root only; repeatable")
	flag.Parse()

	p := project{module: *oModule, path: *oProject, id: *oID}
	v := verifier{p: p, cosign: *oCosign, cosignArgs: insecure}
	var err error
	switch {
	case *oObserve && !*oVerify && !*oPublish && flag.NArg() == 0:
		if *oToken != "" {
			if err = p.checkClaims(os.Getenv(*oToken), *oTag, *oCommit); err != nil {
				log.Fatal(err)
			}
		}
		o := observer{p: p, retries: *oRetries, wait: *oWait, download: download}
		err = o.observe(*oDir, *oTag, *oCommit, *oOut)
	case *oVerify && !*oObserve && !*oPublish && flag.NArg() == 2:
		err = v.verify(*oTag, flag.Arg(0), flag.Arg(1))
	case *oPublish && !*oObserve && !*oVerify && flag.NArg() == 2:
		r := &registry{
			api:     os.Getenv("CI_API_V4_URL"),
			project: p.path,
			token:   os.Getenv("CI_JOB_TOKEN"),
			client:  newClient(&http.Client{Timeout: time.Minute}),
		}
		if r.api == "" || r.token == "" {
			log.Fatal("-publish needs CI_API_V4_URL and CI_JOB_TOKEN")
		}
		err = publish(r, *oTag, flag.Arg(0), flag.Arg(1), v.verify)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ---- observe

type observer struct {
	p        project
	retries  int
	wait     time.Duration
	download func(module, version, dir string, env []string) (*modInfo, error)
}

func (o observer) observe(dir, tag, commit, out string) error {
	if !tagRE.MatchString(tag) {
		return fmt.Errorf("tag %q is not vMAJOR.MINOR.PATCH", tag)
	}
	if !commitRE.MatchString(commit) {
		return fmt.Errorf("commit %q is not a full SHA-1", commit)
	}
	start := now()
	for _, ref := range []string{"HEAD", "refs/tags/" + tag} {
		got, err := revParse(dir, ref+"^{commit}")
		if err != nil {
			return err
		}
		if got != commit {
			return fmt.Errorf("%s is %s, want %s", ref, got, commit)
		}
	}
	vendor, err := os.ReadFile(filepath.Join(dir, "vendor.json"))
	if err != nil {
		return err
	}
	if !json.Valid(vendor) {
		return errors.New("vendor.json is not valid JSON")
	}

	direct, err := o.fetch(tag, "GOPROXY=direct", "GOSUMDB=off")
	if err != nil {
		return fmt.Errorf("from %s: %v", o.p.origin(), err)
	}
	var proxied *modInfo
	for attempt := 1; ; attempt++ {
		proxied, err = o.fetch(tag, "GOPROXY="+proxyURL, "GOSUMDB="+sumDB)
		if err == nil || !notYet(err) || attempt >= o.retries {
			break
		}
		log.Printf("%s does not have %s@%s yet (attempt %d of %d): %v", proxyURL, o.p.module, tag, attempt, o.retries, err)
		time.Sleep(o.wait)
	}
	if err != nil {
		return fmt.Errorf("from %s: %v", proxyURL, err)
	}
	if err := o.p.compare(tag, commit, direct, proxied); err != nil {
		return err
	}
	end := now()

	goVersion, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		return fmt.Errorf("go env GOVERSION: %v", err)
	}
	sum := sha256.Sum256(vendor)
	d := document{
		Schema:       schemaV1,
		Module:       o.p.module,
		Version:      tag,
		Commit:       commit,
		ZipH1:        direct.Sum,
		GoModH1:      direct.GoModSum,
		VendorSHA256: hex.EncodeToString(sum[:]),
		Vendor:       vendor,
		Observed: observed{
			Start:  start.Format(time.RFC3339),
			End:    end.Format(time.RFC3339),
			Origin: o.p.origin(),
			Proxy:  proxyURL,
			SumDB:  sumDB,
		},
		Builder: builder{
			Pipeline: os.Getenv("CI_PIPELINE_URL"),
			Job:      os.Getenv("CI_JOB_URL"),
			Go:       strings.TrimSpace(string(goVersion)),
		},
	}
	b, err := json.MarshalIndent(d, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(b, '\n'), 0o644)
}

// fetch downloads the module into a cache of its own, removed afterwards, so
// that no download can be answered from another one's files.
func (o observer) fetch(version string, extra ...string) (*modInfo, error) {
	root, err := os.MkdirTemp("", "attestgen-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	env, err := goEnv(root, extra...)
	if err != nil {
		return nil, err
	}
	return o.download(o.p.module, version, filepath.Join(root, "work"), env)
}

// goEnv is an environment for the go command that carries nothing from the
// caller's: no GOFLAGS, workspace, go env file, private-module or proxy
// settings, and no git configuration that could rewrite a URL. It also makes
// root/work a module of its own, so that a go.sum above it, as when TMPDIR is
// inside a module, cannot stand in for sum.golang.org.
func goEnv(root string, extra ...string) ([]string, error) {
	for _, d := range []string{"home", "work"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "work", "go.mod"), []byte("module attestgen.invalid/scratch\n\ngo 1.25.0\n"), 0o644); err != nil {
		return nil, err
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(root, "home"),
		"GOENV=off",
		"GOFLAGS=-modcacherw",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"GOPATH=" + filepath.Join(root, "gopath"),
		"GOMODCACHE=" + filepath.Join(root, "modcache"),
		"GOCACHE=" + filepath.Join(root, "gocache"),
		"GOPRIVATE=",
		"GONOPROXY=",
		"GONOSUMDB=",
		"GOINSECURE=",
		"GOVCS=",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
	}
	return append(env, extra...), nil
}

// download runs `go mod download -json` in dir, the scratch module goEnv made.
func download(module, version, dir string, env []string) (*modInfo, error) {
	cmd := exec.Command("go", "mod", "download", "-json", module+"@"+version)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	var m modInfo
	if err := json.Unmarshal(stdout.Bytes(), &m); err != nil {
		return nil, fmt.Errorf("go mod download: %v (%v) %s", err, runErr, bytes.TrimSpace(stderr.Bytes()))
	}
	if m.Error != "" {
		return nil, &downloadError{m.Error}
	}
	if runErr != nil {
		return nil, fmt.Errorf("go mod download: %v %s", runErr, bytes.TrimSpace(stderr.Bytes()))
	}
	return &m, nil
}

type downloadError struct{ msg string }

func (e *downloadError) Error() string { return e.msg }

// notYet reports whether the proxy answered that it has no such version,
// which for a tag pushed a minute ago means only that it has not fetched it.
func notYet(err error) bool {
	var d *downloadError
	return errors.As(err, &d) && (strings.Contains(d.msg, "404 Not Found") || strings.Contains(d.msg, "410 Gone"))
}

func (p project) compare(tag, commit string, direct, proxied *modInfo) error {
	for _, m := range []*modInfo{direct, proxied} {
		if m.Path != p.module || m.Version != tag {
			return fmt.Errorf("a download returned %s@%s, want %s@%s", m.Path, m.Version, p.module, tag)
		}
		if !h1RE.MatchString(m.Sum) || !h1RE.MatchString(m.GoModSum) {
			return fmt.Errorf("a download of %s@%s reported no hashes", p.module, tag)
		}
	}
	o := direct.Origin
	if o == nil {
		return errors.New("the direct download reported no origin")
	}
	if o.VCS != "git" || o.URL != p.origin() || o.Subdir != "" || o.Ref != "refs/tags/"+tag || o.Hash != commit {
		return fmt.Errorf("the direct download came from %s %s %s at %s, subdirectory %q; want git %s refs/tags/%s at %s",
			o.VCS, o.URL, o.Ref, o.Hash, o.Subdir, p.origin(), tag, commit)
	}
	if direct.Sum != proxied.Sum {
		return fmt.Errorf("module hash: %s from %s, %s from %s", direct.Sum, p.origin(), proxied.Sum, proxyURL)
	}
	if direct.GoModSum != proxied.GoModSum {
		return fmt.Errorf("go.mod hash: %s from %s, %s from %s", direct.GoModSum, p.origin(), proxied.GoModSum, proxyURL)
	}
	return nil
}

// checkClaims refuses to go on when the job's ID token would give a
// certificate that -verify rejects, as on a self-hosted runner or in a
// pipeline started by hand. Nothing is signed in such a job. The token itself
// is never printed.
func (p project) checkClaims(token, tag, commit string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("ID token: not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("ID token: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return fmt.Errorf("ID token: %v", err)
	}
	for _, w := range []struct{ claim, value string }{
		{"iss", issuer},
		{"aud", "sigstore"},
		{"project_id", p.id},
		{"project_path", p.path},
		{"ref", tag},
		{"ref_type", "tag"},
		{"sha", commit},
		{"pipeline_source", "push"},
		{"runner_environment", "gitlab-hosted"},
		{"ci_config_ref_uri", strings.TrimPrefix(p.identity(tag), "https://")},
		{"ci_config_sha", commit},
	} {
		v, ok := claims[w.claim]
		if !ok {
			return fmt.Errorf("ID token: no %s claim", w.claim)
		}
		if got := fmt.Sprint(v); got != w.value {
			return fmt.Errorf("ID token: %s is %q, want %q; not signing", w.claim, got, w.value)
		}
	}
	return nil
}

func revParse(dir, rev string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", rev).Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse %s: %v", rev, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ---- verify

type verifier struct {
	p          project
	cosign     string
	cosignArgs []string
	// download is the proxy download of the module; nil means the real one.
	download func(module, version, dir string, env []string) (*modInfo, error)
}

func (v verifier) verify(tag, docPath, bundlePath string) error {
	d, err := readDocument(docPath, v.p, tag)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(bundlePath)
	if err != nil {
		return err
	}
	args := []string{"verify-blob",
		"--bundle", bundlePath,
		"--certificate-identity", v.p.identity(tag),
		"--certificate-oidc-issuer", issuer,
	}
	if signedTimestamps(b) {
		args = append(args, "--use-signed-timestamps")
	}
	args = append(args, v.cosignArgs...)
	cmd := exec.Command(v.cosign, append(args, docPath)...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify-blob: %v", err)
	}

	cert, err := leafCertificate(b)
	if err != nil {
		return err
	}
	if err := v.p.checkCertificate(cert, tag, d.Commit); err != nil {
		return err
	}

	dl := v.download
	if dl == nil {
		dl = download
	}
	root, err := os.MkdirTemp("", "attestgen-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	env, err := goEnv(root, "GOPROXY="+proxyURL, "GOSUMDB="+sumDB)
	if err != nil {
		return err
	}
	m, err := dl(v.p.module, tag, filepath.Join(root, "work"), env)
	if err != nil {
		return fmt.Errorf("from %s: %v", proxyURL, err)
	}
	return checkModule(d, m)
}

// readDocument decodes a document strictly and checks the fields a verifier
// relies on.
func readDocument(path string, p project, tag string) (*document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: data after the document", path)
	}
	switch {
	case d.Schema != schemaV1:
		return nil, fmt.Errorf("%s: schema %q, want %q", path, d.Schema, schemaV1)
	case d.Module != p.module:
		return nil, fmt.Errorf("%s: module %q, want %q", path, d.Module, p.module)
	case d.Version != tag:
		return nil, fmt.Errorf("%s: version %q, want %q", path, d.Version, tag)
	case !commitRE.MatchString(d.Commit):
		return nil, fmt.Errorf("%s: commit %q is not a full SHA-1", path, d.Commit)
	case !h1RE.MatchString(d.ZipH1) || !h1RE.MatchString(d.GoModH1):
		return nil, fmt.Errorf("%s: malformed module hashes", path)
	case !sha256RE.MatchString(d.VendorSHA256) || len(d.Vendor) == 0:
		return nil, fmt.Errorf("%s: no vendor.json record", path)
	}
	return &d, nil
}

// signedTimestamps reports whether a bundle carries RFC 3161 timestamps. The
// public Sigstore instance adds one to every signature; cosign verify-blob
// checks it only when asked, and a Rekor v2 entry has no other time for the
// certificate to be checked at.
func signedTimestamps(bundle []byte) bool {
	var b struct {
		VerificationMaterial struct {
			TimestampVerificationData struct {
				RFC3161Timestamps []json.RawMessage `json:"rfc3161Timestamps"`
			}
		}
	}
	return json.Unmarshal(bundle, &b) == nil && len(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps) != 0
}

// leafCertificate returns the signing certificate of a Sigstore bundle.
func leafCertificate(bundle []byte) (*x509.Certificate, error) {
	var b struct {
		MediaType            string
		VerificationMaterial struct {
			Certificate *struct {
				RawBytes string
			}
			X509CertificateChain *struct {
				Certificates []struct {
					RawBytes string
				}
			}
		}
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, fmt.Errorf("bundle: %v", err)
	}
	if !strings.HasPrefix(b.MediaType, "application/vnd.dev.sigstore.bundle") {
		return nil, fmt.Errorf("bundle: media type %q is not a Sigstore bundle", b.MediaType)
	}
	var raw string
	switch vm := b.VerificationMaterial; {
	case vm.Certificate != nil:
		raw = vm.Certificate.RawBytes
	case vm.X509CertificateChain != nil && len(vm.X509CertificateChain.Certificates) != 0:
		raw = vm.X509CertificateChain.Certificates[0].RawBytes
	default:
		return nil, errors.New("bundle: no certificate; a key-signed bundle proves no pipeline identity")
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("bundle: certificate: %v", err)
	}
	return x509.ParseCertificate(der)
}

// Fulcio certificate extensions, https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md.
// For GitLab their values come from the job's ID token, as set in Fulcio's
// config/identity/config.yaml.
var (
	oidIssuer                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidBuildSignerURI           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	oidBuildSignerDigest        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}
	oidRunnerEnvironment        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}
	oidSourceRepositoryURI      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidSourceRepositoryDigest   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}
	oidSourceRepositoryRef      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}
	oidSourceRepositoryIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15}
	oidBuildTrigger             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 20}
)

// checkCertificate checks the claims cosign verify-blob has no GitLab flags
// for. cosign has already checked the chain, the subject and the issuer.
func (p project) checkCertificate(cert *x509.Certificate, tag, commit string) error {
	want := []struct {
		oid   asn1.ObjectIdentifier
		name  string
		value string
	}{
		{oidIssuer, "issuer", issuer},
		{oidBuildSignerURI, "CI configuration", p.identity(tag)},
		{oidBuildSignerDigest, "CI configuration commit", commit},
		{oidSourceRepositoryURI, "repository", p.origin()},
		{oidSourceRepositoryIdentity, "project ID", p.id},
		{oidSourceRepositoryRef, "ref", "refs/tags/" + tag},
		{oidSourceRepositoryDigest, "commit", commit},
		{oidBuildTrigger, "pipeline source", "push"},
		{oidRunnerEnvironment, "runner", "gitlab-hosted"},
	}
	for _, w := range want {
		got, err := extension(cert, w.oid)
		if err != nil {
			return fmt.Errorf("certificate %s: %v", w.name, err)
		}
		if got != w.value {
			return fmt.Errorf("certificate %s is %q, want %q", w.name, got, w.value)
		}
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != p.identity(tag) {
		return fmt.Errorf("certificate subject %v, want %s", cert.URIs, p.identity(tag))
	}
	return nil
}

// extension returns the value of a Fulcio extension that occurs exactly once
// and holds a DER string.
func extension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	var found []string
	for _, e := range cert.Extensions {
		if !e.Id.Equal(oid) {
			continue
		}
		var s string
		rest, err := asn1.Unmarshal(e.Value, &s)
		if err != nil || len(rest) != 0 {
			return "", fmt.Errorf("extension %v does not hold one string", oid)
		}
		found = append(found, s)
	}
	if len(found) != 1 {
		return "", fmt.Errorf("extension %v occurs %d times, want once", oid, len(found))
	}
	return found[0], nil
}

// checkModule compares the document with the module as the proxy serves it.
func checkModule(d *document, m *modInfo) error {
	if m.Path != d.Module || m.Version != d.Version {
		return fmt.Errorf("the proxy returned %s@%s, want %s@%s", m.Path, m.Version, d.Module, d.Version)
	}
	if m.Sum != d.ZipH1 {
		return fmt.Errorf("module hash: document %s, proxy %s", d.ZipH1, m.Sum)
	}
	if m.GoModSum != d.GoModH1 {
		return fmt.Errorf("go.mod hash: document %s, proxy %s", d.GoModH1, m.GoModSum)
	}
	vendor, err := os.ReadFile(filepath.Join(m.Dir, "vendor.json"))
	if err != nil {
		return fmt.Errorf("the module has no vendor.json: %v", err)
	}
	if sum := sha256.Sum256(vendor); hex.EncodeToString(sum[:]) != d.VendorSHA256 {
		return fmt.Errorf("vendor.json: document sha256 %s, module %x", d.VendorSHA256, sum)
	}
	var a, b bytes.Buffer
	if json.Compact(&a, vendor) != nil || json.Compact(&b, d.Vendor) != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
		return errors.New("vendor.json: the copy in the document differs from the module's")
	}
	return nil
}

// ---- publish

type registry struct {
	api     string // CI_API_V4_URL
	project string // project path
	token   string // CI_JOB_TOKEN
	client  *http.Client
}

// newClient returns a client that keeps the job token on GitLab's own origin:
// net/http forwards a custom header such as JOB-TOKEN to wherever a redirect
// points, and GitLab answers a package download with a redirect to object
// storage. A redirect from https to http is refused.
func newClient(c *http.Client) *http.Client {
	cc := *c
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		first := via[0].URL
		if first.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect from %s to %s", first.Redacted(), req.URL.Redacted())
		}
		if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
			req.Header.Del("JOB-TOKEN")
		}
		return nil
	}
	return &cc
}

func (r *registry) projectURL() string {
	return strings.TrimSuffix(r.api, "/") + "/projects/" + url.PathEscape(r.project)
}

func (r *registry) fileURL(tag, name string) string {
	return r.projectURL() + "/packages/generic/" + packageName + "/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
}

func (r *registry) do(method, u string, body []byte, contentType string) (int, []byte, error) {
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("JOB-TOKEN", r.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, b, err
}

// pages GETs every page of a listing and hands each body to add. It follows
// GitLab's X-Next-Page and fails rather than decide on part of a listing:
// when the header is missing, out of sequence, or the listing runs past
// maxPages.
func (r *registry) pages(u string, add func([]byte) error) error {
	const maxPages = 50
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	for page := 1; page <= maxPages; page++ {
		req, err := http.NewRequest("GET", u+sep+"per_page=100&page="+strconv.Itoa(page), nil)
		if err != nil {
			return err
		}
		req.Header.Set("JOB-TOKEN", r.token)
		resp, err := r.client.Do(req)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: %d %s", u, resp.StatusCode, bytes.TrimSpace(b))
		}
		if err := add(b); err != nil {
			return fmt.Errorf("GET %s: %v", u, err)
		}
		next, ok := resp.Header["X-Next-Page"]
		switch {
		case !ok || len(next) != 1:
			return fmt.Errorf("GET %s: no X-Next-Page header", u)
		case next[0] == "":
			return nil
		case next[0] != strconv.Itoa(page+1):
			return fmt.Errorf("GET %s: page %d is followed by page %q", u, page, next[0])
		}
	}
	return fmt.Errorf("GET %s: more than %d pages; not deciding on part of a listing", u, maxPages)
}

func (r *registry) call(method, u string, in, out any, ok ...int) (int, error) {
	var body []byte
	var ct string
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return 0, err
		}
		ct = "application/json"
	}
	status, b, err := r.do(method, u, body, ct)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %v", method, u, err)
	}
	for _, s := range ok {
		if status == s {
			if out != nil && len(b) != 0 {
				if err := json.Unmarshal(b, out); err != nil {
					return status, fmt.Errorf("%s %s: %v", method, u, err)
				}
			}
			return status, nil
		}
	}
	return status, fmt.Errorf("%s %s: %d %s", method, u, status, bytes.TrimSpace(b))
}

// storedFiles returns how many times each file name is stored under the
// package of tag, counting every page of both listings and packages GitLab
// lists only when asked for hidden ones.
func (r *registry) storedFiles(tag string) (map[string]int, error) {
	ids := map[int]bool{}
	for _, status := range []string{"", "hidden"} {
		q := url.Values{
			"package_type":    {"generic"},
			"package_name":    {packageName},
			"package_version": {tag},
		}
		if status != "" {
			q.Set("status", status)
		}
		err := r.pages(r.projectURL()+"/packages?"+q.Encode(), func(b []byte) error {
			var pkgs []struct {
				ID      int
				Name    string
				Version string
			}
			if err := json.Unmarshal(b, &pkgs); err != nil {
				return err
			}
			for _, p := range pkgs {
				if p.Name == packageName && p.Version == tag { // the name filter matches on a substring
					ids[p.ID] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	files := map[string]int{}
	for id := range ids {
		err := r.pages(fmt.Sprintf("%s/packages/%d/package_files", r.projectURL(), id), func(b []byte) error {
			var pfs []struct {
				FileName string `json:"file_name"`
			}
			if err := json.Unmarshal(b, &pfs); err != nil {
				return err
			}
			for _, f := range pfs {
				files[f.FileName]++
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(ids) > 1 {
		return nil, fmt.Errorf("%d %s packages for %s; this program never leaves more than one. Nothing was changed; a maintainer should inspect them", len(ids), packageName, tag)
	}
	for name := range files {
		if name != docName && name != bundleName {
			return nil, fmt.Errorf("the %s package %s holds %s, which this program never stores. Nothing was changed; a maintainer should inspect it", packageName, tag, name)
		}
	}
	return files, nil
}

type link struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	LinkType string `json:"link_type"`
}

func publish(r *registry, tag, docPath, bundlePath string, verify func(tag, docPath, bundlePath string) error) error {
	if !tagRE.MatchString(tag) {
		return fmt.Errorf("tag %q is not vMAJOR.MINOR.PATCH", tag)
	}
	files, err := r.storedFiles(tag)
	if err != nil {
		return err
	}
	switch doc, bun := files[docName], files[bundleName]; {
	case doc == 0 && bun == 0:
		if err := verify(tag, docPath, bundlePath); err != nil {
			return err
		}
		for _, f := range []struct{ name, path string }{{docName, docPath}, {bundleName, bundlePath}} {
			b, err := os.ReadFile(f.path)
			if err != nil {
				return err
			}
			status, body, err := r.do("PUT", r.fileURL(tag, f.name), b, "application/octet-stream")
			if err != nil {
				return err
			}
			if status != http.StatusCreated {
				return fmt.Errorf("storing %s: %d %s", f.name, status, bytes.TrimSpace(body))
			}
		}
	case doc == 1 && bun == 1:
		log.Printf("%s and %s are already stored for %s; verifying those instead of storing new ones", docName, bundleName, tag)
		if err := r.verifyStored(tag, verify); err != nil {
			return err
		}
	default:
		return fmt.Errorf("the %s package %s holds %d %s and %d %s; expected none or one of each. Nothing was changed; a maintainer should inspect and delete that package version, then retry the job",
			packageName, tag, doc, docName, bun, bundleName)
	}
	return r.release(tag, []link{
		{Name: docName, URL: r.fileURL(tag, docName), LinkType: "other"},
		{Name: bundleName, URL: r.fileURL(tag, bundleName), LinkType: "other"},
	})
}

func (r *registry) verifyStored(tag string, verify func(tag, docPath, bundlePath string) error) error {
	dir, err := os.MkdirTemp("", "attestgen-stored-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	var paths []string
	for _, name := range []string{docName, bundleName} {
		status, b, err := r.do("GET", r.fileURL(tag, name), nil, "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("reading the stored %s: %d", name, status)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		paths = append(paths, p)
	}
	if err := verify(tag, paths[0], paths[1]); err != nil {
		return fmt.Errorf("the stored pair does not verify: %v", err)
	}
	return nil
}

// release links the files from the release of tag, creating the release if
// there is none. An existing release keeps its name and notes; only missing
// links are added.
func (r *registry) release(tag string, links []link) error {
	u := r.projectURL() + "/releases/" + url.PathEscape(tag)
	var rel struct {
		Assets struct {
			Links []link
		}
	}
	status, err := r.call("GET", u, nil, &rel, 200, 404)
	if err != nil {
		return err
	}
	if status == 404 {
		create := map[string]any{
			"tag_name":    tag,
			"name":        tag,
			"description": "Signed provenance for this release: the two files below. VERIFYING.md in the repository says how to check them.",
			"assets":      map[string]any{"links": links},
		}
		status, err = r.call("POST", r.projectURL()+"/releases", create, nil, 201, 409)
		if err != nil {
			return err
		}
		if status == 201 {
			return nil
		}
		// 409: created meanwhile by someone else; reconcile its links below.
		if _, err := r.call("GET", u, nil, &rel, 200); err != nil {
			return err
		}
	}
	for _, want := range links {
		present := false
		for _, have := range rel.Assets.Links {
			switch {
			case have.URL == want.URL && have.Name == want.Name:
				present = true
			case have.URL == want.URL || have.Name == want.Name:
				return fmt.Errorf("release %s already links %q to %s; not touching it", tag, have.Name, have.URL)
			}
		}
		if !present {
			if _, err := r.call("POST", u+"/assets/links", want, nil, 201); err != nil {
				return err
			}
		}
	}
	return nil
}
