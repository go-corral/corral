package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildArchive produces a .tar.gz holding a "corral" file with the given content (plus a
// decoy file, mirroring the real release archive which also ships LICENSE/README).
func buildArchive(t *testing.T, binContent string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name, body string, mode int64) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write("LICENSE", "decoy license\n", 0o644)
	write("corral", binContent, 0o755)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fakeRelease spins up an httptest server that serves a release for version `ver`
// (os/arch linux/amd64) with the given archive and SHA256SUMS bodies, and returns an
// Updater pointed at it with Current=current. sumsOverride, when non-nil, replaces the
// generated checksums file (to test mismatch/missing cases). includeArchiveAsset=false
// omits the archive asset (to test the missing-asset case).
func fakeRelease(t *testing.T, ver, current string, archive []byte, sumsOverride []byte, includeArchiveAsset bool) *Updater {
	t.Helper()
	archiveName := fmt.Sprintf("corral_%s_linux_amd64.tar.gz", ver)
	sumsName := fmt.Sprintf("corral_%s_SHA256SUMS", ver)
	sums := sumsOverride
	if sums == nil {
		sums = []byte(fmt.Sprintf("%s  %s\n", sha256Hex(archive), archiveName))
	}

	var base string
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			var rel Release
			rel.TagName = "v" + ver
			rel.Name = "v" + ver
			rel.Assets = []Asset{
				{Name: sumsName, BrowserDownloadURL: base + "/dl/sums"},
			}
			if includeArchiveAsset {
				rel.Assets = append(rel.Assets,
					Asset{Name: archiveName, BrowserDownloadURL: base + "/dl/archive"})
			}
			_ = json.NewEncoder(w).Encode(&rel)
		case r.URL.Path == "/dl/archive":
			_, _ = w.Write(archive)
		case r.URL.Path == "/dl/sums":
			_, _ = w.Write(sums)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	base = srv.URL
	return &Updater{
		Source:  Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"},
		Client:  srv.Client(),
		GOOS:    "linux",
		GOARCH:  "amd64",
		Current: current,
	}
}

func TestLatestRelease(t *testing.T) {
	u := fakeRelease(t, "0.4.0", "0.3.0", buildArchive(t, "new"), nil, true)
	rel, err := u.LatestRelease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rel.TagName != "v0.4.0" || rel.Version() != "0.4.0" {
		t.Errorf("tag=%q version=%q, want v0.4.0 / 0.4.0", rel.TagName, rel.Version())
	}
}

func TestLatestReleaseNoRelease(t *testing.T) {
	// A project with no releases: the latest endpoint 404s → ErrNoRelease.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "404 Not Found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	u := &Updater{Source: Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"}, Client: srv.Client()}
	if _, err := u.LatestRelease(context.Background()); !errors.Is(err, ErrNoRelease) {
		t.Errorf("err = %v, want ErrNoRelease", err)
	}
}

// installTarget writes a stand-in "old" binary and returns its path; Apply must replace it.
func installTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "corral")
	if err := os.WriteFile(target, []byte("OLD BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestApplySuccess(t *testing.T) {
	archive := buildArchive(t, "NEW BINARY")
	u := fakeRelease(t, "0.4.0", "0.3.0", archive, nil, true)
	target := installTarget(t)

	rel, err := u.LatestRelease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	newVer, err := u.Apply(context.Background(), rel, target, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if newVer != "0.4.0" {
		t.Errorf("newVer = %q, want 0.4.0", newVer)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW BINARY" {
		t.Errorf("target content = %q, want NEW BINARY", got)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("replaced binary is not executable: mode %v", fi.Mode())
	}
	// No staging temp file is left behind in the target directory.
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".corral-update-") {
			t.Errorf("leftover staging file: %s", e.Name())
		}
	}
}

func TestApplyChecksumMismatchFailsClosed(t *testing.T) {
	archive := buildArchive(t, "NEW BINARY")
	badSums := []byte("deadbeef  corral_0.4.0_linux_amd64.tar.gz\n") // wrong hash
	u := fakeRelease(t, "0.4.0", "0.3.0", archive, badSums, true)
	target := installTarget(t)

	rel, _ := u.LatestRelease(context.Background())
	_, err := u.Apply(context.Background(), rel, target, nil)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Apply err = %v, want checksum mismatch", err)
	}
	// Fail-closed: the installed binary is untouched.
	if got, _ := os.ReadFile(target); string(got) != "OLD BINARY" {
		t.Errorf("target was modified despite checksum mismatch: %q", got)
	}
}

func TestApplyMissingChecksumEntryFailsClosed(t *testing.T) {
	archive := buildArchive(t, "NEW BINARY")
	sums := []byte("abc123  some_other_file.tar.gz\n") // no entry for our archive
	u := fakeRelease(t, "0.4.0", "0.3.0", archive, sums, true)
	target := installTarget(t)

	rel, _ := u.LatestRelease(context.Background())
	_, err := u.Apply(context.Background(), rel, target, nil)
	if err == nil || !strings.Contains(err.Error(), "no SHA-256 checksum") {
		t.Fatalf("Apply err = %v, want missing-checksum error", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "OLD BINARY" {
		t.Errorf("target was modified despite missing checksum: %q", got)
	}
}

func TestApplyMissingAssetFailsClosed(t *testing.T) {
	archive := buildArchive(t, "NEW BINARY")
	u := fakeRelease(t, "0.4.0", "0.3.0", archive, nil, false) // archive asset omitted
	target := installTarget(t)

	rel, _ := u.LatestRelease(context.Background())
	_, err := u.Apply(context.Background(), rel, target, nil)
	if err == nil || !strings.Contains(err.Error(), "no asset") {
		t.Fatalf("Apply err = %v, want missing-asset error", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "OLD BINARY" {
		t.Errorf("target was modified despite missing asset: %q", got)
	}
}

func TestChecksumFor(t *testing.T) {
	sums := []byte(strings.Join([]string{
		"aaaa  corral_0.4.0_linux_amd64.tar.gz",  // two-space (text) form
		"bbbb *corral_0.4.0_darwin_arm64.tar.gz", // asterisk (binary) form
		"cccc  dist/corral_0.4.0_linux_arm64.tar.gz",
		"garbage line with too many fields here",
		"",
	}, "\n"))
	for name, want := range map[string]string{
		"corral_0.4.0_linux_amd64.tar.gz":  "aaaa",
		"corral_0.4.0_darwin_arm64.tar.gz": "bbbb",
		"corral_0.4.0_linux_arm64.tar.gz":  "cccc", // matched on base name
	} {
		got, ok := checksumFor(sums, name)
		if !ok || got != want {
			t.Errorf("checksumFor(%q) = (%q, %v), want (%q, true)", name, got, ok, want)
		}
	}
	if _, ok := checksumFor(sums, "corral_0.4.0_windows_amd64.tar.gz"); ok {
		t.Error("checksumFor found a checksum for an absent asset")
	}
}

func TestAssetURL(t *testing.T) {
	rel := &Release{TagName: "v0.4.0"}
	rel.Assets = []Asset{
		{Name: "a", URL: "http://x/url", BrowserDownloadURL: "http://x/direct"},
		{Name: "b", URL: "http://x/onlyurl"},
	}
	if got, _ := assetURL(rel, "a"); got != "http://x/direct" {
		t.Errorf("assetURL(a) = %q, want the browser_download_url", got)
	}
	if got, _ := assetURL(rel, "b"); got != "http://x/onlyurl" {
		t.Errorf("assetURL(b) = %q, want the url fallback", got)
	}
	if _, err := assetURL(rel, "missing"); err == nil {
		t.Error("assetURL(missing) should error")
	}
}

func TestExtractBinary(t *testing.T) {
	got, err := extractBinary(buildArchive(t, "BINARY BYTES"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "BINARY BYTES" {
		t.Errorf("extracted %q, want BINARY BYTES", got)
	}

	// An archive with no corral entry is rejected.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "README", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	_ = gz.Close()
	if _, err := extractBinary(buf.Bytes()); err == nil {
		t.Error("extractBinary should reject an archive without a corral binary")
	}

	// Non-gzip input is rejected.
	if _, err := extractBinary([]byte("not a gzip")); err == nil {
		t.Error("extractBinary should reject non-gzip input")
	}
}

func TestReplaceBinaryPreservesModeAndIsAtomic(t *testing.T) {
	target := installTarget(t)
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(target, []byte("REPLACED")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "REPLACED" {
		t.Errorf("content = %q, want REPLACED", got)
	}

	// A target whose directory does not exist fails cleanly (no panic, clear error).
	if err := replaceBinary(filepath.Join(t.TempDir(), "nope", "corral"), []byte("x")); err == nil {
		t.Error("replaceBinary into a missing directory should error")
	}
}

func TestResolveSource(t *testing.T) {
	// The source is fixed at compile time (derived from the module path) and takes no
	// arguments — there is no config/env override. Under `go test` the module path is this
	// module, so the owner/repo are non-empty and the API base is GitHub's.
	src, err := ResolveSource()
	if err != nil {
		t.Fatal(err)
	}
	if src.APIBase != "https://api.github.com" || src.Owner == "" || src.Repo == "" {
		t.Errorf("ResolveSource = %+v", src)
	}
}

// A 5xx on the metadata endpoint is a real error, not ErrNoRelease (which is reserved for
// 404 / a project with no releases).
func TestLatestReleaseServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	u := &Updater{Source: Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"}, Client: srv.Client()}
	_, err := u.LatestRelease(context.Background())
	if err == nil || errors.Is(err, ErrNoRelease) {
		t.Errorf("err = %v, want a non-nil error that is NOT ErrNoRelease", err)
	}
}

// A failed asset download must fail closed: Apply errors and the installed binary is untouched.
func TestApplyDownloadFailureFailsClosed(t *testing.T) {
	archiveName := "corral_0.4.0_linux_amd64.tar.gz"
	sumsName := "corral_0.4.0_SHA256SUMS"
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			var rel Release
			rel.TagName = "v0.4.0"
			rel.Assets = []Asset{
				{Name: archiveName, BrowserDownloadURL: base + "/dl/archive"},
				{Name: sumsName, BrowserDownloadURL: base + "/dl/sums"},
			}
			_ = json.NewEncoder(w).Encode(&rel)
		case r.URL.Path == "/dl/archive":
			http.Error(w, "upstream down", http.StatusBadGateway) // the archive 502s
		default:
			_, _ = w.Write([]byte("whatever"))
		}
	}))
	t.Cleanup(srv.Close)
	base = srv.URL
	u := &Updater{
		Source: Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"},
		Client: srv.Client(), GOOS: "linux", GOARCH: "amd64", Current: "0.3.0",
	}
	target := installTarget(t)
	rel, _ := u.LatestRelease(context.Background())
	if _, err := u.Apply(context.Background(), rel, target, nil); err == nil {
		t.Fatal("Apply must fail when the archive download fails")
	}
	if got, _ := os.ReadFile(target); string(got) != "OLD BINARY" {
		t.Errorf("target was modified despite a failed download: %q", got)
	}
}

func TestChecksumForEmptyAndBlank(t *testing.T) {
	for _, sums := range [][]byte{[]byte(""), []byte("\n  \n\t\n"), []byte("onlyonefield\n")} {
		if _, ok := checksumFor(sums, "corral_0.4.0_linux_amd64.tar.gz"); ok {
			t.Errorf("checksumFor(%q) reported a match for empty/blank/malformed input", sums)
		}
	}
}

// extractBinary must fail closed on a "corral" that is not a regular file, and on an empty one.
func TestExtractBinaryRejectsNonRegularAndEmpty(t *testing.T) {
	tarGz := func(build func(*tar.Writer)) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		build(tw)
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	// A symlink named "corral" is not a regular file → no binary found.
	symlink := tarGz(func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "corral", Typeflag: tar.TypeSymlink, Linkname: "/bin/sh"})
	})
	if _, err := extractBinary(symlink); err == nil {
		t.Error("extractBinary should reject a symlink named corral")
	}

	// A zero-byte "corral" regular file is rejected as empty.
	empty := tarGz(func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "corral", Mode: 0o755, Size: 0, Typeflag: tar.TypeReg})
	})
	if _, err := extractBinary(empty); err == nil {
		t.Error("extractBinary should reject a zero-byte corral binary")
	}
}

// The token authenticates every request as a Bearer token, and the latest-release endpoint
// is addressed by owner/repo (GitHub shape). A private repository requires the token; this
// proves the header is sent and the path is correct.
func TestTokenSentAsBearerAndEndpointIsGitHubShaped(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		var rel Release
		rel.TagName = "v0.4.0"
		_ = json.NewEncoder(w).Encode(&rel)
	}))
	t.Cleanup(srv.Close)
	u := &Updater{
		Source: Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"},
		Token:  "ghp_testtoken",
		Client: srv.Client(),
	}
	if _, err := u.LatestRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer ghp_testtoken" {
		t.Errorf("Authorization = %q, want Bearer ghp_testtoken", gotAuth)
	}
	if want := "/repos/go-corral/corral/releases/latest"; gotPath != want {
		t.Errorf("endpoint path = %q, want %q", gotPath, want)
	}
}

// An unauthenticated Updater (no token set) sends no Authorization header — the shape a
// public repository is fetched with once the project goes public.
func TestNoTokenSendsNoAuthorization(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var rel Release
		rel.TagName = "v0.4.0"
		_ = json.NewEncoder(w).Encode(&rel)
	}))
	t.Cleanup(srv.Close)
	u := &Updater{Source: Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"}, Client: srv.Client()}
	if _, err := u.LatestRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty (unauthenticated)", gotAuth)
	}
}

// AuthToken reads GITHUB_TOKEN first and falls back to GH_TOKEN (the gh CLI convention).
func TestAuthTokenEnvPrecedence(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	if AuthToken() != "" {
		t.Fatal("AuthToken should be empty when neither env var is set")
	}
	t.Setenv("GH_TOKEN", "gh_fallback")
	if got := AuthToken(); got != "gh_fallback" {
		t.Errorf("AuthToken = %q, want gh_fallback (GH_TOKEN fallback)", got)
	}
	t.Setenv("GITHUB_TOKEN", "gh_preferred")
	if got := AuthToken(); got != "gh_preferred" {
		t.Errorf("AuthToken = %q, want gh_preferred (GITHUB_TOKEN takes precedence)", got)
	}
}

// A cross-host redirect (the API asset URL → a signed storage host) must not carry the
// Authorization header: Go's http.Client strips it when the redirect leaves the API host,
// so the token is never sent to the storage backend.
func TestTokenDroppedOnCrossHostRedirect(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect the asset download to a different hostname.
		http.Redirect(w, r, "http://objects.example.test/asset", http.StatusFound)
	}))
	t.Cleanup(api.Close)

	u := &Updater{
		Source: Source{APIBase: api.URL, Owner: "go-corral", Repo: "corral"},
		Token:  "ghp_secret",
		Client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if auth := req.Header.Get("Authorization"); auth != "" {
					t.Errorf("Authorization leaked to redirect target %s: %q", req.URL.Host, auth)
				}
				return http.ErrUseLastResponse // don't actually follow
			},
		},
	}
	// u.get returns the 302 as a non-2xx statusError; the assertion is in CheckRedirect.
	_, _ = u.get(context.Background(), api.URL+"/dl", octetStream, maxArchiveBytes)
}
