package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/selfupdate"
)

// stubUpdaterServing points cmdUpdate's updaterFor seam at a throwaway server that reports
// `tag` as the latest release. It never serves assets, so the tests below must not reach
// the download/replace path (they use --check or decline). It returns nothing; cleanup is
// registered on t.
func stubUpdaterServing(t *testing.T, tag string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var rel selfupdate.Release
		rel.TagName = tag
		_ = json.NewEncoder(w).Encode(&rel)
	}))
	t.Cleanup(srv.Close)

	origUpdater := updaterFor
	t.Cleanup(func() { updaterFor = origUpdater })
	updaterFor = func(version string) (*selfupdate.Updater, error) {
		return &selfupdate.Updater{
			Source:  selfupdate.Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"},
			Client:  srv.Client(),
			GOOS:    "linux",
			GOARCH:  "amd64",
			Current: version,
		}, nil
	}
}

// updateTestEnv isolates HOME so cmdUpdate's update-check cache write (os.UserHomeDir +
// RecordCheck) lands in a temp dir instead of the developer's real ~/.cache/corral. cmdUpdate
// reads no config of its own; the global-config pinning isolateConfigEnv also does is
// incidental here, but harmless and shared with the other CLI command tests.
func updateTestEnv(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
}

func TestCmdUpdateUpToDate(t *testing.T) {
	updateTestEnv(t)
	stubUpdaterServing(t, "v0.3.0")
	var code int
	out := captureStdout(t, func() { code = cmdUpdate([]string{"--check"}, "0.3.0") })
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if want := "corral update\n  ✓ up to date (0.3.0)\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestCmdUpdateCheckReportsNewer(t *testing.T) {
	updateTestEnv(t)
	stubUpdaterServing(t, "v0.4.0")
	var code int
	out := captureStdout(t, func() { code = cmdUpdate([]string{"--check"}, "0.3.0") })
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	want := "corral update\n" +
		"  ! 0.3.0 → 0.4.0 available\n" +
		"                    → corral update\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestCmdUpdateAheadOfRelease(t *testing.T) {
	updateTestEnv(t)
	stubUpdaterServing(t, "v0.3.0")
	var code int
	out := captureStdout(t, func() { code = cmdUpdate([]string{"--check"}, "0.4.0") })
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if want := "corral update\n  ✓ 0.4.0 is newer than the latest release 0.3.0\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestCmdUpdateDevBuild(t *testing.T) {
	updateTestEnv(t)
	stubUpdaterServing(t, "v0.4.0")
	var code int
	out := captureStdout(t, func() { code = cmdUpdate([]string{"--check"}, "dev") })
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	want := "corral update\n" +
		"  ! \"dev\" is not a release build; the latest release is 0.4.0\n" +
		"                    → corral update\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

// Without --check and without --yes, a declined confirmation must abort and never replace
// the binary. The Apply path is guarded by the confirm gate, so stubbing it to decline is
// enough to prove no replacement happens.
func TestCmdUpdateDeclineAborts(t *testing.T) {
	updateTestEnv(t)
	stubUpdaterServing(t, "v0.4.0")

	origConfirm := confirmUpdate
	t.Cleanup(func() { confirmUpdate = origConfirm })
	confirmUpdate = func(bool, *os.File, io.Writer) bool { return false }

	var code int
	stderr := captureStderr(t, func() { code = cmdUpdate(nil, "0.3.0") })
	if code == 0 {
		t.Errorf("a declined update must exit non-zero, got %d", code)
	}
	if !strings.Contains(stderr, "aborted") {
		t.Errorf("stderr = %q, want it to report the update was aborted", stderr)
	}
}

// serveFullReleaseAndTarget points updaterFor at a server serving a complete release
// (archive + SHA256SUMS) and updateTarget at a throwaway "installed" binary (not the test
// binary), returning that target path. sumsOverride replaces the generated checksums file
// to test the fail-closed path. It is the end-to-end harness for the cmdUpdate Apply path.
func serveFullReleaseAndTarget(t *testing.T, version, binContent string, sumsOverride []byte) string {
	t.Helper()
	archiveName := fmt.Sprintf("corral_%s_linux_amd64.tar.gz", version)
	sumsName := fmt.Sprintf("corral_%s_SHA256SUMS", version)

	var ab bytes.Buffer
	gz := gzip.NewWriter(&ab)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "corral", Mode: 0o755, Size: int64(len(binContent)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(binContent)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := ab.Bytes()
	sums := sumsOverride
	if sums == nil {
		sum := sha256.Sum256(archive)
		sums = []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), archiveName))
	}

	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			var rel selfupdate.Release
			rel.TagName = "v" + version
			rel.Assets = []selfupdate.Asset{
				{Name: archiveName, BrowserDownloadURL: base + "/dl/archive"},
				{Name: sumsName, BrowserDownloadURL: base + "/dl/sums"},
			}
			_ = json.NewEncoder(w).Encode(&rel)
		case r.URL.Path == "/dl/archive":
			_, _ = w.Write(archive)
		case r.URL.Path == "/dl/sums":
			_, _ = w.Write(sums)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	base = srv.URL

	origUpdater := updaterFor
	t.Cleanup(func() { updaterFor = origUpdater })
	updaterFor = func(cur string) (*selfupdate.Updater, error) {
		return &selfupdate.Updater{
			Source: selfupdate.Source{APIBase: srv.URL, Owner: "go-corral", Repo: "corral"},
			Client: srv.Client(), GOOS: "linux", GOARCH: "amd64", Current: cur,
		}, nil
	}

	target := filepath.Join(t.TempDir(), "corral")
	if err := os.WriteFile(target, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	origTarget := updateTarget
	t.Cleanup(func() { updateTarget = origTarget })
	updateTarget = func() (string, error) { return target, nil }
	return target
}

// The full Apply path: download → verify → atomically replace the (throwaway) binary.
func TestCmdUpdateInstallsBinary(t *testing.T) {
	updateTestEnv(t)
	target := serveFullReleaseAndTarget(t, "0.4.0", "NEW BINARY BYTES", nil)
	origConfirm := confirmUpdate
	t.Cleanup(func() { confirmUpdate = origConfirm })
	confirmUpdate = func(bool, *os.File, io.Writer) bool { return true }

	var code int
	out := captureStdout(t, func() { code = cmdUpdate(nil, "0.3.0") })
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%s", code, out)
	}
	if got, _ := os.ReadFile(target); string(got) != "NEW BINARY BYTES" {
		t.Errorf("target content = %q, want the new binary", got)
	}
	want := "corral update\n" +
		"  ! 0.3.0 → 0.4.0 available\n" +
		"    binary          " + target + "\n" +
		"  ✓ updated to 0.4.0\n" +
		"                    re-run corral sync if a release note says the hook\n" +
		"                    registration changed\n" +
		"                    → corral sync\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

// CLI-level fail-closed: a checksum mismatch must abort and leave the binary untouched.
func TestCmdUpdateChecksumMismatchDoesNotReplace(t *testing.T) {
	updateTestEnv(t)
	bad := []byte("deadbeef  corral_0.4.0_linux_amd64.tar.gz\n")
	target := serveFullReleaseAndTarget(t, "0.4.0", "NEW BINARY BYTES", bad)
	origConfirm := confirmUpdate
	t.Cleanup(func() { confirmUpdate = origConfirm })
	confirmUpdate = func(bool, *os.File, io.Writer) bool { return true }

	var code int
	captureStderr(t, func() { code = cmdUpdate([]string{"--yes"}, "0.3.0") })
	if code == 0 {
		t.Error("a checksum mismatch must exit non-zero")
	}
	if got, _ := os.ReadFile(target); string(got) != "OLD" {
		t.Errorf("target was replaced despite a checksum mismatch: %q", got)
	}
}

// confirmUpdate must not proceed non-interactively without --yes (replacing the binary is
// destructive), and must not prompt when there is no terminal.
func TestConfirmUpdateNonInteractive(t *testing.T) {
	r, _, err := os.Pipe() // a pipe read end is not a char device
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	var buf strings.Builder
	if confirmUpdate(false, r, &buf) {
		t.Error("confirmUpdate(false, non-tty) = true; a non-interactive update must require --yes")
	}
	if buf.Len() != 0 {
		t.Errorf("confirmUpdate prompted on a non-tty: %q", buf.String())
	}
	if !confirmUpdate(true, r, &buf) {
		t.Error("confirmUpdate(true, …) = false; --yes must proceed")
	}
}

// /dev/null is a character device, so a mode-bit check would misclassify it as an
// interactive terminal — report.IsTerminal asks the tty driver instead. confirmUpdate must refuse
// the non-interactive update without --yes and without prompting.
func TestConfirmUpdateDevNullNonInteractive(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var buf strings.Builder
	if confirmUpdate(false, f, &buf) {
		t.Error("confirmUpdate(false, /dev/null) = true; a non-interactive update must require --yes")
	}
	if buf.Len() != 0 {
		t.Errorf("confirmUpdate prompted on /dev/null: %q", buf.String())
	}
	if !confirmUpdate(true, f, &buf) {
		t.Error("confirmUpdate(true, …) = false; --yes must proceed")
	}
}
