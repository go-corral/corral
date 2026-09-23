// Package selfupdate downloads, verifies, and installs a newer corral release in place.
// It fails closed on integrity: a missing or mismatched SHA-256 aborts and never touches the
// installed binary. The release source derives solely from the compiled module path
// (github.com/<owner>/<repo>) and is not configurable, so nothing at runtime can redirect where
// binaries come from.
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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

const defaultModulePath = "github.com/go-corral/corral"

const (
	maxMetaBytes    = 4 << 20   // release JSON + the SHA256SUMS file
	maxArchiveBytes = 256 << 20 // the .tar.gz release archive
)

type Source struct {
	APIBase string
	Owner   string
	Repo    string
}

type Updater struct {
	Source  Source
	Token   string
	Client  *http.Client
	GOOS    string
	GOARCH  string
	Current string
}

type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func (r *Release) Version() string { return StripV(r.TagName) }

func New(src Source, currentVersion string) *Updater {
	return &Updater{
		Source:  src,
		Token:   AuthToken(),
		Client:  &http.Client{},
		GOOS:    runtime.GOOS,
		GOARCH:  runtime.GOARCH,
		Current: currentVersion,
	}
}

// AuthToken returns the optional GitHub API token from the environment. GITHUB_TOKEN takes
// precedence; GH_TOKEN is the fallback. Empty when neither is set.
func AuthToken() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

// ResolveSource returns the fixed release source derived from the compiled module path.
// A host other than github.com is treated as a GitHub Enterprise instance (api base /api/v3).
func ResolveSource() (Source, error) {
	path := defaultModulePath
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Path != "" {
		path = bi.Main.Path
	}
	host, rest, found := strings.Cut(path, "/")
	if !found {
		return Source{}, fmt.Errorf("cannot derive the update source from module path %q", path)
	}
	segs := strings.SplitN(rest, "/", 3)
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return Source{}, fmt.Errorf("cannot derive owner/repo from module path %q", path)
	}
	apiBase := "https://api.github.com"
	if host != "github.com" {
		apiBase = "https://" + host + "/api/v3"
	}
	return Source{APIBase: apiBase, Owner: segs[0], Repo: segs[1]}, nil
}

var ErrNoRelease = errors.New("no published release found")

// LatestRelease fetches the project's most recent release via the GitHub "latest" endpoint.
// A 404 maps to ErrNoRelease.
func (u *Updater) LatestRelease(ctx context.Context) (*Release, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/latest", u.Source.APIBase, u.Source.Owner, u.Source.Repo)
	body, err := u.get(ctx, endpoint, githubJSON, maxMetaBytes)
	if se := (*statusError)(nil); errors.As(err, &se) && se.code == http.StatusNotFound {
		return nil, ErrNoRelease
	}
	if err != nil {
		return nil, err
	}
	var r Release
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode release metadata: %w", err)
	}
	if r.TagName == "" {
		return nil, ErrNoRelease
	}
	return &r, nil
}

// Apply downloads the release archive, verifies it against the release's SHA256SUMS (fail-closed),
// extracts the corral binary, and atomically replaces targetPath, returning the installed version.
func (u *Updater) Apply(ctx context.Context, rel *Release, targetPath string, log io.Writer) (string, error) {
	version := rel.Version()
	archiveName := fmt.Sprintf("corral_%s_%s_%s.tar.gz", version, u.GOOS, u.GOARCH)
	sumsName := fmt.Sprintf("corral_%s_SHA256SUMS", version)

	archiveURL, err := assetURL(rel, archiveName)
	if err != nil {
		return "", err
	}
	sumsURL, err := assetURL(rel, sumsName)
	if err != nil {
		return "", err
	}

	logf(log, "downloading %s", archiveName)
	archive, err := u.get(ctx, archiveURL, octetStream, maxArchiveBytes)
	if err != nil {
		return "", fmt.Errorf("download archive: %w", err)
	}
	sums, err := u.get(ctx, sumsURL, octetStream, maxMetaBytes)
	if err != nil {
		return "", fmt.Errorf("download checksums: %w", err)
	}

	want, ok := checksumFor(sums, archiveName)
	if !ok {
		return "", fmt.Errorf("no SHA-256 checksum for %s in %s — refusing to update", archiveName, sumsName)
	}
	got := sha256.Sum256(archive)
	if gotHex := hex.EncodeToString(got[:]); gotHex != want {
		return "", fmt.Errorf("checksum mismatch for %s: downloaded %s, expected %s — refusing to update", archiveName, gotHex, want)
	}
	logf(log, "checksum verified (sha256)")

	bin, err := extractBinary(archive)
	if err != nil {
		return "", err
	}
	if err := replaceBinary(targetPath, bin); err != nil {
		return "", err
	}
	return version, nil
}

func assetURL(rel *Release, name string) (string, error) {
	var have []string
	for _, a := range rel.Assets {
		if a.Name == name {
			if a.BrowserDownloadURL != "" {
				return a.BrowserDownloadURL, nil
			}
			if a.URL != "" {
				return a.URL, nil
			}
		}
		have = append(have, a.Name)
	}
	return "", fmt.Errorf("release %s has no asset %q (assets: %s)", rel.TagName, name, strings.Join(have, ", "))
}

func checksumFor(sums []byte, assetName string) (string, bool) {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(name) == assetName {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

func extractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "corral" {
			continue
		}
		buf, err := io.ReadAll(io.LimitReader(tr, maxArchiveBytes))
		if err != nil {
			return nil, fmt.Errorf("extract corral binary: %w", err)
		}
		if len(buf) == 0 {
			return nil, errors.New("extracted corral binary is empty")
		}
		return buf, nil
	}
	return nil, errors.New("archive does not contain a corral binary")
}

// replaceBinary atomically installs data at targetPath via a sibling temp file, keeping the
// existing binary's mode with the execute bit forced on. On any failure the temp is removed
// and targetPath untouched.
func replaceBinary(targetPath string, data []byte) error {
	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".corral-update-*")
	if err != nil {
		return fmt.Errorf("cannot stage update in %s (need write access to update in place): %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write staged binary: %w", err)
	}
	if err := tmp.Chmod(targetMode(targetPath)); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod staged binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync staged binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close staged binary: %w", err)
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		cleanup()
		return fmt.Errorf("install %s (need write access to update in place): %w", targetPath, err)
	}
	return nil
}

func targetMode(targetPath string) os.FileMode {
	if fi, err := os.Stat(targetPath); err == nil {
		return fi.Mode().Perm() | 0o111
	}
	return 0o755
}

const (
	githubJSON  = "application/vnd.github+json"
	octetStream = "application/octet-stream"
)

// get issues a GET with the optional token and Accept type, following redirects, enforcing
// 2xx, and returning up to max bytes. The token is dropped automatically on cross-host redirects.
func (u *Updater) get(ctx context.Context, rawURL, accept string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if u.Token != "" {
		req.Header.Set("Authorization", "Bearer "+u.Token)
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, &statusError{code: resp.StatusCode, status: resp.Status, body: strings.TrimSpace(string(snippet))}
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

type statusError struct {
	code   int
	status string
	body   string
}

func (e *statusError) Error() string {
	if e.body != "" {
		return e.status + ": " + e.body
	}
	return e.status
}

func logf(w io.Writer, format string, a ...any) {
	if w != nil {
		fmt.Fprintf(w, format+"\n", a...)
	}
}
