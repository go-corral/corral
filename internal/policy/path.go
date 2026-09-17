package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-corral/corral/internal/pathutil"
)

// Canonicalize resolves p to an absolute, symlink-free path suitable for prefix matching. It is
// the core anti-bypass primitive: it defeats renamed-secret/traversal tricks (via Clean + symlink
// resolution) and "write to a path that does not exist yet" tricks (via the lstat-ancestor walk).
// Relative paths are resolved against cwd. The deepest existing ancestor is resolved with
// EvalSymlinks; the non-existent tail is cleaned and re-appended without resolution, so a Write to
// ~/.ssh/authorized_keys canonicalizes under ~/.ssh even though the file does not exist yet.
// Any error other than "does not exist" is returned; callers must fail closed on it.
func Canonicalize(p, cwd string) (string, error) {
	abs, err := lexicalAbs(p, cwd)
	if err != nil {
		return "", err
	}
	return resolveExistingPrefix(abs)
}

// CanonicalizeRoot is Canonicalize for trusted, statically-configured deny roots (the
// always-blocked dirs, config block.directories/files). It differs in one way: a permission error
// during resolution is not fatal — it falls back to the lexically-cleaned absolute path. A sandbox
// (including the macOS Seatbelt profile corral generates) may deny even lstat on the very paths
// corral blocks; strict Canonicalize would brick the whole policy engine there. The lexical prefix
// can only deny more, never less, and any event reaching under an unresolvable ancestor still fails
// closed on its own (strict) canonicalization. Only trusted deny roots, never event paths, relax.
func CanonicalizeRoot(p, cwd string) (string, error) {
	abs, err := lexicalAbs(p, cwd)
	if err != nil {
		return "", err
	}
	canon, err := resolveExistingPrefix(abs)
	if err == nil {
		return canon, nil
	}
	if errors.Is(err, fs.ErrPermission) {
		return abs, nil
	}
	return "", err
}

func lexicalAbs(p, cwd string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if !filepath.IsAbs(p) {
		if cwd == "" {
			return "", fmt.Errorf("relative path %q with no cwd", p)
		}
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p), nil
}

func resolveExistingPrefix(p string) (string, error) {
	var tail []string // path components, deepest first
	cur := p
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			out := resolved
			for i := len(tail) - 1; i >= 0; i-- {
				out = filepath.Join(out, tail[i])
			}
			return out, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("canonicalize %q: %w", p, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("canonicalize %q: no existing ancestor", p)
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

// logicalSysPath maps the macOS firmlink-resolved system roots /private/etc, /private/var and
// /private/tmp back to their conventional /etc, /var and /tmp names. On darwin, /etc is a symlink
// to /private/etc, so Canonicalize resolves a Read of /etc/shadow to /private/etc/shadow. The
// policy's literal system-path matchers are written against the conventional names, so without
// this normalization those gates silently fail to deny /etc/shadow on macOS. No-op off darwin and
// on anything not under a /private firmlink subtree, so Linux behaviour is byte-identical.
// Prefix-safe: the trailing slash keeps /private/etcd from matching /private/etc.
func logicalSysPath(p string) string {
	return logicalSysPathFor(p, runtime.GOOS)
}

// logicalSysPathFor is the goos-parameterized core of logicalSysPath, split out so the darwin
// firmlink mapping is unit-testable on any platform.
func logicalSysPathFor(p, goos string) string {
	if goos != "darwin" {
		return p
	}
	switch p {
	case "/private/etc":
		return "/etc"
	case "/private/var":
		return "/var"
	case "/private/tmp":
		return "/tmp"
	}
	for _, pre := range []string{"/private/etc/", "/private/var/", "/private/tmp/"} {
		if strings.HasPrefix(p, pre) {
			return strings.TrimPrefix(p, "/private")
		}
	}
	return p
}

// Within reports whether canonical path p is equal to, or nested under, the canonical directory
// root. Prefix-safe: "/home/u/.sshx" is not within "/home/u/.ssh".
func Within(p, root string) bool {
	return pathutil.AtOrUnder(p, root)
}
