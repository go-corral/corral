// Package ssh implements the "ssh" feature provider: agent-socket forwarding plus
// read-only overlays of the vetted ssh config files on the always-blocked, masked ~/.ssh.
package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

// Include-resolution safety caps (DoS / pathological-config bounds).
const (
	sshMaxIncludeDepth = 16
	sshMaxFiles        = 256
)

// ssh is the "ssh" feature provider. Enabling it grants SSH into the sandbox:
//   - the ssh-agent (SSH_AUTH_SOCK socket mount + env) — signing without keys;
//   - read-only ssh *config*: ~/.ssh/config, every file it Includes, and
//     ~/.ssh/known_hosts, layered as overlay mounts on top of the masked
//     ~/.ssh (the mask empties ~/.ssh; the overlay re-adds only these vetted files).
//
// Private key files are never mounted (the agent does the signing). Every candidate is
// resolved with EvalSymlinks and the real path is bound (so bwrap can't be tricked into
// mounting a symlink target); must be a regular file; and must never resolve into the
// other masked secret dirs (forbidden, e.g. ~/.gnupg, ~/.aws) — enabling "ssh" must not
// side-door those.
type ssh struct {
	home      string
	sshDir    string   // <home>/.ssh
	authSock  string   // resolved host SSH_AUTH_SOCK ("" = no agent)
	forbidden []string // realpath roots a config file may never resolve into
}

// New builds the ssh provider. authSock is the host SSH_AUTH_SOCK; floor is the
// set of always-blocked secret-dir roots (config.AlwaysBlockedExpanded — already
// absolute). The provider derives its own containment policy from it: ~/.ssh is
// excluded (that is exactly the dir the overlay legitimately re-grants files
// from), and a config file must never resolve into any of the remaining roots
// (~/.gnupg, ~/.aws, ~/.kube, …) — enabling "ssh" must not side-door the other masked
// secrets. Owning the subtraction here keeps the policy with the code it guards.
func New(home, authSock string, floor []string) spec.Provider {
	sshDir := filepath.Join(home, ".ssh")
	var forbidden []string
	for _, p := range floor {
		if p != sshDir {
			forbidden = append(forbidden, p)
		}
	}
	return &ssh{
		home:      home,
		sshDir:    sshDir,
		authSock:  strings.TrimSpace(authSock),
		forbidden: resolveForbidden(forbidden),
	}
}

// resolveForbidden maps each forbidden root to its EvalSymlinks realpath so
// isForbidden compares like-for-like with the discovered candidates (which are
// themselves EvalSymlinks-resolved in collectConfigFiles). Without this a root
// whose realpath differs from its lexical form is never matched: on macOS
// /var/root/.gnupg resolves to /private/var/root/.gnupg (the /var firmlink), and
// on any OS a ~/.gnupg that is itself a symlink resolves elsewhere — either way
// the forbidden check would silently let a config Include side-door into the
// masked secret dir. A root that does not exist can hold no discoverable file, so
// the cleaned lexical path is a safe (never-matching) fallback.
func resolveForbidden(roots []string) []string {
	out := make([]string, len(roots))
	for i, r := range roots {
		if real, err := filepath.EvalSymlinks(r); err == nil {
			out[i] = real
		} else {
			out[i] = filepath.Clean(r)
		}
	}
	return out
}

func (s *ssh) Name() string { return "ssh" }

// Available is true when there is something to grant: a live agent socket, or an
// ssh config / known_hosts to expose.
func (s *ssh) Available(ctx context.Context) bool {
	if s.authSock != "" && spec.IsSocket(s.authSock) {
		return true
	}
	return spec.IsRegular(filepath.Join(s.sshDir, "config")) ||
		spec.IsRegular(filepath.Join(s.sshDir, "known_hosts"))
}

// Mint reads host state only (ssh config + the agent socket) and mutates nothing, so it
// is inherently side-effect-free: the dryRun flag changes nothing here (it exists
// for the Provider contract so ResolvePreview can reuse this same body via Mint).
func (s *ssh) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	c := &spec.Contribution{Env: map[string]string{}}

	// 1. The agent. Its socket may live anywhere — including under a masked secret
	// dir (gpg-agent's ssh socket is in ~/.gnupg). It is the explicitly-enabled
	// capability, so it rides as an Overlay (rw) and is exempt from the forbidden
	// check that applies to discovered config files. Bind the EvalSymlinks-resolved
	// realpath as the source (same guard as config files: bwrap can't be redirected
	// by a symlinked SSH_AUTH_SOCK at mount time), but keep the destination + env at
	// the path ssh clients expect.
	if s.authSock != "" && spec.IsSocket(s.authSock) {
		if real, err := filepath.EvalSymlinks(s.authSock); err == nil {
			c.Mounts = append(c.Mounts, sandbox.Mount{
				Src: real, Dst: s.authSock, Overlay: true, Optional: true,
			})
			c.Env["SSH_AUTH_SOCK"] = s.authSock
			// The base sandbox note says ~/.ssh is masked — without this line the model
			// concludes ssh/git-over-ssh cannot work and stops trying. Agent branch only:
			// config/known_hosts overlays alone grant no auth, so there they'd oversell.
			c.AgentNotes = append(c.AgentNotes,
				"ssh works despite the masked ~/.ssh: the host ssh-agent is forwarded via SSH_AUTH_SOCK (keys never enter the sandbox; the agent signs).")
		}
	}

	// 2. Config + its includes + known_hosts, as read-only overlays on masked ~/.ssh.
	files := s.collectConfigFiles()
	for _, f := range files {
		c.Mounts = append(c.Mounts, sandbox.Mount{
			Src: f.src, Dst: f.dst, ReadOnly: true, Overlay: true, Optional: true,
		})
	}

	if len(c.Mounts) == 0 {
		return nil, errors.New("ssh: nothing to provide (no agent, config, or known_hosts)")
	}
	var granted []string
	if _, ok := c.Env["SSH_AUTH_SOCK"]; ok {
		granted = append(granted, "forwarding the host ssh-agent socket (SSH_AUTH_SOCK)")
	}
	if len(files) > 0 {
		granted = append(granted, fmt.Sprintf("overlaying %d vetted config file(s) read-only on the masked ~/.ssh", len(files)))
	}
	c.Status = []string{strings.Join(granted, "; ")}
	return c, nil
}

// sshFile pairs the sandbox destination with the resolved real host source.
type sshFile struct{ src, dst string }

// collectConfigFiles resolves ~/.ssh/config, follows its Include directives, and
// returns the vetted set of config files plus known_hosts. Recursion is bounded
// by depth, a visited-realpath set, and a total-file cap.
func (s *ssh) collectConfigFiles() []sshFile {
	var out []sshFile
	seen := map[string]bool{}

	// vet resolves dst to a real path and applies the guards.
	vet := func(dst string) (real string, ok bool) {
		if len(seen) >= sshMaxFiles {
			return "", false
		}
		real, err := filepath.EvalSymlinks(dst)
		if err != nil || !spec.IsRegular(real) || s.isForbidden(real) || seen[real] {
			return "", false
		}
		seen[real] = true
		return real, true
	}

	var walk func(dst string, depth int)
	walk = func(dst string, depth int) {
		real, ok := vet(dst)
		if !ok {
			return
		}
		out = append(out, sshFile{src: real, dst: dst})
		if depth >= sshMaxIncludeDepth {
			return
		}
		for _, pat := range parseIncludes(real) {
			for _, target := range s.resolveInclude(pat) {
				walk(target, depth+1)
			}
		}
	}

	walk(filepath.Join(s.sshDir, "config"), 0)

	kh := filepath.Join(s.sshDir, "known_hosts")
	if real, ok := vet(kh); ok {
		out = append(out, sshFile{src: real, dst: kh})
	}
	return out
}

// resolveInclude expands one Include pattern into candidate destination paths.
// Per ssh_config(5), a relative pattern in a user config is resolved against
// ~/.ssh; ~ expands to home; globs expand. ~user is not expanded.
func (s *ssh) resolveInclude(pattern string) []string {
	pattern = strings.TrimSpace(pattern)
	switch {
	case pattern == "":
		return nil
	case pattern == "~":
		pattern = s.home
	case strings.HasPrefix(pattern, "~/"):
		pattern = filepath.Join(s.home, pattern[2:])
	case !filepath.IsAbs(pattern):
		pattern = filepath.Join(s.sshDir, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

// parseIncludes extracts the arguments of every Include directive in an ssh
// config file. It ignores Host/Match block context: for mounting we want every
// file ssh might read, so we over-approximate rather than evaluate conditions.
func parseIncludes(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var incs []string
	sc := bufio.NewScanner(f)
	// Cap line length at 1 MiB so a pathological single-line config can't exhaust memory.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kw, rest := splitKeyword(line)
		if strings.EqualFold(kw, "include") {
			incs = append(incs, splitArgs(rest)...)
		}
	}
	return incs
}

// splitKeyword splits an ssh_config line into its keyword and the remainder.
func splitKeyword(line string) (kw, rest string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimLeft(line[i:], " \t=")
}

// splitArgs splits an argument string on whitespace, honoring simple double quotes.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return args
}

// isForbidden reports whether a resolved real path is at or under any
// forbidden root.
func (s *ssh) isForbidden(real string) bool {
	for _, root := range s.forbidden {
		if pathutil.AtOrUnderClean(real, root) {
			return true
		}
	}
	return false
}
