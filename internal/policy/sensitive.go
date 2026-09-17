package policy

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// This file is the single classifier for "is this path a secret/credential artifact?", shared by
// the Bash gate and the path pattern gate. Keeping one classifier means the two enforcement layers
// can never drift. The always-blocked paths are enforced separately by BlockedPathRule; this adds
// the file-type and non-home cases.

// secretFileExts are lowercased extensions denoting key/secret material. Public-certificate
// extensions (.crt/.cer/.der) are deliberately excluded: commonly committed, not credential
// material. The content secret scanner still catches an actual private key regardless of extension.
var secretFileExts = map[string]string{
	".pem": "a key/certificate", ".key": "a key/certificate", ".p12": "a key/certificate",
	".pfx": "a key/certificate",
	".gpg": "a PGP key", ".pgp": "a PGP key", ".asc": "a PGP key",
	".kdbx": "a password database", ".kdb": "a password database", ".1pif": "a password database",
	".agilekeychain": "a password database", ".opvault": "a password database",
	".keychain": "a macOS keychain", ".keychain-db": "a macOS keychain",
	".env": "an environment/secrets",
}

// secretDirComponents map a path segment that is a known secrets directory to a description. These
// are the classifier's copy of config.AlwaysBlockedPaths' names; a drift-guard test holds the two
// sets equal.
var secretDirComponents = map[string]string{
	".ssh":   "an SSH key directory",
	".gnupg": "a GPG key directory",
	".aws":   "an AWS credentials directory",
	".kube":  "a Kubernetes credentials directory",
	".azure": "an Azure credentials directory",
}

// secretDirPairs anchor a segment that is a secrets directory only under a specific parent.
// "gcloud" alone would false-positive a vendored gcloud/ directory; the credential store is
// specifically .config/gcloud.
var secretDirPairs = map[[2]string]string{
	{".config", "gcloud"}: "a Google Cloud credentials directory",
}

var secretNameRe = regexp.MustCompile(`(?i)^(secret|secrets|credential|credentials|password|passwords|passwd|token|tokens|api[_-]?key|apikey)s?\.(json|ya?ml|toml|ini|txt|conf|cfg|env)$`)

var etcCredFiles = map[string]bool{
	"/etc/shadow": true, "/etc/gshadow": true, "/etc/passwd": true,
	"/etc/group": true, "/etc/sudoers": true,
}

func classifySensitive(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	p = logicalSysPath(p)
	base := filepath.Base(p)
	lowerBase := strings.ToLower(base)

	switch {
	case lowerBase == ".env" || lowerBase == ".envrc":
		return "an environment/secrets file (.env)", true
	case strings.HasPrefix(lowerBase, ".env."):
		// .env.example / .sample / .template / .dist are committed templates — allow them;
		// everything else (.env.local, .env.production) is a secret.
		if !hasAnySuffix(lowerBase, ".example", ".sample", ".template", ".dist") {
			return "an environment/secrets file (.env)", true
		}
	case lowerBase == ".netrc":
		return "a .netrc credentials file", true
	case lowerBase == ".git-credentials":
		return "a git credential-store file", true
	}

	// git's credential store at its XDG location is a bare "credentials" file (no extension),
	// which secretNameRe misses — and its parent ~/.config/git is baseline-readable.
	if strings.HasSuffix(strings.ToLower(p), "/.config/git/credentials") {
		return "a git credential-store file", true
	}

	if ext := strings.ToLower(filepath.Ext(base)); ext != "" {
		if reason, ok := secretFileExts[ext]; ok {
			return reason + " file (" + ext + ")", true
		}
	}

	if secretNameRe.MatchString(base) {
		return "a credential-named file", true
	}

	if etcCredFiles[p] {
		return "a system credential file", true
	}

	segs := strings.Split(p, "/")
	for i, seg := range segs {
		lower := strings.ToLower(seg)
		if reason, ok := secretDirComponents[lower]; ok {
			return reason, true
		}
		if i > 0 {
			if reason, ok := secretDirPairs[[2]string{strings.ToLower(segs[i-1]), lower}]; ok {
				return reason, true
			}
		}
	}
	return "", false
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// AgentFootprint is policy's leaf-package mirror of an agent's static enforcement footprint
// (spec.Footprint): the config-dir marker plus the files/subdirs whose write/delete the hook
// gates. policy imports no agent — the composition root (cli) maps agents.Footprint onto this,
// exactly as it maps agents.ConfigPath onto sandbox.Rule — so the policy engine stays agent-neutral.
type AgentFootprint struct {
	Dir            string
	DirReason      string
	ProtectedFiles map[string]string
	ProtectedDirs  map[string]string
}

// selfProtect carries the inputs selfConfigMatch needs: the active agent's canonical effective
// config dir and static footprint, every registered agent's footprint (for defense-in-depth), and
// canonical absolute paths of non-corral hook scripts. hookPaths is nil when config is
// missing/unreadable/empty, which degrades to the static footprint rules.
type selfProtect struct {
	configDir     string
	footprint     AgentFootprint
	allFootprints []AgentFootprint
	hookPaths     []string
	// extraPaths are additional canonical runtime artifacts corral guards from write/delete
	// (audit log + backups, repo-level ignore files), each mapped to a reason. Matched by exact
	// canonical-path equality; nil when none.
	extraPaths map[string]string
	// auditLogBase is the canonical audit-log path. Rotation backups carry timestamped names that
	// can't be enumerated ahead of time, so the log and every rotation sibling is guarded by prefix.
	// Empty when unknown.
	auditLogBase string
}

// selfConfigMatch reports whether path is configuration corral protects from write/delete: the
// active agent's config hosting corral's enforcement, or corral's own launcher config. The whys
// are cross-session escalation: the project dir is mounted rw, so a sandboxed (possibly
// prompt-injected) agent could otherwise drop a .corral.yml that grants itself host access on the
// next launch, or plant a settings file/extension that disables the policy hook, or hand-edit
// .mcp.json to auto-register a server the next session trusts. The user-scope registry
// ~/.claude.json is deliberately not gated: it doubles as session/project state that must stay
// writable.
func selfConfigMatch(path string, sp selfProtect) (string, bool) {
	configDir := sp.configDir
	fp := sp.footprint
	if configDir != "" {
		if path == configDir {
			return fp.DirReason, true
		}
		for name, reason := range fp.ProtectedFiles {
			if path == filepath.Join(configDir, name) {
				return reason, true
			}
		}
		for sub, reason := range fp.ProtectedDirs {
			abs := filepath.Join(configDir, sub)
			// Match at/under the subtree (inclusive) and any intermediate parent between configDir
			// and the subtree: deleting or renaming the parent takes the subtree with it. The parent
			// direction is bounded to paths under configDir, so an ancestor outside it ($HOME, /)
			// never matches here.
			if Within(path, abs) || (Within(abs, path) && Within(path, configDir)) {
				return reason, true
			}
		}
	}
	if slices.Contains(sp.hookPaths, path) {
		return "a registered Claude Code hook script", true
	}
	if reason, ok := sp.extraPaths[path]; ok {
		return reason, true
	}
	if sp.auditLogBase != "" && (path == sp.auditLogBase || strings.HasPrefix(path, sp.auditLogBase+".")) {
		return "corral's audit log", true
	}
	// Defense-in-depth: for any registered agent's config-dir segment (allFootprints), match the
	// remainder against that agent's protected files/subtrees. Fires regardless of the active
	// agent, user, or relocation — one agent's session must not sabotage another's enforcement.
	if reason, ok := matchAgentFootprint(strings.Split(path, "/"), sp.allFootprints); ok {
		return reason, true
	}
	// corral's own launcher config. Sentinel project basenames match anywhere; the global config
	// is matched by its `…/corral/config.yml` shape. Both .yml and .yaml are covered defensively.
	switch base := filepath.Base(path); base {
	case ".corral.yml", ".corral.yaml", ".corral.local.yml", ".corral.local.yaml":
		return "corral's launcher config", true
	case ".mcp.json":
		return "the project MCP server registry (.mcp.json)", true
	case "config.yml", "config.yaml":
		if filepath.Base(filepath.Dir(path)) == "corral" {
			return "corral's launcher config", true
		}
	}
	return "", false
}

// matchAgentFootprint walks path's segments and, at any segment equal to a footprint's Dir marker,
// matches the remainder after it against that agent's protected files (exact next segment) and
// protected subtrees (segment prefix in either direction, so a multi-segment key like
// "agent/extensions" gates both its contents and its intermediate parents), plus the bare-dir
// case.
func matchAgentFootprint(segs []string, footprints []AgentFootprint) (string, bool) {
	for i, s := range segs {
		for _, fp := range footprints {
			if fp.Dir == "" || s != fp.Dir {
				continue
			}
			if i == len(segs)-1 {
				return fp.DirReason, true
			}
			rem := segs[i+1:]
			if reason, ok := fp.ProtectedFiles[rem[0]]; ok {
				return reason, true
			}
			for sub, reason := range fp.ProtectedDirs {
				dsegs := strings.Split(sub, "/")
				if segsHavePrefix(rem, dsegs) || segsHavePrefix(dsegs, rem) {
					return reason, true
				}
			}
		}
	}
	return "", false
}

func segsHavePrefix(segs, prefix []string) bool {
	return len(segs) >= len(prefix) && slices.Equal(segs[:len(prefix)], prefix)
}
