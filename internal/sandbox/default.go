package sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

// SandboxEnvVar is set to "1" in every sandbox, so the SessionStart hook
// injects the sandbox note only when sandboxed.
const SandboxEnvVar = "CORRAL_SANDBOX"

// GlobalConfigEnvVar pins the launcher-resolved global config path for the
// in-sandbox hook, which drops $XDG_CONFIG_HOME and would otherwise re-resolve
// to a divergent path.
const GlobalConfigEnvVar = "CORRAL_GLOBAL_CONFIG"

// ProviderNotesEnvVar carries the active providers' secret-free, model-facing
// notes into the sandbox. Reserved so env.set cannot plant model-facing context.
const ProviderNotesEnvVar = "CORRAL_PROVIDER_NOTES"

// BackendNotesEnvVar is the backend dual of ProviderNotesEnvVar.
const BackendNotesEnvVar = "CORRAL_BACKEND_NOTES"

// AgentEnvVar pins the launched agent for the in-sandbox hook. Reserved so
// env.set cannot forge it.
const AgentEnvVar = "CORRAL_AGENT"

// AuditPathEnvVar pins the launcher-resolved audit-log path for the
// in-sandbox hook, which would otherwise re-resolve it from the private home.
const AuditPathEnvVar = "CORRAL_AUDIT_PATH"

// BinEnvVar pins the corral binary an agent's in-process policy extension
// re-invokes. Reserved so nothing can redirect enforcement.
const BinEnvVar = "CORRAL_BIN"

// PresenceAckEnvVar silences the sandbox-presence warning only. Deliberately
// not reserved — there is nothing to forge.
const PresenceAckEnvVar = "CORRAL_PRESENCE_ACK"

// DisableHooksEnvVar is the kill switch: set it outside the sandbox and corral
// enforces nothing. Honored only when CORRAL_SANDBOX is absent — inside corral's
// own sandbox it is ignored, so a bare-launch mechanism can never become an
// in-sandbox enforcement switch.
const DisableHooksEnvVar = "CORRAL_DISABLE_HOOKS"

// InsideCorral reports whether the process runs inside a corral sandbox.
// Deliberately spoofable: it backs only the presence warning and the
// SessionStart note.
func InsideCorral() bool { return os.Getenv(SandboxEnvVar) != "" }

// EnvEnabled reports whether an opt-in var is switched on: only "1"/"true"
// count, so CORRAL_DISABLE_HOOKS=0 stays enabled.
func EnvEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// HooksDisabled reports whether the kill switch is in effect: enabled and not
// inside corral's own sandbox.
func HooksDisabled() bool { return !InsideCorral() && EnvEnabled(DisableHooksEnvVar) }

// PresenceAcked reports whether the user has acknowledged running without corral run.
func PresenceAcked() bool { return EnvEnabled(PresenceAckEnvVar) }

// DefaultParams is the host-and-config-derived input to DefaultSpec.
type DefaultParams struct {
	Home        string
	SandboxHome string // $HOME the child sees; defaults to Home
	ProjectDir  string

	// AgentConfigDir is where the agent keeps account/auth and state. Empty
	// leaves the $AGENT_CONFIG_DIR token empty, skipping every baseline rule
	// that references it (the fail-safe), so no agent state is bound rather
	// than guessing one.
	AgentConfigDir string

	Net      NetPolicy
	Hostname string

	// AgentBinDir is the launched program's resolved dir, emitted as
	// $AGENT_BIN_DIR so macOS re-allows reads there for an agent under $HOME.
	AgentBinDir string

	// AgentEnv is extra environment the agent contributes, merged after
	// passthrough so it wins.
	AgentEnv map[string]string

	// TempEnvAliases are agent-specific temp-dir env names beyond POSIX
	// TMPDIR/TMP/TEMPDIR, repointed at the per-session temp dir by Seatbelt's
	// Prepare. Ignored on bwrap.
	TempEnvAliases []string

	// AgentRules are the agent's filesystem grants outside its config dir.
	AgentRules []Rule

	// BlockedPaths: always-blocked paths unioned with config block.directories,
	// already ~-expanded.
	BlockedPaths []string
	// BlockedFiles: config block.files, ~-expanded.
	BlockedFiles []string

	// EnvPassthrough is a strict allowlist: named vars are forwarded from
	// HostEnv, anything else dropped.
	EnvPassthrough []string
	HostEnv        map[string]string
}

// DefaultSpec builds the backend-agnostic launch intent. It does not compile
// the embedded baseline — each backend does that itself.
func DefaultSpec(p DefaultParams) SandboxSpec {
	if p.AgentConfigDir != "" {
		_ = os.MkdirAll(p.AgentConfigDir, 0o700)
	}

	var mounts []Mount
	if p.ProjectDir != "" {
		mounts = append(mounts, Mount{Src: p.ProjectDir})
	}

	env := baseEnv(p.Home, p.sandboxHome())
	env["PATH"] = prependBrewPath(env["PATH"], p.HostEnv["PATH"])
	for _, name := range p.EnvPassthrough {
		if v, ok := p.HostEnv[name]; ok && v != "" {
			env[name] = v
		}
	}
	for k, v := range p.AgentEnv {
		env[k] = v
	}
	env[SandboxEnvVar] = "1"

	net := p.Net
	if net == "" {
		net = NetOpen
	}
	hostname := p.Hostname
	if hostname == "" {
		hostname = "corral"
	}

	return SandboxSpec{
		Hostname:       hostname,
		WorkDir:        p.ProjectDir,
		Mounts:         mounts,
		Tmpfs:          []string{"/tmp"},
		BlockedPaths:   p.BlockedPaths,
		BlockedFiles:   p.BlockedFiles,
		SetEnv:         env,
		TempEnvAliases: p.TempEnvAliases,
		AgentRules:     p.AgentRules,
		Tokens:         p.baselineTokens(),
		Net:            net,
		DieWithParent:  true,
	}
}

func (p DefaultParams) baselineTokens() map[string]string {
	return map[string]string{
		"HOME":             p.Home,
		"AGENT_CONFIG_DIR": p.AgentConfigDir,
		"XDG_RUNTIME_DIR":  p.HostEnv["XDG_RUNTIME_DIR"],
		"AGENT_BIN_DIR":    p.AgentBinDir,
	}
}

func (p DefaultParams) sandboxHome() string {
	if p.SandboxHome != "" {
		return p.SandboxHome
	}
	return p.Home
}

// baseEnv is the always-set minimal environment. Only HOME and the PATH
// ~/.local/bin prefix follow sandboxHome; USER/LOGNAME derive from realHome.
func baseEnv(realHome, sandboxHome string) map[string]string {
	return map[string]string{
		"HOME":    sandboxHome,
		"PATH":    filepath.Join(sandboxHome, ".local", "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin",
		"USER":    filepath.Base(realHome),
		"LOGNAME": filepath.Base(realHome),
		"SHELL":   "/bin/sh",
		"LANG":    "C.UTF-8",
	}
}

// prependBrewPath prepends the Apple-Silicon Homebrew bin/sbin dirs to PATH,
// but only those already in the host PATH. No-op off Homebrew or on Linux.
func prependBrewPath(path, hostPath string) string {
	hostDirs := strings.Split(hostPath, ":")
	var dirs []string
	for _, d := range []string{"/opt/homebrew/bin", "/opt/homebrew/sbin"} {
		for _, e := range hostDirs {
			if e == d {
				dirs = append(dirs, d)
				break
			}
		}
	}
	if len(dirs) == 0 {
		return path
	}
	return strings.Join(dirs, ":") + ":" + path
}
