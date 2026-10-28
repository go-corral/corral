// Package spec is the agent contract: the Agent interface plus agent-neutral data types.
// It imports only the leaf package health, so implementations and the registry can depend on
// it without an import cycle.
package spec

import (
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/health"
)

// ConfigPath is a filesystem path the agent needs exposed outside its ConfigDir, folded into
// the sandbox baseline.
type ConfigPath struct {
	Path        string
	Description string
	Writeable   bool
	Archs       []string
	// Recursive controls macOS subtree-vs-node (nil = backend default, the subtree); false
	// restricts to the single node. Informational on Linux.
	Recursive *bool
	// Regex marks Path as a macOS SBPL regex pattern (the bwrap backend skips these).
	Regex    bool
	Optional bool
}

type BannerField struct {
	Label string
	Value string
}

// Args is the `args` setting every agent config embeds inline.
type Args struct {
	Args []string `yaml:"args"`
}

func (a Args) LaunchArgs() []string { return a.Args }

// ArgsFields is the validation row for configured args, empty when none are set.
func (a Args) ArgsFields() []BannerField {
	if len(a.Args) == 0 {
		return nil
	}
	return []BannerField{{Label: "Args", Value: strings.Join(a.Args, " ")}}
}

type AgentConfig interface {
	SandboxEnv() map[string]string
	ValidationFields() []BannerField
	// LaunchArgs are passed to the agent before the `corral run -- ...` arguments.
	LaunchArgs() []string
}

type Launch struct {
	// TempEnvAliases are agent-specific temp-dir env var names beyond POSIX TMPDIR/TMP/TEMPDIR
	// that a temp-isolating backend repoints at the session temp dir. Honored on Seatbelt only.
	TempEnvAliases []string

	// ExtensionAsset, when non-empty, is an embedded policy extension the launcher materializes,
	// binds read-only, and activates via ExtensionFlag + the bound path on the agent's argv.
	ExtensionAsset []byte
	ExtensionName  string
	ExtensionFlag  string
	// ExtensionEnv, when set, activates the materialized extension through the environment
	// instead of ExtensionFlag. It receives the bound extension path.
	ExtensionEnv func(path string) map[string]string

	// Args, when set, rewrites the agent's arguments (everything after the binary) or rejects
	// them before launch.
	Args func(args []string) ([]string, error)
}

// Footprint is an agent's static enforcement footprint: the config-dir marker plus the files
// and subdirs whose write/delete the fail-closed hook self-protects.
type Footprint struct {
	Dir            string
	DirReason      string
	ProtectedFiles map[string]string
	ProtectedDirs  map[string]string
}

type StatusInput struct {
	Home    string
	Host    map[string]string
	Self    string
	WorkDir string
}

type SyncInput struct {
	Home         string
	Host         map[string]string
	DryRun       bool
	Remove       bool
	BinaryPath   string
	SettingsPath string
}

type SyncReport struct {
	Messages []string
	Diff     *SyncDiff
	Changed  bool
}

type SyncDiff struct {
	Before, After      []byte
	FromLabel, ToLabel string
}

type Agent interface {
	Name() string
	Binaries() []string
	ConfigDir(home string, host map[string]string) string
	Launch() Launch
	ConfigPaths() []ConfigPath
	ReservedEnv() []string
	Doctor(StatusInput) []health.Check
	Sync(SyncInput) (SyncReport, error)
	LaunchWarnings(StatusInput) []health.Check
	ProtectedPaths(configDir string) []string
	Footprint() Footprint
}

// BinDir resolves the directory of the resolved agent binary, canonicalizing symlinks (npm
// shims, version managers) so the path matches what Seatbelt tests against.
func BinDir(bin string) string {
	if bin == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	dir := filepath.Dir(bin)
	if !filepath.IsAbs(dir) {
		return ""
	}
	return dir
}
