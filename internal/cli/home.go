package cli

import (
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
)

// baselineArch maps a backend Kind to the baseline rules' arch vocabulary ("linux"/"macos"),
// which differs from runtime.GOOS ("linux"/"darwin").
func baselineArch(kind sandbox.Kind) string {
	if kind == sandbox.KindBwrap {
		return "linux"
	}
	return "macos"
}

// hookGuardDir returns the agent config dir whose private-home shadow drops corral's
// enforcement, "" when none can.
func hookGuardDir(cfg *config.Config, realHome string, host map[string]string) string {
	if len(cfg.AgentLaunch().ExtensionAsset) > 0 {
		return ""
	}
	dir := cfg.AgentConfigDir(realHome, host)
	if dir != cfg.AgentConfigDir(realHome, nil) {
		return ""
	}
	return dir
}
