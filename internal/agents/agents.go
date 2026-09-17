// Package agents is the registry facade for corral's coding-agent adapters.
// The contract (Agent interface + neutral carrier types) lives in internal/agents/spec;
// each agent is its own package; this facade wires them together by registering each by
// Name. The seam types below are re-exported as aliases of the spec types.
package agents

import (
	"sort"

	"github.com/go-corral/corral/internal/agents/claude"
	"github.com/go-corral/corral/internal/agents/pi"
	"github.com/go-corral/corral/internal/agents/spec"
)

type (
	Agent        = spec.Agent
	AgentConfig  = spec.AgentConfig
	Launch       = spec.Launch
	BannerField  = spec.BannerField
	ConfigPath   = spec.ConfigPath
	Footprint    = spec.Footprint
	StatusInput  = spec.StatusInput
	SyncInput    = spec.SyncInput
	SyncReport   = spec.SyncReport
	SyncDiff     = spec.SyncDiff
	DoctorReport = spec.DoctorReport
	DoctorLine   = spec.DoctorLine
)

func BinDir(bin string) string { return spec.BinDir(bin) }

const Default = "claude"

var registry = buildRegistry(claude.New(), pi.New())

func buildRegistry(list ...Agent) map[string]Agent {
	m := make(map[string]Agent, len(list))
	for _, a := range list {
		m[a.Name()] = a
	}
	return m
}

func Lookup(name string) (Agent, bool) {
	a, ok := registry[name]
	return a, ok
}

func Known() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func AllReservedEnv() []string {
	seen := map[string]bool{}
	var names []string
	for _, a := range registry {
		for _, n := range a.ReservedEnv() {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names
}
