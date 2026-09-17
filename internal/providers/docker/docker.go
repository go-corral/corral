// Package docker implements the docker socket-broker provider.
package docker

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

// DefaultDockerSocket is the daemon socket bound when the docker provider is on.
// Only this default location is handled — rootless docker is not.
const DefaultDockerSocket = "/var/run/docker.sock"

type docker struct {
	socketPath string
	dockerCfg  string
}

// New builds the docker provider for the given home directory.
func New(home string) spec.Provider {
	cfg := ""
	if home != "" {
		cfg = filepath.Join(home, ".docker")
	}
	return &docker{socketPath: DefaultDockerSocket, dockerCfg: cfg}
}

func (d *docker) Name() string { return "docker" }

func (d *docker) Available(ctx context.Context) bool {
	return spec.IsSocket(d.socketPath)
}

// Mint reads host state only and mutates nothing, so it is side-effect-free.
func (d *docker) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	if !spec.IsSocket(d.socketPath) {
		return nil, fmt.Errorf("docker socket %q not found", d.socketPath)
	}
	// Bind the socket by its canonical path (resolve symlinks) so the bind source is
	// the real inode. Dst stays the conventional location so in-sandbox docker clients
	// find the socket where they expect.
	socketSrc := d.socketPath
	if real, err := filepath.EvalSymlinks(d.socketPath); err == nil {
		socketSrc = real
	}
	c := &spec.Contribution{
		Mounts:     []sandbox.Mount{{Src: socketSrc, Dst: d.socketPath}},
		AgentNotes: []string{"docker is available and talks to the HOST daemon: containers, images, and volume mounts live on the host, outside this sandbox."},
	}
	status := "brokering the host docker daemon socket (rw)"
	if d.dockerCfg != "" {
		// Best-effort (Optional): a user may have no ~/.docker; read-only so the
		// sandboxed claude can use existing logins but not mutate host creds.
		c.Mounts = append(c.Mounts, sandbox.Mount{
			Src: d.dockerCfg, Dst: d.dockerCfg, ReadOnly: true, Optional: true,
		})
		status += " + " + d.dockerCfg + " (read-only)"
	}
	c.Status = []string{status}
	return c, nil
}
