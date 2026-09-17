package sandbox

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
)

// Kind identifies a sandbox backend, selected once per command.
type Kind string

const (
	KindBwrap    Kind = "bwrap"
	KindSeatbelt Kind = "seatbelt"
)

// DefaultKind returns the backend for the current OS, or an "unsupported OS"
// error rather than guessing. The single place runtime.GOOS maps to a backend.
func DefaultKind() (Kind, error) {
	return defaultKindFor(runtime.GOOS)
}

func defaultKindFor(goos string) (Kind, error) {
	switch goos {
	case "linux":
		return KindBwrap, nil
	case "darwin":
		return KindSeatbelt, nil
	default:
		return "", fmt.Errorf("unsupported OS %q: corral supports linux (bwrap) and macOS (seatbelt)", goos)
	}
}

// ParseKind validates an explicit backend name from the -backend flag. Unlike
// DefaultKind it does not consult runtime.GOOS, so an override is honored on
// any OS; a real launch still gates on the backend's Available().
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case KindBwrap, KindSeatbelt:
		return Kind(s), nil
	default:
		return "", fmt.Errorf("unknown backend %q: want %q or %q", s, KindBwrap, KindSeatbelt)
	}
}

// ResolveKind picks the backend: the explicit override when non-empty, else the
// OS default. The concrete backend is constructed by the cli factory.
func ResolveKind(override string) (Kind, error) {
	if override != "" {
		return ParseKind(override)
	}
	return DefaultKind()
}

// ReportTool writes a "  name: <path>" diagnostic line for a sandbox helper
// to w, resolving it on PATH. Shared by the backend packages' Doctor methods.
func ReportTool(w io.Writer, name string) {
	if p, err := exec.LookPath(name); err == nil {
		fmt.Fprintf(w, "  %s: %s\n", name, p)
	} else {
		fmt.Fprintf(w, "  %s: NOT FOUND\n", name)
	}
}
