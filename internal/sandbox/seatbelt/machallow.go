package seatbelt

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed mach-allow.json
var machAllowJSON []byte

// machService is one entry in the strict mach-lookup allowlist. Kind selects
// the SBPL filter: "" or "name" → (global-name), "prefix" → (global-name-prefix),
// "regex" → (global-name-regex).
type machService struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

type machAllowFile struct {
	Schema   string          `json:"$schema"`
	Comment  json.RawMessage `json:"_comment"`
	Services []machService   `json:"services"`
}

var machAllowlist = mustLoadMachAllow()

func mustLoadMachAllow() []machService {
	s, err := loadMachAllow(machAllowJSON)
	if err != nil {
		panic("seatbelt: embedded mach allowlist invalid: " + err.Error())
	}
	return s
}

// loadMachAllow strict-decodes the allowlist JSON and validates each entry.
func loadMachAllow(data []byte) ([]machService, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f machAllowFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(f.Services) == 0 {
		return nil, fmt.Errorf("no services")
	}
	seen := make(map[string]bool, len(f.Services))
	for i, s := range f.Services {
		if s.Name == "" || s.Description == "" {
			return nil, fmt.Errorf("service %d: name and description are required", i)
		}
		switch s.Kind {
		case "", "name", "prefix", "regex":
		default:
			return nil, fmt.Errorf("service %d (%q): kind %q is not name|prefix|regex", i, s.Name, s.Kind)
		}
		if strings.ContainsAny(s.Name, "\t\n\" ") {
			return nil, fmt.Errorf("service %d: name %q contains whitespace or a quote", i, s.Name)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("service %d: duplicate name %q", i, s.Name)
		}
		seen[s.Name] = true
	}
	return f.Services, nil
}

func (s machService) sbpl() string {
	switch s.Kind {
	case "prefix":
		return fmt.Sprintf("(global-name-prefix %q)", s.Name)
	case "regex":
		return fmt.Sprintf(`(global-name-regex #"%s")`, s.Name)
	default:
		return fmt.Sprintf("(global-name %q)", s.Name)
	}
}

// machAllowEntry compiles a user mach.allow string into a machService: a
// trailing "*" becomes a global-name-prefix, otherwise an exact global-name.
func machAllowEntry(raw string) machService {
	if strings.HasSuffix(raw, "*") {
		return machService{Name: strings.TrimSuffix(raw, "*"), Kind: "prefix"}
	}
	return machService{Name: raw, Kind: "name"}
}
