// Package config loads and validates policy.toml — the per-project
// allowlist, approval mode, and token-source configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Approval modes. Empty in TOML defaults to ApprovalNever — fail-closed: an
// operator who forgets to set this gets "nothing outside the allowlist ever
// runs," not an unattended prompt that might hang on a headless machine.
const (
	ApprovalAlways = "always"
	ApprovalPrompt = "prompt"
	ApprovalNever  = "never"
)

// BackendSecretService is the only token_source.backend value v1 supports —
// the freedesktop Secret Service API (via `secret-tool`), which KWallet
// implements on this machine but which GNOME Keyring implements too. A
// container/headless backend is a Phase 2 addition to this constant list,
// not a schema change.
const BackendSecretService = "secret-service"

type Config struct {
	TokenSource TokenSource `toml:"token_source"`
	Projects    []Project   `toml:"projects"`
}

type TokenSource struct {
	Backend string `toml:"backend"`
}

type Project struct {
	Alias        string       `toml:"alias"`
	BWSProjectID string       `toml:"bws_project_id"`
	TokenEntry   string       `toml:"token_entry"`
	Approval     string       `toml:"approval"`
	Allow        []AllowEntry `toml:"allow"`
}

type AllowEntry struct {
	Argv []string `toml:"argv"`
}

// AllowArgv returns the project's allowlist as a plain [][]string, the
// shape internal/policy.Match expects — keeps policy.go free of a
// dependency on this package's TOML-shaped types.
func (p Project) AllowArgv() [][]string {
	out := make([][]string, len(p.Allow))
	for i, e := range p.Allow {
		out[i] = e.Argv
	}
	return out
}

// Load reads and validates policy.toml at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	for i := range c.Projects {
		if c.Projects[i].Approval == "" {
			c.Projects[i].Approval = ApprovalNever
		}
	}
}

func (c *Config) validate() error {
	if c.TokenSource.Backend != BackendSecretService {
		return fmt.Errorf("token_source.backend %q is not supported (only %q in this version)", c.TokenSource.Backend, BackendSecretService)
	}

	if len(c.Projects) == 0 {
		return errors.New("no projects defined")
	}

	seen := make(map[string]bool, len(c.Projects))
	for _, p := range c.Projects {
		if p.Alias == "" {
			return errors.New("a project is missing alias")
		}
		if seen[p.Alias] {
			return fmt.Errorf("duplicate project alias %q", p.Alias)
		}
		seen[p.Alias] = true

		if p.BWSProjectID == "" {
			return fmt.Errorf("project %q: bws_project_id is required", p.Alias)
		}
		if p.TokenEntry == "" {
			return fmt.Errorf("project %q: token_entry is required", p.Alias)
		}
		switch p.Approval {
		case ApprovalAlways, ApprovalPrompt, ApprovalNever:
		default:
			return fmt.Errorf("project %q: approval %q must be one of %q, %q, %q", p.Alias, p.Approval, ApprovalAlways, ApprovalPrompt, ApprovalNever)
		}
		for _, entry := range p.Allow {
			if len(entry.Argv) == 0 {
				return fmt.Errorf("project %q: an allow entry has an empty argv", p.Alias)
			}
		}
	}

	return nil
}

// Project looks up a project by alias.
func (c *Config) Project(alias string) (Project, bool) {
	for _, p := range c.Projects {
		if p.Alias == alias {
			return p, true
		}
	}
	return Project{}, false
}

// DefaultPath returns the default policy.toml location, honoring
// XDG_CONFIG_HOME.
func DefaultPath() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "secrets-broker", "policy.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".config", "secrets-broker", "policy.toml"), nil
}

// DefaultAuditLogPath returns the default audit.jsonl location, honoring
// XDG_STATE_HOME. It's independently resolvable from DefaultPath so a
// broken/missing policy.toml still produces an audit record — see
// internal/broker.
func DefaultAuditLogPath() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "secrets-broker", "audit.jsonl"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "secrets-broker", "audit.jsonl"), nil
}
