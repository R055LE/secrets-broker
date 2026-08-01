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

// Supported token_source.backend values.
//   - BackendSecretService: the freedesktop Secret Service API (via
//     `secret-tool`), for an interactive desktop session (KWallet or GNOME
//     Keyring). Needs no backend-specific config.
//   - BackendEnv: a single environment variable, for a headless deployment
//     where the token is injected at process start (systemd, container).
//   - BackendFile: a single file path, for the Docker-secrets/Kubernetes-
//     Secret-volume convention.
const (
	BackendSecretService = "secret-service"
	BackendEnv           = "env"
	BackendFile          = "file"
)

// Supported approval_source.backend values.
//   - ApprovalBackendKDialog: `kdialog --yesno` on a live desktop session.
//     The default when approval_source is omitted entirely, preserving
//     existing config files' behavior.
//   - ApprovalBackendTailscaleRelay: a remote decision via a
//     secrets-broker-relay running on a separate device — see
//     decisions/0008 and decisions/0009 for why it has to be a separate
//     device and how the control/decision port split works.
const (
	ApprovalBackendKDialog        = "kdialog"
	ApprovalBackendTailscaleRelay = "tailscale-relay"
)

const (
	defaultRelayPollIntervalSeconds = 2
	defaultRelayTimeoutSeconds      = 300
)

type Config struct {
	TokenSource    TokenSource    `toml:"token_source"`
	ApprovalSource ApprovalSource `toml:"approval_source"`
	Projects       []Project      `toml:"projects"`
}

type TokenSource struct {
	Backend string     `toml:"backend"`
	Env     EnvSource  `toml:"env"`
	File    FileSource `toml:"file"`
}

type EnvSource struct {
	Var string `toml:"var"`
}

type FileSource struct {
	Path string `toml:"path"`
}

type ApprovalSource struct {
	Backend        string               `toml:"backend"`
	TailscaleRelay TailscaleRelaySource `toml:"tailscale_relay"`
}

type TailscaleRelaySource struct {
	// ControlURL is the relay's control-port base URL, e.g.
	// "http://100.x.y.z:7620" — must be the relay's tailscale IP, not a
	// LAN or public address, or the whole point is lost.
	ControlURL          string `toml:"control_url"`
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`
	TimeoutSeconds      int    `toml:"timeout_seconds"`
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

	if c.ApprovalSource.Backend == "" {
		c.ApprovalSource.Backend = ApprovalBackendKDialog
	}
	if c.ApprovalSource.Backend == ApprovalBackendTailscaleRelay {
		if c.ApprovalSource.TailscaleRelay.PollIntervalSeconds == 0 {
			c.ApprovalSource.TailscaleRelay.PollIntervalSeconds = defaultRelayPollIntervalSeconds
		}
		if c.ApprovalSource.TailscaleRelay.TimeoutSeconds == 0 {
			c.ApprovalSource.TailscaleRelay.TimeoutSeconds = defaultRelayTimeoutSeconds
		}
	}
}

func (c *Config) validate() error {
	switch c.TokenSource.Backend {
	case BackendSecretService:
		// no backend-specific config required
	case BackendEnv:
		if c.TokenSource.Env.Var == "" {
			return errors.New(`token_source.env.var is required when backend is "env"`)
		}
	case BackendFile:
		if c.TokenSource.File.Path == "" {
			return errors.New(`token_source.file.path is required when backend is "file"`)
		}
	default:
		return fmt.Errorf("token_source.backend %q is not supported (must be one of %q, %q, %q)", c.TokenSource.Backend, BackendSecretService, BackendEnv, BackendFile)
	}

	switch c.ApprovalSource.Backend {
	case ApprovalBackendKDialog:
		// no backend-specific config required
	case ApprovalBackendTailscaleRelay:
		if c.ApprovalSource.TailscaleRelay.ControlURL == "" {
			return errors.New(`approval_source.tailscale_relay.control_url is required when backend is "tailscale-relay"`)
		}
	default:
		return fmt.Errorf("approval_source.backend %q is not supported (must be one of %q, %q)", c.ApprovalSource.Backend, ApprovalBackendKDialog, ApprovalBackendTailscaleRelay)
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
