// Package adminweb serves the root-only administrator surface behind Tailscale Serve.
package adminweb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/R055LE/secrets-broker/internal/boundedio"
	"github.com/R055LE/secrets-broker/internal/execx"
	"github.com/R055LE/secrets-broker/internal/securefile"
	"github.com/pelletier/go-toml/v2"
)

const (
	ConfigPath = "/etc/secrets-broker-admin/web.toml"
	SocketPath = "/run/secrets-broker-admin.sock"
	PolicyPath = "/etc/secrets-broker/policy.toml"
)

type Config struct {
	Host        string `toml:"host"`
	Login       string `toml:"login"`
	ApprovalURL string `toml:"approval_url"`
}

var hostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.ts\.net$`)

func ParseConfig(data []byte) (Config, error) {
	var cfg Config
	if len(data) > 4096 {
		return cfg, errors.New("admin web configuration is too large")
	}
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, errors.New("invalid admin web configuration")
	}
	if len(cfg.Host) > 253 || !hostPattern.MatchString(cfg.Host) {
		return Config{}, errors.New("host must be the exact HTTPS Tailscale hostname")
	}
	if len(cfg.Login) == 0 || len(cfg.Login) > 256 {
		return Config{}, errors.New("login must be the exact personal Tailscale login")
	}
	for _, char := range cfg.Login {
		if char < 33 || char > 126 || char == ',' {
			return Config{}, errors.New("login contains unsupported characters")
		}
	}
	if cfg.ApprovalURL != "" {
		link, err := url.Parse(cfg.ApprovalURL)
		if err != nil || link.Scheme != "http" || !hostPattern.MatchString(link.Hostname()) ||
			link.Port() != "7621" || link.User != nil || link.RawQuery != "" || link.Fragment != "" ||
			(link.Path != "" && link.Path != "/") {
			return Config{}, errors.New("approval_url must be the separate relay's private HTTP Tailscale URL on port 7621")
		}
	}
	return cfg, nil
}

func LoadConfig() (Config, error) {
	data, err := securefile.Read(ConfigPath, 4096, 0o077, false)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(data)
}

func CheckTailscale(ctx context.Context, cfg Config, runner execx.Runner) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		stdout, stderr := boundedio.NewBuffer(64<<10), boundedio.NewBuffer(4096)
		code, err := runner.RunPassthrough(ctx, "/usr/bin/tailscale", args,
			[]string{"PATH=/usr/bin:/bin", "LC_ALL=C"}, "/", nil, stdout, stderr)
		if err != nil || code != 0 || stdout.Exceeded() || stderr.Exceeded() || len(stderr.Bytes()) != 0 {
			return nil, errors.New("tailscale boundary check failed")
		}
		return stdout.Bytes(), nil
	}
	operator, err := run("get", "operator")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(operator)) != "" {
		return errors.New("tailscale operator must be empty")
	}
	data, err := run("serve", "status", "--json")
	if err != nil {
		return err
	}
	return validateServe(data, cfg.Host)
}

func validateServe(data []byte, host string) error {
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil || got == nil {
		return errors.New("invalid Serve configuration")
	}
	// Compare the complete shape so a new forwarding or public route fails closed.
	if len(got) == 0 {
		return nil
	}
	expected := fmt.Sprintf(`{"TCP":{"443":{"HTTPS":true}},"Web":{%q:{"Handlers":{"/":{"Proxy":%q}}}}}`, host+":443", "unix:"+SocketPath)
	var want map[string]any
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("serve configuration conflicts with the private admin socket")
	}
	return nil
}
