package adminweb

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/R055LE/secrets-broker/internal/execx"
)

var testConfig = Config{Host: "broker.example.ts.net", Login: "operator@example.invalid"}

func TestConfigRejectsOverridesAndInvalidIdentity(t *testing.T) {
	valid := "host = 'broker.example.ts.net'\nlogin = 'operator@example.invalid'\n"
	if cfg, err := ParseConfig([]byte(valid)); err != nil || cfg != testConfig {
		t.Fatalf("ParseConfig = %#v, %v", cfg, err)
	}
	for _, input := range []string{
		valid + "policy = '/tmp/policy'", strings.ReplaceAll(valid, "broker.example.ts.net", "localhost"),
		strings.ReplaceAll(valid, "broker.example.ts.net", "broker.example.ts.net:443"),
		strings.ReplaceAll(valid, "operator@example.invalid", ""),
		strings.ReplaceAll(valid, "operator@example.invalid", "one,two"),
		strings.ReplaceAll(valid, "operator@example.invalid", "one two"), strings.Repeat("x", 4097),
	} {
		if _, err := ParseConfig([]byte(input)); err == nil {
			t.Fatalf("accepted invalid configuration %q", input)
		}
	}
}

func TestServeConfigurationAllowsOnlyPrivateFixedProxy(t *testing.T) {
	valid := `{"TCP":{"443":{"HTTPS":true}},"Web":{"broker.example.ts.net:443":{"Handlers":{"/":{"Proxy":"unix:/run/secrets-broker-admin.sock"}}}}}`
	for _, input := range []string{"{}", valid} {
		if err := validateServe([]byte(input), testConfig.Host); err != nil {
			t.Fatalf("valid configuration: %v", err)
		}
	}
	for _, input := range []string{
		"null", "{}{}", `{"AllowFunnel":{"broker.example.ts.net:443":true}}`,
		strings.ReplaceAll(valid, "unix:/run/secrets-broker-admin.sock", "http://localhost:8000"),
		strings.ReplaceAll(valid, "broker.example.ts.net", "other.example.ts.net"),
		strings.ReplaceAll(valid, `"HTTPS":true`, `"HTTPS":false`),
		strings.TrimSuffix(valid, "}") + `,"AllowFunnel":{"broker.example.ts.net:443":true}}`,
	} {
		if err := validateServe([]byte(input), testConfig.Host); err == nil {
			t.Fatalf("accepted unsafe Serve configuration %s", input)
		}
	}
}

func TestApprovalLinkIsPrivateAndSeparate(t *testing.T) {
	base := "host = 'broker.example.ts.net'\nlogin = 'operator@example.invalid'\napproval_url = '"
	for _, link := range []string{"http://relay.example.ts.net:7621", "http://relay.example.ts.net:7621/"} {
		if cfg, err := ParseConfig([]byte(base + link + "'")); err != nil || cfg.ApprovalURL != link {
			t.Fatalf("valid relay link: %#v %v", cfg, err)
		}
	}
	for _, link := range []string{"https://relay.example.ts.net:7621", "http://localhost:7621", "http://relay.example.ts.net:7620", "http://user@relay.example.ts.net:7621", "http://relay.example.ts.net:7621/decide", "http://relay.example.ts.net:7621/?id=x", "http://relay.example.ts.net:7621/#x"} {
		if _, err := ParseConfig([]byte(base + link + "'")); err == nil {
			t.Fatalf("accepted relay link %q", link)
		}
	}
}

type tailscaleRunner struct {
	execx.FakeRunner
	operator, status string
}

func (f *tailscaleRunner) RunPassthrough(ctx context.Context, name string, args, env []string, dir string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	f.Calls = append(f.Calls, execx.Call{Name: name, Args: args, Env: env, Dir: dir})
	if _, ok := ctx.Deadline(); !ok {
		panic("Tailscale check has no timeout")
	}
	if args[0] == "get" {
		_, _ = io.WriteString(stdout, f.operator)
	} else {
		_, _ = io.WriteString(stdout, f.status)
	}
	return 0, nil
}

func TestTailscaleCheckUsesFixedCommandsAndRejectsOperator(t *testing.T) {
	fake := &tailscaleRunner{status: "{}"}
	if err := CheckTailscale(context.Background(), testConfig, fake); err != nil {
		t.Fatal(err)
	}
	if len(fake.Calls) != 2 || fake.Calls[0].Name != "/usr/bin/tailscale" ||
		!reflect.DeepEqual(fake.Calls[0].Args, []string{"get", "operator"}) ||
		!reflect.DeepEqual(fake.Calls[1].Args, []string{"serve", "status", "--json"}) {
		t.Fatalf("unexpected commands: %#v", fake.Calls)
	}
	fake.operator = "agent\n"
	if err := CheckTailscale(context.Background(), testConfig, fake); err == nil {
		t.Fatal("accepted Tailscale operator")
	}
	failed := &execx.FakeRunner{PassthroughExitCode: 1, PassthroughStderr: "sentinel-private-error"}
	if err := CheckTailscale(context.Background(), testConfig, failed); err == nil || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("failure not sanitized: %v", err)
	}
}
