// This client is installed as a fake root tailscaled only in the isolated CI runner.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const alias = "web-ci-project"

var client = &http.Client{
	Timeout: 40 * time.Second,
	Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/run/secrets-broker-admin.sock")
	}},
}

func request(path string, form url.Values, login string) (string, int, error) {
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, "http://localhost"+path, body)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Tailscale-User-Login", login)
	req.Header.Set("X-Forwarded-Host", "broker.example.ts.net")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://broker.example.ts.net")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	return string(data), res.StatusCode, err
}

func expect(path string, form url.Values, text string) (string, error) {
	body, status, err := request(path, form, "operator@example.invalid")
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if status != http.StatusOK || !strings.Contains(body, text) {
		return "", fmt.Errorf("%s: status %d, expected result absent", path, status)
	}
	return body, nil
}

func token(body, action string) (string, error) {
	form := regexp.MustCompile(`(?s)<form method="post" action="` + regexp.QuoteMeta(action) + `">(.*?)</form>`).FindStringSubmatch(body)
	if len(form) != 2 {
		return "", fmt.Errorf("%s: form absent", action)
	}
	match := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(form[1])
	if len(match) != 2 {
		return "", fmt.Errorf("%s: token absent", action)
	}
	return match[1], nil
}

func post(body, action string, fields url.Values, text string) (string, error) {
	csrf, err := token(body, action)
	if err != nil {
		return "", err
	}
	fields.Set("csrf", csrf)
	return expect(action, fields, text)
}

func save(body string) (string, error) {
	return post(body, "/projects/commit", url.Values{"alias": {alias}, "confirm": {"yes"}}, "Policy saved.")
}

func run() error {
	for _, login := range []string{"", "forged@example.invalid"} {
		_, status, err := request("/", nil, login)
		if err != nil || status != http.StatusForbidden {
			return fmt.Errorf("identity denial failed: status %d, %v", status, err)
		}
	}
	body, err := expect("/", nil, "Local broker policy")
	if err != nil {
		return err
	}
	body, err = post(body, "/projects/discover", url.Values{}, "Example CI project")
	if err != nil {
		return err
	}
	fields := url.Values{"alias": {alias}, "project_id": {"00000000-0000-0000-0000-000000000000"}, "token_entry": {"web-ci-entry"}, "working_dir": {"/home/runner"}}
	body, err = post(body, "/projects/create", fields, "confirm mode with an empty allowlist")
	if err != nil {
		return err
	}
	body, err = post(body, "/projects/commit", url.Values{"alias": {alias}}, "Local project created in confirm mode with no allowed commands")
	if err != nil {
		return err
	}
	body, err = post(body, "/projects/path", url.Values{"alias": {alias}}, "Worker can enter</dt><dd>true")
	if err != nil {
		return err
	}
	if !strings.Contains(body, "Runner can enter</dt><dd>true") {
		return fmt.Errorf("runner path probe failed")
	}
	body, err = post(body, "/projects/access", url.Values{"alias": {alias}}, "The worker can access this Bitwarden project.")
	if err != nil {
		return err
	}
	body, err = post(body, "/projects/add", url.Values{"alias": {alias}, "argv": {"/usr/bin/true", "two words", ""}}, "Review add")
	if err != nil {
		return err
	}
	body, err = save(body)
	if err != nil {
		return err
	}
	if !strings.Contains(body, "<li><code>two words</code>") || !strings.Contains(body, "empty argument") {
		return fmt.Errorf("exact arguments changed")
	}
	body, err = post(body, "/projects/mode", url.Values{"alias": {alias}, "mode": {"automatic"}}, "Review mode")
	if err != nil {
		return err
	}
	body, err = save(body)
	if err != nil {
		return err
	}
	if !strings.Contains(body, "automatic: allowlisted commands run without confirmation") {
		return fmt.Errorf("approval mode not saved")
	}
	fields.Set("token_entry", "web-ci-updated")
	body, err = post(body, "/projects/metadata", fields, "Review metadata")
	if err != nil {
		return err
	}
	body, err = save(body)
	if err != nil {
		return err
	}
	if !strings.Contains(body, "<code>web-ci-updated</code>") {
		return fmt.Errorf("metadata not saved")
	}
	body, err = post(body, "/projects/remove", url.Values{"alias": {alias}, "entry": {"0"}}, "Review remove")
	if err != nil {
		return err
	}
	body, err = save(body)
	if err != nil {
		return err
	}
	if !strings.Contains(body, "No commands are allowed.") {
		return fmt.Errorf("argument removal failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Packaged administrator service acceptance passed.")
}
