package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// RelayStatus mirrors internal/relay.Status by value, not by import —
// this package only needs the string values a relay's control port
// returns, not the relay's internal domain model. Keeps this a thin HTTP
// client, not a second copy of relay's types.
type RelayStatus string

const (
	RelayStatusPending  RelayStatus = "pending"
	RelayStatusApproved RelayStatus = "approved"
	RelayStatusDenied   RelayStatus = "denied"
	RelayStatusExpired  RelayStatus = "expired"
)

// RelayClient talks to a secrets-broker-relay's control port. A separate
// interface from Approver itself so TailscaleApprover's polling/timeout
// logic is unit-testable against a fake, without a real HTTP server —
// same seam pattern as execx.Runner elsewhere in this project.
type RelayClient interface {
	Register(ctx context.Context, id, prompt string) error
	Poll(ctx context.Context, id string) (RelayStatus, error)
}

// HTTPRelayClient is the real RelayClient, talking to a relay's control
// port over plain HTTP. The tailnet is what makes this safe to leave
// unencrypted and unauthenticated at the transport level — not TLS, not
// a bearer token here. See decisions/0008.
type HTTPRelayClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewHTTPRelayClient(baseURL string, httpClient *http.Client) *HTTPRelayClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &HTTPRelayClient{baseURL: baseURL, httpClient: httpClient}
}

func (c *HTTPRelayClient) Register(ctx context.Context, id, prompt string) error {
	body, err := json.Marshal(map[string]string{"prompt": prompt})
	if err != nil {
		return fmt.Errorf("encoding register request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/requests/"+id, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("registering with relay: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("relay returned %d registering request", resp.StatusCode)
	}
	return nil
}

func (c *HTTPRelayClient) Poll(ctx context.Context, id string) (RelayStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/requests/"+id, nil)
	if err != nil {
		return "", fmt.Errorf("building poll request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("polling relay: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("relay returned %d polling request", resp.StatusCode)
	}

	var view struct {
		Status RelayStatus `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&view); err != nil {
		return "", fmt.Errorf("decoding poll response: %w", err)
	}
	return view.Status, nil
}
