package worker

import (
	"strings"
	"testing"
)

func TestDecodeRequestRejectsUnknownFields(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(`{"project":"p","working_dir":"/tmp","argv":["true"],"config":"/tmp/evil"}`))
	if err == nil {
		t.Fatal("expected caller-supplied config field to be rejected")
	}
}

func TestDecodeRequestRejectsOversizedBody(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(strings.Repeat("x", maxRequestBytes+1)))
	if err == nil {
		t.Fatal("expected oversized request to be rejected")
	}
}
