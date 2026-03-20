package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_EmptyHeader(t *testing.T) {
	headers := http.Header{} // no Authorization header set

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected an error for missing Authorization header, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader1(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer abcdef") // Example of a malformed
	// or headers.Set("Authorization", "ApiKey") // missing token

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected an error for malformed Authorization header, got nil")
	}
}

func TestGetAPIKey_MalformedHeader2(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey") // missing token

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected an error for malformed Authorization header, got nil")
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("unexpected error for valid header: %v", err)
	}
	if key != "my-secret-key" {
		t.Fatalf("expected key 'my-secret-key', got '%s'", key)
	}
}
