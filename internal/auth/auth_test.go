package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey testkey123"},
			},
			expectedKey:   "testkey123",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKeytestkey123"},
			},
			expectedKey:   "1",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Wrong Authorization Type",
			headers: http.Header{
				"Authorization": []string{"Bearer testkey123"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if err != nil && tt.expectedError != nil {
				if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else if err != tt.expectedError {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
