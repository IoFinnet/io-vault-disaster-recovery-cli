// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// dummyHandler returns a simple 200 OK handler for testing middleware.
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t,
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
		rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "camera=(), microphone=(), geolocation=()", rec.Header().Get("Permissions-Policy"))
}

func TestValidateOrigin_AllowedOrigins(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		origin string
	}{
		{"POST with localhost origin", http.MethodPost, "/api/recover", "http://localhost:8080"},
		{"POST with 127.0.0.1 origin", http.MethodPost, "/api/recover", "http://127.0.0.1:8080"},
		{"POST with no origin header", http.MethodPost, "/api/recover", ""},
		{"POST list-vaults with localhost", http.MethodPost, "/api/list-vaults", "http://localhost:8080"},
		{"GET with no origin", http.MethodGet, "/", ""},
		{"GET with malicious origin (allowed for GET)", http.MethodGet, "/static/styles.css", "http://evil.com"},
	}

	handler := validateOrigin(dummyHandler(), 8080)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code, "expected request to be allowed")
		})
	}
}

func TestValidateOrigin_RejectedOrigins(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		origin string
	}{
		{"POST from evil.com", http.MethodPost, "/api/recover", "http://evil.com"},
		{"POST from wrong port", http.MethodPost, "/api/recover", "http://localhost:9999"},
		{"POST from https (wrong scheme)", http.MethodPost, "/api/recover", "https://localhost:8080"},
		{"POST from subdomain trick", http.MethodPost, "/api/recover", "http://localhost:8080.evil.com"},
		{"POST list-vaults from evil origin", http.MethodPost, "/api/list-vaults", "http://attacker.example.com"},
		{"POST list-zip-files from evil origin", http.MethodPost, "/api/list-zip-files", "http://evil.com:8080"},
	}

	handler := validateOrigin(dummyHandler(), 8080)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code, "expected request to be rejected")
		})
	}
}

func TestValidateOrigin_OptionsHandling(t *testing.T) {
	handler := validateOrigin(dummyHandler(), 8080)

	t.Run("OPTIONS from evil origin rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/recover", nil)
		req.Header.Set("Origin", "http://evil.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("OPTIONS with no origin rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/recover", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("OPTIONS from localhost allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/recover", nil)
		req.Header.Set("Origin", "http://localhost:8080")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestValidateOrigin_DifferentPorts(t *testing.T) {
	handler := validateOrigin(dummyHandler(), 8083)

	t.Run("correct port accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/recover", nil)
		req.Header.Set("Origin", "http://localhost:8083")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("wrong port rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/recover", nil)
		req.Header.Set("Origin", "http://localhost:8080")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestSecurityHeadersOnErrorResponses(t *testing.T) {
	// Compose both middlewares: security headers wrapping origin validation.
	// A rejected origin should still have security headers in the response.
	handler := securityHeaders(validateOrigin(dummyHandler(), 8080))

	req := httptest.NewRequest(http.MethodPost, "/api/recover", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "camera=(), microphone=(), geolocation=()", rec.Header().Get("Permissions-Policy"))
}
