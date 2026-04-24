package http

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shyntr/password-verifier/internal/model"
	"github.com/shyntr/password-verifier/internal/service"
	"github.com/shyntr/password-verifier/internal/store"
)

const testAPIKey = "test-api-key"

func TestVerifyPasswordSuccessWithoutAPIKey(t *testing.T) {
	handler := newTestHandler(t, "", NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, "", `{"login_challenge":"opaque","username":"admin","password":"admin"}`)

	if resp.StatusCode != nethttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, nethttp.StatusOK)
	}

	var body model.VerifyPasswordResponse
	decodeBody(t, resp, &body)

	if body.Subject != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("subject = %q", body.Subject)
	}
	if body.Context.Identity == nil {
		t.Fatal("identity context is nil")
	}
	if body.Context.Authentication == nil {
		t.Fatal("authentication context is nil")
	}
	if body.Context.Identity.Attributes["preferred_username"] != "admin" {
		t.Fatalf("preferred_username = %q", body.Context.Identity.Attributes["preferred_username"])
	}
	if len(body.Context.Identity.Groups) != 1 || body.Context.Identity.Groups[0] != "engineering" {
		t.Fatalf("groups = %#v", body.Context.Identity.Groups)
	}
	if len(body.Context.Identity.Roles) != 1 || body.Context.Identity.Roles[0] != "admin" {
		t.Fatalf("roles = %#v", body.Context.Identity.Roles)
	}
	if len(body.Context.Authentication.AMR) != 1 || body.Context.Authentication.AMR[0] != "pwd" {
		t.Fatalf("amr = %#v", body.Context.Authentication.AMR)
	}
}

func TestVerifyPasswordInvalidPasswordWithoutAPIKey(t *testing.T) {
	handler := newTestHandler(t, "", NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, "", `{"login_challenge":"opaque","username":"admin","password":"wrong"}`)

	assertError(t, resp, nethttp.StatusUnauthorized, "invalid_credentials")
}

func TestVerifyPasswordUnknownUser(t *testing.T) {
	handler := newTestHandler(t, "", NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, "", `{"login_challenge":"opaque","username":"missing","password":"admin"}`)

	assertError(t, resp, nethttp.StatusUnauthorized, "invalid_credentials")
}

func TestVerifyPasswordMissingAuthorizationWithAPIKey(t *testing.T) {
	handler := newTestHandler(t, testAPIKey, NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, "", `{"login_challenge":"opaque","username":"admin","password":"admin"}`)

	assertError(t, resp, nethttp.StatusUnauthorized, "unauthorized_client")
}

func TestVerifyPasswordWrongAuthorizationWithAPIKey(t *testing.T) {
	handler := newTestHandler(t, testAPIKey, NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, "wrong", `{"login_challenge":"opaque","username":"admin","password":"admin"}`)

	assertError(t, resp, nethttp.StatusUnauthorized, "unauthorized_client")
}

func TestVerifyPasswordSuccessWithAPIKey(t *testing.T) {
	handler := newTestHandler(t, testAPIKey, NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, testAPIKey, `{"login_challenge":"opaque","username":"admin","password":"admin"}`)

	if resp.StatusCode != nethttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, nethttp.StatusOK)
	}
}

func TestVerifyPasswordUnauthorizedClient(t *testing.T) {
	handler := newTestHandler(t, testAPIKey, NewRateLimiter(10, time.Minute))

	for _, apiKey := range []string{"", "wrong"} {
		resp := postVerify(t, handler, apiKey, `{"login_challenge":"opaque","username":"admin","password":"admin"}`)

		assertError(t, resp, nethttp.StatusUnauthorized, "unauthorized_client")
	}
}

func TestVerifyPasswordMissingFields(t *testing.T) {
	handler := newTestHandler(t, testAPIKey, NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, testAPIKey, `{"login_challenge":"opaque","username":"admin"}`)

	assertError(t, resp, nethttp.StatusBadRequest, "invalid_request")
}

func TestVerifyPasswordUnknownJSONField(t *testing.T) {
	handler := newTestHandler(t, testAPIKey, NewRateLimiter(10, time.Minute))

	resp := postVerify(t, handler, testAPIKey, `{"login_challenge":"opaque","username":"admin","password":"admin","extra":true}`)

	assertError(t, resp, nethttp.StatusBadRequest, "invalid_request")
}

func TestVerifyPasswordOversizedBody(t *testing.T) {
	handler := newTestHandler(t, testAPIKey, NewRateLimiter(10, time.Minute))
	password := strings.Repeat("a", maxBodyBytes)

	resp := postVerify(t, handler, testAPIKey, `{"login_challenge":"opaque","username":"admin","password":"`+password+`"}`)

	assertError(t, resp, nethttp.StatusBadRequest, "invalid_request")
}

func TestVerifyPasswordRateLimit(t *testing.T) {
	handler := newTestHandler(t, "", NewRateLimiter(2, time.Minute))
	body := `{"login_challenge":"opaque","username":"admin","password":"wrong"}`

	for i := 0; i < 2; i++ {
		resp := postVerify(t, handler, "", body)
		if resp.StatusCode != nethttp.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d", i+1, resp.StatusCode, nethttp.StatusUnauthorized)
		}
	}

	resp := postVerify(t, handler, "", body)

	assertError(t, resp, nethttp.StatusTooManyRequests, "rate_limited")
}

func TestHealth(t *testing.T) {
	handler := newTestHandler(t, "", NewRateLimiter(10, time.Minute))

	req := httptest.NewRequest(nethttp.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()

	if resp.StatusCode != nethttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, nethttp.StatusOK)
	}

	var body map[string]string
	decodeBody(t, resp, &body)
	if body["status"] != "ok" {
		t.Fatalf("status body = %#v", body)
	}
}

func TestResponseNormalizationOmitsEmptyFields(t *testing.T) {
	user := store.User{
		Subject:       "22222222-2222-2222-2222-222222222222",
		Username:      "user",
		Email:         "user@example.test",
		EmailVerified: false,
	}

	encoded, err := json.Marshal(model.VerifyPasswordResponse{
		Subject: user.Subject,
		Context: user.ResponseContext(),
	})
	if err != nil {
		t.Fatal(err)
	}

	body := string(encoded)
	for _, disallowed := range []string{"null", "email", "groups", "roles", "acr", "authenticated_at"} {
		if strings.Contains(body, disallowed) {
			t.Fatalf("response %s contains %q", body, disallowed)
		}
	}
	if !strings.Contains(body, `"identity":{"attributes":{"preferred_username":"user"}}`) {
		t.Fatalf("response %s missing expected identity attributes", body)
	}
	if !strings.Contains(body, `"authentication":{"amr":["pwd"]}`) {
		t.Fatalf("response %s missing expected authentication context", body)
	}
}

func newTestHandler(t *testing.T, apiKey string, limiter *RateLimiter) nethttp.Handler {
	t.Helper()

	userStore, err := store.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(apiKey, service.NewVerifier(userStore), WithRateLimiter(limiter), WithLogger(logger))
	return srv.Handler()
}

func postVerify(t *testing.T, handler nethttp.Handler, apiKey string, body string) *nethttp.Response {
	t.Helper()

	req := httptest.NewRequest(nethttp.MethodPost, "/v1/verify-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func assertError(t *testing.T, resp *nethttp.Response, status int, code string) {
	t.Helper()

	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d", resp.StatusCode, status)
	}

	var body model.ErrorResponse
	decodeBody(t, resp, &body)
	if body.Error != code {
		t.Fatalf("error = %q, want %q", body.Error, code)
	}
}

func decodeBody(t *testing.T, resp *nethttp.Response, out any) {
	t.Helper()

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
