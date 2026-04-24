package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	nethttp "net/http"
	"strings"
	"time"

	"github.com/shyntr/password-verifier/internal/model"
	"github.com/shyntr/password-verifier/internal/service"
)

const (
	maxBodyBytes       = 8192
	maxUsernameBytes   = 256
	maxPasswordBytes   = 4096
	maxChallengeBytes  = 2048
	maxListItems       = 100
	maxStringItemBytes = 128
)

type Server struct {
	apiKey      string
	verifier    *service.Verifier
	rateLimiter *RateLimiter
	logger      *slog.Logger
}

type Option func(*Server)

func WithRateLimiter(rateLimiter *RateLimiter) Option {
	return func(s *Server) {
		s.rateLimiter = rateLimiter
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

func NewServer(apiKey string, verifier *service.Verifier, opts ...Option) *Server {
	s := &Server{
		apiKey:      apiKey,
		verifier:    verifier,
		rateLimiter: NewRateLimiter(20, time.Minute),
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Server) Handler() nethttp.Handler {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/verify-password", s.verifyPassword)
	return s.securityHeaders(mux)
}

func (s *Server) health(w nethttp.ResponseWriter, _ *nethttp.Request) {
	writeJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) verifyPassword(w nethttp.ResponseWriter, r *nethttp.Request) {
	start := time.Now()
	sourceIP := clientIP(r)

	if !s.authorized(r) {
		writeError(w, nethttp.StatusUnauthorized, "unauthorized_client")
		s.logOutcome("unauthorized_client", "", sourceIP, start)
		return
	}

	req, err := decodeVerifyRequest(w, r)
	if err != nil {
		writeError(w, nethttp.StatusBadRequest, "invalid_request")
		s.logOutcome("invalid_request", "", sourceIP, start)
		return
	}

	usernameHash := redactedHash(req.Username)
	if !validVerifyRequest(req) {
		writeError(w, nethttp.StatusBadRequest, "invalid_request")
		s.logOutcome("invalid_request", usernameHash, sourceIP, start)
		return
	}

	if !s.rateLimiter.Allow(sourceIP, req.Username) {
		writeError(w, nethttp.StatusTooManyRequests, "rate_limited")
		s.logOutcome("rate_limited", usernameHash, sourceIP, start)
		return
	}

	resp, err := s.verifier.Verify(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			writeError(w, nethttp.StatusUnauthorized, "invalid_credentials")
			s.logOutcome("invalid_credentials", usernameHash, sourceIP, start)
			return
		}
		writeError(w, nethttp.StatusUnauthorized, "invalid_credentials")
		s.logOutcome("invalid_credentials", usernameHash, sourceIP, start)
		return
	}

	if !validContext(resp.Context) {
		writeError(w, nethttp.StatusUnauthorized, "invalid_credentials")
		s.logOutcome("invalid_credentials", usernameHash, sourceIP, start)
		return
	}

	writeJSON(w, nethttp.StatusOK, resp)
	s.logOutcome("success", usernameHash, sourceIP, start)
}

func (s *Server) authorized(r *nethttp.Request) bool {
	if s.apiKey == "" {
		return true
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	return constantTimeEqual(strings.TrimPrefix(header, prefix), s.apiKey)
}

func (s *Server) securityHeaders(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logOutcome(outcome, usernameHash, sourceIP string, start time.Time) {
	s.logger.Info("verify_password",
		"outcome", outcome,
		"username_hash", usernameHash,
		"source_ip", sourceIP,
		"latency_ms", time.Since(start).Milliseconds(),
	)
}

func decodeVerifyRequest(w nethttp.ResponseWriter, r *nethttp.Request) (model.VerifyPasswordRequest, error) {
	var req model.VerifyPasswordRequest
	r.Body = nethttp.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return req, errors.New("request body must contain one JSON object")
	}
	return req, nil
}

func validVerifyRequest(req model.VerifyPasswordRequest) bool {
	return req.LoginChallenge != "" &&
		req.Username != "" &&
		req.Password != "" &&
		len(req.LoginChallenge) <= maxChallengeBytes &&
		len(req.Username) <= maxUsernameBytes &&
		len(req.Password) <= maxPasswordBytes
}

func validContext(ctx model.ResponseContext) bool {
	if ctx.Identity == nil && ctx.Authentication == nil {
		return false
	}
	if ctx.Identity != nil && !validIdentityContext(*ctx.Identity) {
		return false
	}
	if ctx.Authentication != nil && !validAuthenticationContext(*ctx.Authentication) {
		return false
	}
	return true
}

func validIdentityContext(ctx model.IdentityContext) bool {
	return validAttributes(ctx.Attributes) &&
		validStringList(ctx.Groups) &&
		validStringList(ctx.Roles)
}

func validAuthenticationContext(ctx model.AuthenticationContext) bool {
	return validStringList(ctx.AMR) &&
		validString(ctx.ACR) &&
		validString(ctx.AuthenticatedAt)
}

func validAttributes(attributes map[string]string) bool {
	for key, value := range attributes {
		if key == "" || !validString(key) || !validString(value) {
			return false
		}
	}
	return true
}

func validString(value string) bool {
	return len(value) <= maxStringItemBytes
}

func validStringList(values []string) bool {
	if len(values) > maxListItems {
		return false
	}
	for _, value := range values {
		if value == "" || len(value) > maxStringItemBytes {
			return false
		}
	}
	return true
}

func writeError(w nethttp.ResponseWriter, status int, code string) {
	writeJSON(w, status, model.ErrorResponse{Error: code})
}

func writeJSON(w nethttp.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func constantTimeEqual(got, want string) bool {
	gotHash := sha256.Sum256([]byte(got))
	wantHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1 && len(got) == len(want)
}

func redactedHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func clientIP(r *nethttp.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
