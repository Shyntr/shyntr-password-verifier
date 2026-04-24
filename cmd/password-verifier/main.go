package main

import (
	"context"
	"errors"
	"log/slog"
	nethttp "net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	verifierhttp "github.com/shyntr/password-verifier/internal/http"
	"github.com/shyntr/password-verifier/internal/service"
	"github.com/shyntr/password-verifier/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	apiKey := os.Getenv("VERIFIER_API_KEY")

	addr := os.Getenv("VERIFIER_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	userStore, err := store.NewMemoryStore()
	if err != nil {
		logger.Error("failed to initialize user store", "error", err)
		os.Exit(1)
	}

	server := &nethttp.Server{
		Addr:              addr,
		Handler:           verifierhttp.NewServer(apiKey, service.NewVerifier(userStore), verifierhttp.WithLogger(logger)).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("password verifier listening", "addr", addr)
		errCh <- server.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-stop:
		logger.Info("shutdown requested", "signal", sig.String())
	case err := <-errCh:
		if !errors.Is(err, nethttp.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}
