package service

import (
	"errors"

	"github.com/shyntr/password-verifier/internal/model"
	"github.com/shyntr/password-verifier/internal/store"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type UserStore interface {
	FindByUsername(username string) (store.User, bool)
	FakePasswordHash() []byte
}

type Verifier struct {
	store UserStore
}

func NewVerifier(store UserStore) *Verifier {
	return &Verifier{store: store}
}

func (v *Verifier) Verify(username, password string) (model.VerifyPasswordResponse, error) {
	user, ok := v.store.FindByUsername(username)
	hash := v.store.FakePasswordHash()
	if ok {
		hash = user.PasswordHash
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil || !ok {
		return model.VerifyPasswordResponse{}, ErrInvalidCredentials
	}

	return model.VerifyPasswordResponse{
		Subject: user.Subject,
		Context: user.ResponseContext(),
	}, nil
}
