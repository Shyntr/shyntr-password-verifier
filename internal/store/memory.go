package store

import (
	"errors"
	"fmt"

	"github.com/shyntr/password-verifier/internal/model"
	"golang.org/x/crypto/bcrypt"
)

var ErrUserNotFound = errors.New("user not found")

const (
	adminPasswordHash = "$2a$10$gmPwBTKWZcPOAGTHs7drreD2OfmQHO5qnMP6XGkqMUNg/dvQ8TYgu"
	fakePasswordHash  = "$2a$10$hT0e8sQe7XmAlqpygQH5SOmgHHY6xVPFt0kDQ5v0j3ayGM/edyLxG"
)

type User struct {
	Subject       string
	Username      string
	PasswordHash  []byte
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Groups        []string
	Roles         []string
}

type MemoryStore struct {
	usersByUsername map[string]User
	fakeHash        []byte
}

func NewMemoryStore() (*MemoryStore, error) {
	admin := User{
		Subject:       "11111111-1111-1111-1111-111111111111",
		Username:      "admin",
		PasswordHash:  []byte(adminPasswordHash),
		Email:         "admin@example.test",
		EmailVerified: true,
		Name:          "Admin User",
		GivenName:     "Admin",
		FamilyName:    "User",
		Groups:        []string{"engineering"},
		Roles:         []string{"admin"},
	}

	for name, hash := range map[string][]byte{
		"admin": admin.PasswordHash,
		"fake":  []byte(fakePasswordHash),
	} {
		if _, err := bcrypt.Cost(hash); err != nil {
			return nil, fmt.Errorf("invalid %s password hash: %w", name, err)
		}
	}

	return &MemoryStore{
		usersByUsername: map[string]User{
			admin.Username: admin,
		},
		fakeHash: []byte(fakePasswordHash),
	}, nil
}

func (s *MemoryStore) FindByUsername(username string) (User, bool) {
	user, ok := s.usersByUsername[username]
	return user, ok
}

func (s *MemoryStore) FakePasswordHash() []byte {
	return s.fakeHash
}

func (u User) ResponseContext() model.ResponseContext {
	attributes := make(map[string]string)
	if u.Username != "" {
		attributes["preferred_username"] = u.Username
	}
	if u.EmailVerified && u.Email != "" {
		attributes["email"] = u.Email
	}
	if u.Name != "" {
		attributes["name"] = u.Name
	}
	if u.GivenName != "" {
		attributes["given_name"] = u.GivenName
	}
	if u.FamilyName != "" {
		attributes["family_name"] = u.FamilyName
	}

	ctx := model.ResponseContext{
		Authentication: &model.AuthenticationContext{
			AMR: []string{"pwd"},
		},
	}
	if len(attributes) > 0 || len(u.Groups) > 0 || len(u.Roles) > 0 {
		ctx.Identity = &model.IdentityContext{
			Attributes: attributes,
			Groups:     cloneStrings(u.Groups),
			Roles:      cloneStrings(u.Roles),
		}
	}
	return ctx
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}
