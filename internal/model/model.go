package model

type VerifyPasswordRequest struct {
	LoginChallenge string `json:"login_challenge"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

type VerifyPasswordResponse struct {
	Subject string          `json:"subject"`
	Context ResponseContext `json:"context,omitempty"`
}

type ResponseContext struct {
	Identity       *IdentityContext       `json:"identity,omitempty"`
	Authentication *AuthenticationContext `json:"authentication,omitempty"`
}

type IdentityContext struct {
	Attributes map[string]string `json:"attributes,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
}

type AuthenticationContext struct {
	AMR             []string `json:"amr,omitempty"`
	ACR             string   `json:"acr,omitempty"`
	AuthenticatedAt string   `json:"authenticated_at,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
