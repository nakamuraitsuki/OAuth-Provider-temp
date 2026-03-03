package crypto

import (
	"context"
	"crypto/subtle"

	"example.com/m/internal/domain/oauth"
)

type tokenCredential struct{}

func NewTokenCredential() oauth.CredentialService { return &tokenCredential{} }

func (c *tokenCredential) SecureCompare(ctx context.Context, safe, input string) bool {
	return subtle.ConstantTimeCompare([]byte(safe), []byte(input)) == 1
}
