package crypto

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"example.com/m/internal/domain/oauth"
)

type codeValidator struct{}

func NewCodeValidator() *codeValidator { return &codeValidator{} }

func (v *codeValidator) Validate(ctx context.Context, inputCode string, stored *oauth.AuthorizationCode) error {
	// タイミング攻撃対策
	if subtle.ConstantTimeCompare([]byte(stored.Code()), []byte(inputCode)) != 1 {
		return errors.New("invalid authorization code")
	}

	if time.Now().After(stored.ExpiresAt()) {
		return errors.New("authorization code expired")
	}

	return nil
}
