package oauth

import (
	"context"
)

type AuthorizationCodeRepository interface {
	Save(ctx context.Context, code *AuthorizationCode) error
	FindByCode(ctx context.Context, code string) (*AuthorizationCode, error)
	Delete(ctx context.Context, code string) error
}
