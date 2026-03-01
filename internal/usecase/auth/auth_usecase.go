package auth

import (
	"context"

	"example.com/m/internal/domain/user"
)

type AuthUseCase interface {
	Authenticate(ctx context.Context, input AuthInput) (*user.User, error)
	Register(ctx context.Context, input RegisterInput) error
	GetIssuer() string
}
