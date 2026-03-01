package user

import (
	"context"

	"example.com/m/internal/domain/user"
)

type UserUseCase interface {
	GetProfile(ctx context.Context, userID string) (*user.User, error)
}
