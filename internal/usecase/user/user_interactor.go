package user

import (
	"context"

	"example.com/m/internal/domain/user"
)

type userInteractor struct {
	userRepo user.Repository
}

func NewUserInteractor(userRepo user.Repository) UserUseCase {
	return &userInteractor{
		userRepo: userRepo,
	}
}

func (i *userInteractor) GetProfile(ctx context.Context, userID string) (*user.User, error) {
	return i.userRepo.FindByID(ctx, userID)
}
