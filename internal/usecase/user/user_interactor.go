package user

import (
	"context"

	"example.com/m/internal/domain/user"
	"github.com/google/uuid"
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
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	return i.userRepo.FindByID(ctx, id)
}
