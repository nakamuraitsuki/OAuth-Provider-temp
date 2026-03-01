package auth

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	FindByUserID(ctx context.Context, userID uuid.UUID) (*PasswordCredential, error)
	Save(ctx context.Context, cred *PasswordCredential) error
}
