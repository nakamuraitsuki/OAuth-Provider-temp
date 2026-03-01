package auth

import "context"

type Repository interface {
	FindByUserID(ctx context.Context, userID string) (*PasswordCredential, error)
	Save(ctx context.Context, cred *PasswordCredential) error
}
