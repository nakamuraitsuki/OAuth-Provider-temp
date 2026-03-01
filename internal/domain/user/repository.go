package user

import (
	"context"

	"github.com/google/uuid"
)

// Repository はUserエンティティの永続化を定義する。
type Repository interface {
	// NOTE: Save は新規作成と更新の両方を扱う。
	Save(ctx context.Context, user *User) error
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
}
