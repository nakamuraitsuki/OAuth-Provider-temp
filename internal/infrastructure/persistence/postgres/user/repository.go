package user

import (
	"context"
	"database/sql"
	"errors"

	"example.com/m/internal/domain/user"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// userModel はDBのテーブル構造を定義する内部的な構造体（DTO）
type userModel struct {
	ID          uuid.UUID `db:"id"`
	Username    string    `db:"username"`
	DisplayName string    `db:"display_name"`
}

// toEntity はDBモデルをドメインエンティティに変換し
func (m *userModel) toEntity() *user.User {
	return user.NewUser(m.ID, m.Username, m.DisplayName)
}

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) user.Repository {
	return &userRepository{db: db}
}

func (r *userRepository) Save(ctx context.Context, u *user.User) error {
	query := `
		INSERT INTO users (id, username, display_name)
		VALUES (:id, :username, :display_name)
		ON CONFLICT (id) DO UPDATE SET
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name
	`
	_, err := r.db.NamedExecContext(ctx, query, userModel{
		ID:          u.ID(),
		Username:    u.Username(),
		DisplayName: u.DisplayName(),
	})
	return err
}

func (r *userRepository) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	var m userModel
	query := "SELECT id, username, display_name FROM users WHERE id = $1"
	if err := r.db.GetContext(ctx, &m, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // またはカスタムのエラー
		}
		return nil, err
	}
	return m.toEntity(), nil
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*user.User, error) {
	var m userModel
	query := "SELECT id, username, display_name FROM users WHERE username = $1"
	if err := r.db.GetContext(ctx, &m, query, username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return m.toEntity(), nil
}
