package auth

import (
	"context"
	"database/sql"
	"errors"

	"example.com/m/internal/domain/auth"
	"github.com/jmoiron/sqlx"
)

type credentialModel struct {
	UserID       string `db:"user_id"`
	PasswordHash string `db:"password_hash"`
}

type sqlCredentialRepository struct {
	db *sqlx.DB
}

func NewSQLCredentialRepository(db *sqlx.DB) auth.Repository {
	return &sqlCredentialRepository{db: db}
}

func (r *sqlCredentialRepository) FindByUserID(ctx context.Context, userID string) (*auth.PasswordCredential, error) {
	var m credentialModel
	query := `SELECT user_id, password_hash FROM credentials WHERE user_id = $1`

	if err := r.db.GetContext(ctx, &m, query, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return auth.NewPasswordCredential(m.UserID, m.PasswordHash), nil
}

func (r *sqlCredentialRepository) Save(ctx context.Context, cred *auth.PasswordCredential) error {
	query := `
		INSERT INTO credentials (user_id, password_hash)
		VALUES (:user_id, :password_hash)
		ON CONFLICT (user_id) 
		DO UPDATE SET password_hash = EXCLUDED.password_hash
	`

	_, err := r.db.NamedExecContext(ctx, query, credentialModel{
		UserID:       cred.UserID(),
		PasswordHash: cred.PasswordHash(),
	})

	return err
}
