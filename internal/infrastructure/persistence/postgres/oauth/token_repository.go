package oauth

import (
	"context"
	"errors"
	"time"

	"example.com/m/internal/domain/oauth"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type accessTokenModel struct {
	Token     string    `db:"token"`
	ClientID  uuid.UUID `db:"client_id"`
	UserID    uuid.UUID `db:"user_id"`
	ExpiresAt time.Time `db:"expires_at"`
}

type atScopeRelationModel struct {
	Token   string `db:"token"`
	ScopeID int    `db:"scope_id"`
}

type refreshTokenModel struct {
	Token     string    `db:"token"`
	ClientID  uuid.UUID `db:"client_id"`
	UserID    uuid.UUID `db:"user_id"`
	ExpiresAt time.Time `db:"expires_at"`
}

type rtScopeRelationModel struct {
	Token   string `db:"token"`
	ScopeID int    `db:"scope_id"`
}

type tokenRepository struct {
	db *sqlx.DB
}

func NewTokenRepository(db *sqlx.DB) oauth.TokenRepository {
	return &tokenRepository{db: db}
}

func (r *tokenRepository) SaveAccessToken(ctx context.Context, token *oauth.AccessToken) error {
	tokenModel := accessTokenModel{
		Token:     token.Token(),
		ClientID:  token.ClientID(),
		UserID:    token.UserID(),
		ExpiresAt: token.ExpiresAt(),
	}

	var scopeModels []atScopeRelationModel
	for _, scope := range token.Scope() {
		scopeID, exists := ScopeIDs[scope]
		if !exists {
			return errors.New("invalid scope: " + scope)
		}
		scopeModels = append(scopeModels, atScopeRelationModel{
			Token:   token.Token(),
			ScopeID: scopeID,
		})
	}

	const query = `
INSERT INTO access_tokens (token, client_id, user_id, expires_at)
VALUES (:token, :client_id, :user_id, :expires_at)
`
	const queryScopes = `INSERT INTO access_token_scopes (token, scope_id) VALUES (:token, :scope_id)`
	tx , err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.NamedExecContext(ctx, query, tokenModel)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.NamedExecContext(ctx, queryScopes, scopeModels)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (r *tokenRepository) FindAccessToken(ctx context.Context, tokenStr string) (*oauth.AccessToken, error) {
	var tm accessTokenModel
	const query = `
SELECT token, client_id, user_id, expires_at
FROM access_tokens
WHERE token = $1
`

	const queryScopes = `SELECT token, scope_id FROM access_token_scopes WHERE token = $1`

	
	err := r.db.GetContext(ctx, &tm, query, tokenStr)
	if err != nil {
		return nil, err
	}

	var scopeRelations []atScopeRelationModel
	if err := r.db.SelectContext(ctx, &scopeRelations, queryScopes, tokenStr); err != nil {
		return nil, err
	}

	scopes := make([]string, len(scopeRelations))
	for i, rel := range scopeRelations {
		scopes[i] = ScopesTable[rel.ScopeID]
	}

	return oauth.NewAccessToken(
		tm.Token,
		tm.ClientID,
		tm.UserID,
		scopes,
		tm.ExpiresAt,
	), nil
}

func (r *tokenRepository) DeleteAccessToken(ctx context.Context, tokenStr string) error {
	const query = `
DELETE FROM access_tokens
WHERE token = $1
`
	const queryScopes = `DELETE FROM access_token_scopes WHERE token = $1`
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, queryScopes, tokenStr)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.ExecContext(ctx, query, tokenStr)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (r *tokenRepository) SaveRefreshToken(ctx context.Context, token *oauth.RefreshToken) error {
	tokenModel := refreshTokenModel{
		Token:     token.Token(),
		ClientID:  token.ClientID(),
		UserID:    token.UserID(),
		ExpiresAt: token.ExpiresAt(),
	}

	var scopeModels []rtScopeRelationModel
	for _, scope := range token.Scope() {
		scopeID, exists := ScopeIDs[scope]
		if !exists {
			return errors.New("invalid scope: " + scope)
		}
		scopeModels = append(scopeModels, rtScopeRelationModel{
			Token:   token.Token(),
			ScopeID: scopeID,
		})
	}

	const query = `
INSERT INTO refresh_tokens (token, client_id, user_id,  expires_at)
VALUES (:token, :client_id, :user_id, :expires_at)
`
	const queryScopes = `INSERT INTO refresh_token_scopes (token, scope_id) VALUES (:token, :scope_id)`

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.NamedExecContext(ctx, query, tokenModel)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.NamedExecContext(ctx, queryScopes, scopeModels)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (r *tokenRepository) FindRefreshToken(ctx context.Context, tokenStr string) (*oauth.RefreshToken, error) {
	var tm refreshTokenModel
	const query = `
SELECT token, client_id, user_id, expires_at
FROM refresh_tokens
WHERE token = $1
`

	const queryScopes = `SELECT token, scope_id FROM refresh_token_scopes WHERE token = $1`

	err := r.db.GetContext(ctx, &tm, query, tokenStr)
	if err != nil {
		return nil, err
	}

	var scopeRelations []rtScopeRelationModel
	if err := r.db.SelectContext(ctx, &scopeRelations, queryScopes, tokenStr); err != nil {
		return nil, err
	}

	scopes := make([]string, len(scopeRelations))
	for i, rel := range scopeRelations {
		scopes[i] = ScopesTable[rel.ScopeID]
	}

	return oauth.NewRefreshToken(
		tm.Token,
		tm.ClientID,
		tm.UserID,
		scopes,
		tm.ExpiresAt,
	), nil
}

func (r *tokenRepository) DeleteRefreshToken(ctx context.Context, tokenStr string) error {
	const query = `
DELETE FROM refresh_tokens
WHERE token = $1
`
	const queryScopes = `DELETE FROM refresh_token_scopes WHERE token = $1`
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, queryScopes, tokenStr)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.ExecContext(ctx, query, tokenStr)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
