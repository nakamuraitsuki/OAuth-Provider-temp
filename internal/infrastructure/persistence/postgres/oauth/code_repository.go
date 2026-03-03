package oauth

import (
	"context"
	"errors"
	"time"

	"example.com/m/internal/domain/oauth"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type authorizationCodeModel struct {
	Code        string    `db:"code"`
	ClientID    uuid.UUID `db:"client_id"`
	UserID      uuid.UUID `db:"user_id"`
	RedirectURI string    `db:"redirect_uri"`
	State       string    `db:"state"`
	ExpiresAt   time.Time `db:"expires_at"`
}

type scopeCodeRelationModel struct {
	Code    string `db:"code"`
	ScopeID int    `db:"scope_id"`
}

type codeRepository struct {
	db *sqlx.DB
}

func NewCodeRepository(db *sqlx.DB) oauth.AuthorizationCodeRepository {
	return &codeRepository{db: db}
}

func (r *codeRepository) Save(ctx context.Context, code *oauth.AuthorizationCode) error {
	codeModel := authorizationCodeModel{
		Code:        code.Code(),
		ClientID:    code.ClientID(),
		UserID:      code.UserID(),
		RedirectURI: code.RedirectURI(),
		State:       code.State(),
		ExpiresAt:   code.ExpiresAt(),
	}

	var scopeModels []scopeCodeRelationModel
	for _, scope := range code.Scope() {
		scopeID, exists := ScopeIDs[scope]
		if !exists {
			return errors.New("invalid scope: " + scope)
		}
		scopeModels = append(scopeModels, scopeCodeRelationModel{
			Code:    code.Code(),
			ScopeID: scopeID,
		})
	}

	const query = `
INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, state, expires_at)
VALUES (:code, :client_id, :user_id, :redirect_uri, :state, :expires_at)
`

	// Bulk insert for scopes
	const queryScopes = `INSERT INTO authorization_code_scopes (code, scope_id) VALUES (:code, :scope_id)`

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.NamedExecContext(ctx, query, codeModel)
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

func (r *codeRepository) FindByCode(ctx context.Context, codeStr string) (*oauth.AuthorizationCode, error) {
	var cm authorizationCodeModel
	const query = `
SELECT code, client_id, user_id, redirect_uri, state, expires_at
FROM authorization_codes
WHERE code = $1
`

	const queryScopes = `SELECT code, scope_id FROM authorization_code_scopes WHERE code = $1`
	
	err := r.db.GetContext(ctx, &cm, query, codeStr)
	if err != nil {
		return nil, err
	}
	
	var scopeModels []scopeCodeRelationModel
	if err := r.db.SelectContext(ctx, &scopeModels, queryScopes, codeStr); err != nil {
		return nil, err
	}

	scopes := make([]string, len(scopeModels))
	for i, sm := range scopeModels {
		scopes[i] = ScopesTable[sm.ScopeID]
	}

	return oauth.NewAuthorizationCode(
		cm.Code,
		cm.ClientID,
		cm.UserID,
		cm.RedirectURI,
		scopes,
		cm.State,
		cm.ExpiresAt,
	), nil
}

func (r *codeRepository) Delete(ctx context.Context, codeStr string) error {
	const query = `DELETE FROM authorization_codes WHERE code = $1`
	_, err := r.db.ExecContext(ctx, query, codeStr)
	return err
}
