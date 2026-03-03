package oauth

import (
	"context"

	"example.com/m/internal/domain/oauth"
	"example.com/m/internal/domain/oauth/value"
	"github.com/google/uuid"
)

// クライアントは事前に登録されていると仮定するため、リポジトリは静的なマップを使用してクライアント情報を管理します。

var staticClients = map[uuid.UUID]*oauth.Client{
	uuid.MustParse("a394037d-727b-499e-b9b4-3a78c7615fef"): oauth.NewClient(
		uuid.MustParse("a394037d-727b-499e-b9b4-3a78c7615fef"),
		"$2y$05$vFR41M6J4zMSI4FURvDjsOXWHK22cKzxwjk84W/qD75aJMzzuyiqC", // secret
		oauth.ClientTypeConfidential,
		[]string{"http://..."},
		[]string{
			value.ScopeProfileRead,
			value.ScopeOpenID,
		},
	),
}

type clientRepository struct{}

func NewClientRepository() oauth.ClientRepository {
	return &clientRepository{}
}

func (r *clientRepository) FindByID(ctx context.Context, id uuid.UUID) (*oauth.Client, error) {
	client, exists := staticClients[id]
	if !exists {
		return nil, nil // Not found
	}
	return client, nil
}
