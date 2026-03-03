package oauth

import (
	"slices"

	"github.com/google/uuid"
)

// [RFC6749 Section 2.1] Client Types
// OAuth 2.0 のクライアントは、機密クライアントと公開クライアントの2種類に分類される
type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

type Client struct {
	id         uuid.UUID
	secretHash string // クライアントシークレットは、機密クライアントにのみ存在する
	clientType ClientType
	// [RFC6749 Section 3.1.2] リクエストに含まれる Redirect URI を覚えておくためのフィールド
	redirectURIs []string
	// [RFC6749 Section 3.3] Scope
	// クライアントがリクエストできるスコープを覚えておくためのフィールド
	scope []string
}

func NewClient(
	id uuid.UUID,
	secretHash string,
	clientType ClientType,
	redirectURIs []string,
	scope []string,
) *Client {
	return &Client{
		id:           id,
		secretHash:   secretHash,
		clientType:   clientType,
		redirectURIs: redirectURIs,
		scope:        scope,
	}
}

func (c *Client) SecretHash() string { return c.secretHash }

func (c *Client) MatchesRedirectURI(uri string) bool {
	return slices.Contains(c.redirectURIs, uri)
}

func (c *Client) IsValidScope(requestedScope []string) bool {
	for _, scope := range requestedScope {
		if !slices.Contains(c.scope, scope) {
			return false
		}
	}
	return true
}
