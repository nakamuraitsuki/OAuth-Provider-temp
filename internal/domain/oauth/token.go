package oauth

import (
	"time"

	"github.com/google/uuid"
)

// [RFC6749 Section 1.4] Access Token
type AccessToken struct {
	token     string
	clientID  uuid.UUID
	userID    uuid.UUID
	scope     []string
	expiresAt time.Time
}

// [RFC6749 Section 1.5] Refresh Token
type RefreshToken struct {
	token     string
	clientID  uuid.UUID
	userID    uuid.UUID
	scope     []string
	expiresAt time.Time
}

func NewAccessToken(
	token string, 
	clientID, userID uuid.UUID, 
	scope []string, 
	expiresAt time.Time,
) *AccessToken {
	return &AccessToken{
		token:     token,
		clientID:  clientID,
		userID:    userID,
		scope:     scope,
		expiresAt: expiresAt,
	}
}

func NewRefreshToken(
	token string, 
	clientID, userID uuid.UUID, 
	scope []string, 
	expiresAt time.Time,
) *RefreshToken {
	return &RefreshToken{
		token:     token,
		clientID:  clientID,
		userID:    userID,
		scope:     scope,
		expiresAt: expiresAt,
	}
}

func (t *AccessToken) Token() string { return t.token }
func (t *AccessToken) ClientID() uuid.UUID { return t.clientID }
func (t *AccessToken) UserID() uuid.UUID { return t.userID }
func (t *AccessToken) Scope() []string { return t.scope }
func (t *AccessToken) ExpiresAt() time.Time { return t.expiresAt }

func (t *RefreshToken) Token() string { return t.token }
func (t *RefreshToken) ClientID() uuid.UUID { return t.clientID }
func (t *RefreshToken) UserID() uuid.UUID { return t.userID }
func (t *RefreshToken) Scope() []string { return t.scope }
func (t *RefreshToken) ExpiresAt() time.Time { return t.expiresAt }
