package oauth

import (
	"time"

	"github.com/google/uuid"
)

// [RFC6749 Section 4.1] Authorization Code
type AuthorizationCode struct {
	code        string
	clientID    uuid.UUID
	userID      uuid.UUID
	redirectURI string
	scope       []string
	state       string
	expiresAt   time.Time
}

// [RFC6749 Section 4.1.2] Code は短命にしましょう。
func NewAuthorizationCode(
	code string,
	clientID, userID uuid.UUID,
	redirectURI string,
	scope []string,
	state string,
	expiresAt time.Time,
) *AuthorizationCode {
	return &AuthorizationCode{
		code:        code,
		clientID:    clientID,
		userID:      userID,
		redirectURI: redirectURI,
		scope:       scope,
		state:       state,
		expiresAt:   expiresAt,
	}
}

func (c *AuthorizationCode) IsExpired() bool     { return time.Now().After(c.expiresAt) }
func (c *AuthorizationCode) Code() string        { return c.code }
func (c *AuthorizationCode) ClientID() uuid.UUID { return c.clientID }
func (c *AuthorizationCode) UserID() uuid.UUID   { return c.userID }
func (c *AuthorizationCode) RedirectURI() string { return c.redirectURI }
func (c *AuthorizationCode) Scope() []string     { return c.scope }
func (c *AuthorizationCode) State() string       { return c.state }
func (c *AuthorizationCode) ExpiresAt() time.Time { return c.expiresAt }