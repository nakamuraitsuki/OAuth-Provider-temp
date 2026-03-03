package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"example.com/m/internal/domain/oauth"
	"github.com/google/uuid"
)

const (
	accessTokenExpirationTime  = time.Hour           // １時間
	refreshTokenExpirationTime = 30 * 24 * time.Hour // 30日
)

type tokenGenerator struct{}

func NewTokenGenerator() oauth.TokenGenerator { return &tokenGenerator{} }

func (g *tokenGenerator) GenerateAccessToken(
	ctx context.Context,
	clientID, userID uuid.UUID,
	scope []string,
) (*oauth.AccessToken, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	return oauth.NewAccessToken(
		t,
		clientID,
		userID,
		scope,
		time.Now().Add(accessTokenExpirationTime),
	), nil
}

func (g *tokenGenerator) GenerateRefreshToken(
	ctx context.Context,
	clientID, userID uuid.UUID,
	scope []string,
) (*oauth.RefreshToken, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	return oauth.NewRefreshToken(
		t,
		clientID,
		userID,
		scope,
		time.Now().Add(refreshTokenExpirationTime),
	), nil
}
