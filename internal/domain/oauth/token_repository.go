package oauth

import "context"

type TokenRepository interface {
	// Access Token 用
	SaveAccessToken(ctx context.Context, token *AccessToken) error
	FindAccessToken(ctx context.Context, tokenStr string) (*AccessToken, error)
	DeleteAccessToken(ctx context.Context, tokenStr string) error

	// Refresh Token 用
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	FindRefreshToken(ctx context.Context, tokenStr string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, tokenStr string) error
}
