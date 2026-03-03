package oauth

import (
	"context"
	"errors"
	"time"

	"example.com/m/internal/domain/oauth"
)

var ErrInvalidToken = errors.New("invalid_token")

type RefreshTokenUseCase interface {
	Execute(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error)
}

type refreshTokenInteractor struct {
	tokenRepo      oauth.TokenRepository
	tokenValidator oauth.CredentialService
	tokenGen       oauth.TokenGenerator
}

func NewRefreshTokenInteractor(tokenRepo oauth.TokenRepository, tokenValidator oauth.CredentialService, tokenGen oauth.TokenGenerator) RefreshTokenUseCase {
	return &refreshTokenInteractor{
		tokenRepo:      tokenRepo,
		tokenValidator: tokenValidator,
		tokenGen:       tokenGen,
	}
}

type RefreshTokenInput struct {
	RefreshToken string
	Scope        string
}

type RefreshTokenOutput struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
}

func (i *refreshTokenInteractor) Execute(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	// refresh token を検証する。
	// もし有効なら、新しい access token を発行する。
	token, err := i.tokenRepo.FindRefreshToken(ctx, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	// Token の検証
	if time.Now().After(token.ExpiresAt()) {
		return nil, ErrInvalidToken
	}
	if ok := i.tokenValidator.SecureCompare(ctx, token.Token(), input.RefreshToken); !ok {
		return nil, ErrInvalidToken
	}

	// 新しい access token を発行する。
	accessToken, err := i.tokenGen.GenerateAccessToken(ctx, token.ClientID(), token.UserID(), token.Scope())
	if err != nil {
		return nil, err
	}

	// 新しい refresh token を発行する。
	refreshToken, err := i.tokenGen.GenerateRefreshToken(ctx, token.ClientID(), token.UserID(), token.Scope())
	if err != nil {
		return nil, err
	}

	// 古い refresh token を無効化する
	if err := i.tokenRepo.DeleteRefreshToken(ctx, token.Token()); err != nil {
		return nil, err
	}

	// 新しいTokenを保存する
	if err := i.tokenRepo.SaveAccessToken(ctx, accessToken); err != nil {
		return nil, err
	}
	if err := i.tokenRepo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	return &RefreshTokenOutput{
		AccessToken:  accessToken.Token(),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken.Token(),
	}, nil
}