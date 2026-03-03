package oauth

import (
	"context"
	"time"

	"example.com/m/internal/domain/oauth"
)

type VerifyTokenUseCase interface {
	Execute(ctx context.Context, input VerifyTokenInput) (*VerifyTokenOutput, error)
}

type verifyTokenInteractor struct {
	tokenRepo      oauth.TokenRepository
	tokenValidator oauth.CredentialService
}

func NewVerifyTokenUseCase(
	tokenRepo oauth.TokenRepository,
	tokenValidator oauth.CredentialService,
) VerifyTokenUseCase {
	return &verifyTokenInteractor{
		tokenRepo:      tokenRepo,
		tokenValidator: tokenValidator,
	}
}

type VerifyTokenInput struct {
	AccessToken string
}

type VerifyTokenOutput struct {
	Active   bool
	UserID   string
	ClientID string
	Scope    []string
}

func (i *verifyTokenInteractor) Execute(ctx context.Context, input VerifyTokenInput) (*VerifyTokenOutput, error) {
	token, err := i.tokenRepo.FindAccessToken(ctx, input.AccessToken)
	if err != nil {
		return &VerifyTokenOutput{Active: false}, nil
	}

	if time.Now().After(token.ExpiresAt()) {
		return &VerifyTokenOutput{Active: false}, nil
	}

	if !i.tokenValidator.SecureCompare(ctx, token.Token(), input.AccessToken) {
		return &VerifyTokenOutput{Active: false}, nil
	}

	return &VerifyTokenOutput{
		Active:   true,
		UserID:   token.UserID().String(),
		ClientID: token.ClientID().String(),
		Scope:    token.Scope(),
	}, nil
}
