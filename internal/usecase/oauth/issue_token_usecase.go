package oauth

import (
	"context"
	"errors"
	"time"

	"example.com/m/internal/domain/oauth"
	"github.com/google/uuid"
)

var (
	ErrInvalidGrant         = errors.New("invalid_grant")
	ErrInvalidClient        = errors.New("invalid_client")
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")
)

// [RFC 6749 Section 4.1.4] Access Token Response
// 具体例の時間をそのまま流用
const AccessTokenExpirationTime = 1 * time.Hour

type IssueTokenUseCase interface {
	Execute(ctx context.Context, req IssueTokenInput) (*IssueTokenOutput, error)
}

type issueTokenInteractor struct {
	clientRepo oauth.ClientRepository
	codeRepo   oauth.AuthorizationCodeRepository
	tokenRepo  oauth.TokenRepository
	hasher     oauth.SecretHashService
	tokenGen   oauth.TokenGenerator
	codeValidator oauth.CodeValidator
}

func NewIssueTokenInteractor(
	clientRepo oauth.ClientRepository,
	codeRepo oauth.AuthorizationCodeRepository,
	tokenRepo oauth.TokenRepository,
	hasher oauth.SecretHashService,
	tokenGen oauth.TokenGenerator,
	codeValidator oauth.CodeValidator,
) IssueTokenUseCase {
	return &issueTokenInteractor{
		clientRepo: clientRepo,
		codeRepo:   codeRepo,
		tokenRepo:  tokenRepo,
		tokenGen:   tokenGen,
		hasher:     hasher,
		codeValidator: codeValidator,
	}
}

// [RFC 6749 Section 4.1.3] Access Token Request
type IssueTokenInput struct {
	GrantType   string // "authorization_code" でなくてはならない
	Code        string
	RedirectURI string
	ClientID    string

	// Section 4.1.3 より、クライアントは認証情報を提供する必要がある
	// 方法は [RFC Section 3.2.1] の方式に従う
	ClientSecret string
}

// [RFC 6749 Section 4.1.4] Access Token Response
type IssueTokenOutput struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	// more parameters can be added if needed
}

func (i *issueTokenInteractor) Execute(ctx context.Context, req IssueTokenInput) (*IssueTokenOutput, error) {
	if req.GrantType != "authorization_code" {
		return nil, ErrUnsupportedGrantType
	}

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return nil, ErrServerError
	}
	client, err := i.clientRepo.FindByID(ctx, clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// クライアント検証（Secret の検証）
	ok, err := i.hasher.Compare(ctx, client.SecretHash(), req.ClientSecret)
	if err != nil {
		return nil, ErrServerError
	}
	if !ok {
		return nil, ErrInvalidClient
	}

	// 認証コードの検証
	authCode, err := i.codeRepo.FindByCode(ctx, req.Code)
	if err != nil {
		// ここで「もし削除済み（既に使用済み）なら関連トークンを Revoke する」ロジックを将来的に追加可能
		return nil, ErrInvalidGrant
	}
  if err := i.codeValidator.Validate(ctx, req.Code, authCode); err != nil {
		return nil, ErrInvalidGrant
	}

	// Redirect URI の検証
	if authCode.RedirectURI() != req.RedirectURI {
		return nil, ErrInvalidGrant
	}

	// 有効期限の確認
	if authCode.IsExpired() {
		return nil, ErrInvalidGrant
	}

	// 認証コードは一度しか使えないため、ここで削除する（[RFC 6749 Section 4.1.2] より）
	if err := i.codeRepo.Delete(ctx, req.Code); err != nil {
		return nil, ErrServerError
	}

	accessToken, err := i.tokenGen.GenerateAccessToken(ctx, clientID, authCode.UserID(), authCode.Scope())
	if err != nil {
		return nil, ErrServerError
	}
	if err := i.tokenRepo.SaveAccessToken(ctx, accessToken); err != nil {
		return nil, ErrServerError
	}

	refreshToken, err := i.tokenGen.GenerateRefreshToken(ctx, clientID, authCode.UserID(), authCode.Scope())
	if err != nil {
		return nil, ErrServerError
	}
	if err := i.tokenRepo.SaveRefreshToken(ctx, refreshToken); err != nil {
		return nil, ErrServerError
	}

	return &IssueTokenOutput{
		AccessToken:  accessToken.Token(),
		TokenType:    "Bearer",
		ExpiresIn:    int64(AccessTokenExpirationTime.Seconds()),
		RefreshToken: refreshToken.Token(),
	}, nil
}
