package oauth

import (
	"example.com/m/internal/usecase/oauth"
)

type OauthHandler struct {
	authorizeUseCase    oauth.AuthorizeUseCase
	issueTokenUseCase   oauth.IssueTokenUseCase
	refreshTokenUseCase oauth.RefreshTokenUseCase
}

func NewOauthHandler(authorizeUseCase oauth.AuthorizeUseCase, issueTokenUseCase oauth.IssueTokenUseCase, refreshTokenUseCase oauth.RefreshTokenUseCase) *OauthHandler {
	return &OauthHandler{
		authorizeUseCase:    authorizeUseCase,
		issueTokenUseCase:   issueTokenUseCase,
		refreshTokenUseCase: refreshTokenUseCase,
	}
}
