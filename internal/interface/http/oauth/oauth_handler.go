package oauth

import (
	"example.com/m/internal/usecase/oauth"
)

type OauthHandler struct {
	authorizeUseCase  oauth.AuthorizeUseCase
	issueTokenUseCase oauth.IssueTokenUseCase
}

func NewOauthHandler(authorizeUseCase oauth.AuthorizeUseCase, issueTokenUseCase oauth.IssueTokenUseCase) *OauthHandler {
	return &OauthHandler{
		authorizeUseCase:  authorizeUseCase,
		issueTokenUseCase: issueTokenUseCase,
	}
}
