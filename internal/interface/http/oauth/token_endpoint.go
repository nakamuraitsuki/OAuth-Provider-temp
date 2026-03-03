package oauth

import (
	"net/http"

	"example.com/m/internal/usecase/oauth"
	"github.com/labstack/echo/v4"
)

// [RFC6749 3.2] TokenEndpoint
// POST /oauth/token
func (h *OauthHandler) TokenEndpoint(c echo.Context) error {
	// [RFC6749 4.1.3] Access Token Request より
	// application/x-www-form-urlencodedでRequestは来るはずで、
	// DTO タグは form が適切
	var req struct {
		GrantType    string `form:"grant_type"`
		RefreshToken string `form:"refresh_token"` // [RFC6749 6] Refresh Token Grant より
		Code         string `form:"code"`
		RedirectURI  string `form:"redirect_uri"`
		ClientID     string `form:"client_id"`
		ClientSecret string `form:"client_secret"`
		Scope        string `form:"scope"` // [RFC6749 6] Refresh Token Grant より
	}
	if err := c.Bind(&req); err != nil {
		return sendError(c, http.StatusBadRequest, "invalid_request")
	}

	// [RFC6749 2.3.1] Client Authentication より
	// クライアント認証は、Basic認証ヘッダが基本。もしダメな場合のみBodyを使う
	var finalClientID, finalClientSecret string

	clientID, clientSecret, ok := c.Request().BasicAuth()
	if ok {
		finalClientID = clientID
		finalClientSecret = clientSecret

		// ２つの認証方式の併用は、[RFC6749 2.3] の最後で禁止されている
		// よって、Basicがありつつ、Bodyにもクライアント認証情報があったらエラー
		if req.ClientID != "" || req.ClientSecret != "" {
			return sendError(c, http.StatusBadRequest, "invalid_request")
		}
	} else {
		finalClientID = req.ClientID
		finalClientSecret = req.ClientSecret
	}

	if req.GrantType == "refresh_token" {
		// [RFC6749 6] Refresh Token Grant より
		if req.RefreshToken == "" {
			return sendError(c, http.StatusBadRequest, "invalid_request")
		}
		input := oauth.RefreshTokenInput{
			RefreshToken: req.RefreshToken,
			Scope:        req.Scope,
		}
		output, err := h.refreshTokenUseCase.Execute(c.Request().Context(), input)
		if err != nil {
			switch err {
			case oauth.ErrInvalidToken:
				return sendError(c, http.StatusBadRequest, "invalid_grant")
			default:
				return sendError(c, http.StatusInternalServerError, "server_error")
			}
		}
		return c.JSON(http.StatusOK, output)
	}

	input := oauth.IssueTokenInput{
		GrantType:    req.GrantType,
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
		ClientID:     finalClientID,
		ClientSecret: finalClientSecret,
	}

	output, err := h.issueTokenUseCase.Execute(c.Request().Context(), input)
	if err != nil {
		switch err {
		case oauth.ErrInvalidGrant:
			return sendError(c, http.StatusBadRequest, "invalid_grant")
		case oauth.ErrUnauthorizedClient:
			return sendError(c, http.StatusUnauthorized, "unauthorized_client")
		case oauth.ErrAccessDenied:
			return sendError(c, http.StatusForbidden, "access_denied")
		case oauth.ErrUnsupportedResponseType:
			return sendError(c, http.StatusBadRequest, "unsupported_response_type")
		default:
			return sendError(c, http.StatusInternalServerError, "server_error")
		}
	}

	var res struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"` // Refresh Token は、もし発行される場合のみ返す
		IDToken      string `json:"id_token,omitempty"`      // OIDC の ID Token も、もし発行される場合のみ返す
	}
	
	res.AccessToken = output.AccessToken
	res.TokenType = output.TokenType
	res.ExpiresIn = output.ExpiresIn
	res.RefreshToken = output.RefreshToken
	if output.IDToken != "" {
		res.IDToken = output.IDToken
	}
	return c.JSON(http.StatusOK, res)
}