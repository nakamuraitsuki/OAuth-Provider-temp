package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"example.com/m/internal/usecase/oauth"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

// [RFC6749 3.1] Authorization Endpoint
// GET 対応必須かつ、POST 対応も推奨されている

// GET /oauth/authorize
func (h *OauthHandler) AuthorizationGETEndpoint(c echo.Context) error {
	// RFC6749 では、認証している必要があるが、方法はおまかせとなっている。
	// 今回はCookieをベースとしたセッションで認証確認を行う
	sess, _ := session.Get("session", c)
	userID, ok := sess.Values["user_id"].(string)

	// RFC: 認可サーバはまずソースオーナを認証しなくてはならない
	if !ok || userID == "" {
		// 一時リダイレクトとしてログインページにリダイレクトする
		return c.Redirect(http.StatusSeeOther, "/login?return_to="+c.Request().URL.String())
	}

	// [RFC6749 3.1.2] Authorization Request より
	// query component でRequestは来るはずで、query を抽出するのが適切

	// Scopes はスペース区切りで来るはずなので、 strings.Fields でよしなに扱ってもらう
	requestedScopes := strings.Fields(c.QueryParam("scope"))
	req := oauth.AuthorizeInput{
		ResponseType: c.QueryParam("response_type"),
		ClientID:     c.QueryParam("client_id"),
		RedirectURI:  c.QueryParam("redirect_uri"),
		Scope:        requestedScopes,
		State:        c.QueryParam("state"),
		// 対話によるユーザ認証の結果は、クエリパラメータではなく、クッキーなどから取得するのが適切
	}

	// 先に基本的な形式をチェックしておくと後で楽
	if req.ResponseType != "code" {
		return sendError(c, http.StatusBadRequest, "unsupported_response_type")
	}
	if req.ResponseType == "" || req.ClientID == "" {
		return sendError(c, http.StatusBadRequest, "invalid_request")
	}

	// 認可画面の表示
	return c.Render(http.StatusOK, "authorize.html", map[string]interface{}{
		"ResponseType": req.ResponseType,
		"ClientID":     req.ClientID,
		"RedirectURI":  req.RedirectURI,
		"Scope":        req.Scope,
		"State":        req.State,
		"UserID":       userID,
	})
}

// POST /oauth/authorize
func (h *OauthHandler) AuthorizationPOSTEndpoint(c echo.Context) error {
	sess, _ := session.Get("session", c)
	userID, ok := sess.Values["user_id"].(string)
	if !ok || userID == "" {
		return c.Redirect(http.StatusSeeOther, "/login?return_to="+c.Request().URL.String())
	}

	// 定義はないが、認可画面からのPOSTはhidden field などから受け取る想定
	var req struct {
		ResponseType string `form:"response_type"`
		ClientID     string `form:"client_id"`
		RedirectURI  string `form:"redirect_uri"`
		Scope        string `form:"scope"`
		State        string `form:"state"`
		Action       string `form:"action"` // "approve" or "deny"
	}
	if err := c.Bind(&req); err != nil {
		return sendError(c, http.StatusBadRequest, "invalid_request")
	}

	input := oauth.AuthorizeInput{
		ResponseType: req.ResponseType,
		ClientID:     req.ClientID,
		RedirectURI:  req.RedirectURI,
		Scope:        strings.Fields(req.Scope),
		State:        req.State,
		UserID:       userID,
		IsAuthorized: req.Action == "approve",
	}

	output, err := h.authorizeUseCase.Execute(c.Request().Context(), input)
	if err != nil {
		// client_id や redirect_uri が不正な場合のリダイレクトは明確に禁止されている
		switch err {
		case oauth.ErrUnauthorizedClient:
			return sendError(c, http.StatusUnauthorized, "unauthorized_client")
		case oauth.ErrAccessDenied:
			// usecase 内で、IsAuthorized が false の場合はアクセス拒否エラーを返すようにしているので、ここでリダイレクトする
			// RFC 6749 4.1.2.1
			u, err := url.Parse(req.RedirectURI)
			if err != nil {
				return sendError(c, http.StatusBadRequest, "invalid_redirect_uri")
			}
			q := u.Query()
			q.Set("error", "access_denied")
			q.Set("state", req.State)
			u.RawQuery = q.Encode()
			return c.Redirect(http.StatusFound, u.String())
		case oauth.ErrUnsupportedResponseType:
			return sendError(c, http.StatusBadRequest, "unsupported_response_type")
		default:
			return sendError(c, http.StatusInternalServerError, "server_error")
		}
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return sendError(c, http.StatusBadRequest, "invalid_redirect_uri")
	}

	q := u.Query()
	// [RFC6749 3.1.1] Authorization Response より
	// 結果はクエリパラメータで返す必要がある
	q.Set("code", output.Code)
	// state は OPTIONAL だが、あれば必ず返す必要がある
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	// [RFC6749 ]
	return c.Redirect(http.StatusFound, u.String())
}
