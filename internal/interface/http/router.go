package http

import (
	"net/http"

	"example.com/m/internal/interface/http/auth"
	"example.com/m/internal/interface/http/oauth"
	"example.com/m/internal/interface/http/user"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func InitRoutes(
	e *echo.Echo,
	authHandler *auth.AuthHandler,
	oauthHandler *oauth.OauthHandler,
	userHandler *user.UserHandler,
) {
	e.GET("/register", authHandler.ShowRegister)
	e.POST("/register", authHandler.Register)
	e.GET("/login", authHandler.ShowLogin)
	e.POST("/login", authHandler.Login)
	e.POST("/logout", authHandler.Logout)
	e.GET("/dashboard", authHandler.Dashboard)

	// OAuth2.0のエンドポイント
	e.POST("/oauth/token", oauthHandler.TokenEndpoint)
	e.GET("/oauth/authorize", oauthHandler.AuthorizationGETEndpoint)
	e.POST("/oauth/authorize", oauthHandler.AuthorizationPOSTEndpoint)

	// profile:read スコープが必要なエンドポイントの例
	e.GET("/profile", userHandler.GetProfile)

	// ログイン状態によるリダイレクト分岐
	e.GET("/", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		if sess.Values["user_id"] != nil {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}
		return c.Redirect(http.StatusSeeOther, "/register")
	})
}
