package http

import (
	"net/http"

	"example.com/m/internal/interface/http/auth"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func InitRoutes(
	e *echo.Echo,
	authHandler *auth.AuthHandler,
) {
	e.GET("/register", authHandler.ShowRegister)
	e.POST("/register", authHandler.Register)
	e.GET("/login", authHandler.ShowLogin)
	e.POST("/login", authHandler.Login)
	e.GET("/dashboard", authHandler.Dashboard)

	// ログイン状態によるリダイレクト分岐
	e.GET("/", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		if sess.Values["user_id"] != nil {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}
		return c.Redirect(http.StatusSeeOther, "/register")
	})
}
