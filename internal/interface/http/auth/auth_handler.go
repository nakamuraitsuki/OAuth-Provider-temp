package auth

import (
	"net/http"

	"example.com/m/internal/usecase/auth"
	"example.com/m/internal/usecase/user"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	authUC auth.AuthUseCase
	userUC user.UserUseCase
}

func NewAuthHandler(
	authUC auth.AuthUseCase,
	userUC user.UserUseCase,
) *AuthHandler {
	return &AuthHandler{
		authUC: authUC,
		userUC: userUC,
	}
}

// ShowRegister: GET /register
func (h *AuthHandler) ShowRegister(c echo.Context) error {
	return c.Render(http.StatusOK, "register.html", map[string]interface{}{
		"Issuer": h.authUC.GetIssuer(),
	})
}

// Register: POST /register
func (h *AuthHandler) Register(c echo.Context) error {
	var req struct {
		Username    string `form:"username"`
		Password    string `form:"password"`
		DisplayName string `form:"display_name"`
	}
	if err := c.Bind(&req); err != nil {
		return c.Redirect(http.StatusSeeOther, "/register?error=invalid_input")
	}

	err := h.authUC.Register(c.Request().Context(), auth.RegisterInput{
		Username:    req.Username,
		Password:    req.Password,
		DisplayName: req.DisplayName,
	})

	if err != nil {
		return c.Redirect(http.StatusSeeOther, "/register?error=conflict")
	}

	return c.Redirect(http.StatusSeeOther, "/login?registered=true")
}

// ShowLogin: GET /login
func (h *AuthHandler) ShowLogin(c echo.Context) error {
	returnTo := c.QueryParam("return_to")
	return c.Render(http.StatusOK, "login.html", map[string]interface{}{
		"Issuer": h.authUC.GetIssuer(),
		"ReturnTo": returnTo,
	})
}

// Login: POST /login
func (h *AuthHandler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.Redirect(http.StatusSeeOther, "/login?error=invalid_input")
	}

	user, err := h.authUC.Authenticate(c.Request().Context(), auth.AuthInput{
		Username: req.Username,
		Password: req.Password,
	})

	if err != nil {
		return c.Redirect(http.StatusSeeOther, "/login?error=unauthorized")
	}

	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   false, // if productive, set to true
		SameSite: http.SameSiteLaxMode,
	}

	sess.Values["user_id"] = user.ID().String()
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return err
	}

	returnTo := c.QueryParam("return_to")
	if returnTo == "" {
		returnTo = "/dashboard"
	}
	return c.Redirect(http.StatusSeeOther, returnTo)
}

// Logout: POST /logout
func (h *AuthHandler) Logout(c echo.Context) error {
	sess, _ := session.Get("session", c)

	// セッションの中身を空にする、あるいはオプションで有効期限をマイナスにする
	sess.Options.MaxAge = -1
	sess.Values = make(map[interface{}]interface{})

	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to logout")
	}

	// ログイン画面やトップページへリダイレクト
	return c.Redirect(http.StatusSeeOther, "/register")
}

// Dashboard: GET /dashboard
func (h *AuthHandler) Dashboard(c echo.Context) error {
	sess, _ := session.Get("session", c)
	userID, ok := sess.Values["user_id"].(string)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/register")
	}

	user, err := h.userUC.GetProfile(c.Request().Context(), userID)
	if err != nil {
		return c.Redirect(http.StatusSeeOther, "/register")
	}

	res := UserResponse{
		ID:          user.ID().String(),
		DisplayName: user.DisplayName(),
	}

	return c.Render(http.StatusOK, "dashboard.html", map[string]interface{}{
		"User": res,
	})
}
