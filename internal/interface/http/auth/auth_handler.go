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

// ShowLogin: GET /login
func (h *AuthHandler) ShowLogin(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", map[string]interface{}{
		"Issuer": h.authUC.GetIssuer(),
	})
}

// Login: POST /login
func (h *AuthHandler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.Redirect(http.StatusSeeOther, "login?error=invalid_input")
	}

	user, err := h.authUC.Authenticate(c.Request().Context(), auth.AuthInput{
		Username: req.Username,
		Password: req.Password,
	})

	if err != nil {
		return c.Redirect(http.StatusSeeOther, "login?error=unauthorized")
	}

	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
		Secure:   false, // if productive, set to true
		SameSite: http.SameSiteLaxMode,
	}

	sess.Values["user_id"] = user.ID
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, "/dashboard")
}

// Dashboard: GET /dashboard
func (h *AuthHandler) Dashboard(c echo.Context) error {
	sess, _ := session.Get("session", c)
	userID, ok := sess.Values["user_id"].(string)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	user, err := h.userUC.GetProfile(c.Request().Context(), userID)
	if err != nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	res := UserResponse{
		ID:          user.ID(),
		DisplayName: user.DisplayName(),
	}

	return c.Render(http.StatusOK, "dashboard.html", map[string]interface{}{
		"User": res,
	})
}
