package user

import (
	"slices"

	"example.com/m/internal/usecase/oauth"
	"example.com/m/internal/usecase/user"
	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	userUseCase    user.UserUseCase
	tokenValidater oauth.VerifyTokenUseCase
}

func NewUserHandler(
	userUseCase user.UserUseCase,
	tokenValidater oauth.VerifyTokenUseCase,
) *UserHandler {
	return &UserHandler{
		userUseCase:    userUseCase,
		tokenValidater: tokenValidater,
	}
}

type ProfileResponse struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	UserDisplayName string `json:"user_display_name"`
}

// GET /profile
func (h *UserHandler) GetProfile(c echo.Context) error {
	// RFC: TokenはBearer で渡されるのが一般的と書かれている
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	// "Bearer " プレフィックスを削除
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return c.JSON(401, map[string]string{"error": "Invalid token format"})
	}
	token := authHeader[7:] // "Bearer " は7文字なので、7文字目以降を取得
	if len(token) == 0 {
		return c.JSON(401, map[string]string{"error": "Invalid token format"})
	}

	// トークンの検証
	verifyInput := oauth.VerifyTokenInput{AccessToken: token}
	verifyOutput, err := h.tokenValidater.Execute(c.Request().Context(), verifyInput)
	if err != nil || !verifyOutput.Active {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	if !verifyOutput.Active {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	if verifyOutput.UserID == "" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}
	if verifyOutput.ClientID == "" {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	if !slices.Contains(verifyOutput.Scope, "profile:read") {
		return c.JSON(403, map[string]string{"error": "Forbidden"})
	}

	// ユーザープロフィールの取得
	profile, err := h.userUseCase.GetProfile(c.Request().Context(), verifyOutput.UserID)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Internal Server Error"})
	}

	return c.JSON(200, ProfileResponse{
		UserID:          profile.ID().String(),
		Username:        profile.Username(),
		UserDisplayName: profile.DisplayName(),
	})
}
