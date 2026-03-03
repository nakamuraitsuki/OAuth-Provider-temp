package oauth

import "github.com/labstack/echo/v4"

// [RFC6749 5.2] Error Response より
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// 毎回echo.NewHTTPErrorを作るのは冗長なので、ここにヘルパを用意する
func sendError(c echo.Context, code int, errCode string) error {
	return c.JSON(code, OAuthErrorResponse{
		Error: errCode,
	})
}
