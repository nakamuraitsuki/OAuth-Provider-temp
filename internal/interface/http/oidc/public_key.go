package oidc

import (
	"example.com/m/internal/infrastructure/security/oidc"
	"github.com/labstack/echo/v4"
)

type JWKSHandler struct {
	jwksResonse oidc.JWKSResponse
}

func NewJWKSHandler(jwks oidc.JWKSResponse) *JWKSHandler {
	return &JWKSHandler{
		jwksResonse: jwks,
	}
}

func (h *JWKSHandler) Handle(c echo.Context) error {
	return c.JSON(200, h.jwksResonse)
}
