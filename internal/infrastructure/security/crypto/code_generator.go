package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"example.com/m/internal/domain/oauth"
)

type codeGenerator struct{}

func NewCodeGenerator() oauth.CodeGenerator { return &codeGenerator{} }

func (g *codeGenerator) Generate(ctx context.Context) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
