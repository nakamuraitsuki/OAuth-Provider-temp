package oauth

import (
	"context"

	"github.com/google/uuid"
)

type TokenGenerator interface {
	GenerateAccessToken(ctx context.Context, clientID, userID uuid.UUID, scope []string) (*AccessToken, error)
	GenerateRefreshToken(ctx context.Context, clientID, userID uuid.UUID, scope []string) (*RefreshToken, error)
}

type CredentialService interface {
	SecureCompare(ctx context.Context, safe, input string) bool
}
