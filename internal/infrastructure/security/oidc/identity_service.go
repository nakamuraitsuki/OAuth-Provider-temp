package oidc

import (
	"context"
	"crypto/rsa"

	"example.com/m/internal/domain/oidc"
	"github.com/golang-jwt/jwt/v5"
)

type identityService struct {
	privateKey *rsa.PrivateKey
	keyID      string
}

func NewIdentityService(key *rsa.PrivateKey, kid string) oidc.IdentityService {
	return &identityService{
		privateKey: key,
		keyID:      kid,
	}
}

func (s *identityService) Sign(ctx context.Context, token *oidc.IDToken) (string, error) {
	claims := jwt.MapClaims{
		"iss": token.Issuer,
		"sub": token.Subject,
		"aud": token.Audience,
		"exp": token.ExpiresAt.Unix(),
		"iat": token.IssuedAt.Unix(),
	}

	if token.Nonce != "" {
		claims["nonce"] = token.Nonce
	}
	if token.Name != "" {
		claims["name"] = token.Name
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	jwtToken.Header["kid"] = s.keyID
	
	signedToken, err := jwtToken.SignedString(s.privateKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
