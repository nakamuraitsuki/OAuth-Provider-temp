package bcrypt

import (
	"context"

	"example.com/m/internal/domain/oauth"
	"golang.org/x/crypto/bcrypt"
)

type secretHashService struct{}

func NewSecretHashService() oauth.SecretHashService { return &secretHashService{} }

func (s *secretHashService) Hash(ctx context.Context, secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *secretHashService) Compare(ctx context.Context, hash, secret string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
