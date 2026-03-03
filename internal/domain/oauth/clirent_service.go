package oauth

import "context"

type SecretHashService interface {
	Hash(ctx context.Context, secret string) (string, error)
	Compare(ctx context.Context, hash, secret string) (bool, error)
}
