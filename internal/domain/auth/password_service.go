package auth

import "context"

// PasswordService はパスワードのハッシュ化と検証を行うサービス。
type PasswordService interface {
	Verify(ctx context.Context, plain, hashed string) (bool, error)
	Hash(ctx context.Context, password string) (string, error)
}
