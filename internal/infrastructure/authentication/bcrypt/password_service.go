package bcrypt

import (
	"context"

	"example.com/m/internal/domain/auth"
	"golang.org/x/crypto/bcrypt"
)

type bcryptPasswordService struct{}

func NewBCryptPasswordService() auth.PasswordService {
	return &bcryptPasswordService{}
}

func (s *bcryptPasswordService) Hash(ctx context.Context, password string) (string, error) {
	// コスト（計算負荷）は 10 程度が現在の標準的
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *bcryptPasswordService) Verify(ctx context.Context, plain, hashed string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	if err != nil {
		// パスワード不一致の場合はエラーではなく false を返す
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
