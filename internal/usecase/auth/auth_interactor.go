package auth

import (
	"context"
	"errors"

	"example.com/m/internal/domain/auth"
	"example.com/m/internal/domain/user"
	"github.com/google/uuid"
)

type authInteractor struct {
	userRepo        user.Repository
	credentialRepo  auth.Repository
	passwordService auth.PasswordService
	issuerURL       string
}

func NewAuthInteractor(
	userRepo user.Repository,
	credentialRepo auth.Repository,
	passwordService auth.PasswordService,
	issuerURL string,
) AuthUseCase {
	return &authInteractor{
		userRepo:        userRepo,
		credentialRepo:  credentialRepo,
		passwordService: passwordService,
		issuerURL:       issuerURL,
	}
}

type AuthInput struct {
	Username string
	Password string
}

func (i *authInteractor) Authenticate(ctx context.Context, input AuthInput) (*user.User, error) {
	usr, err := i.userRepo.FindByUsername(ctx, input.Username)
	if err != nil {
		// セキュリティ上、ユーザーが存在しない場合も「認証失敗」として扱う
		return nil, errors.New("invalid username or password")
	}

	cred, err := i.credentialRepo.FindByUserID(ctx, usr.ID())
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	ok, err := i.passwordService.Verify(ctx, input.Password, cred.PasswordHash())
	if err != nil || !ok {
		return nil, errors.New("invalid username or password")
	}

	return usr, nil
}

type RegisterInput struct {
	Username    string
	DisplayName string
	Password    string
}

func (i *authInteractor) Register(ctx context.Context, input RegisterInput) error {
	usr := user.NewUser(uuid.New(), input.Username, input.DisplayName)
	if err := i.userRepo.Save(ctx, usr); err != nil {
		return err
	}

	// 2. パスワードのハッシュ化と保存
	hash, err := i.passwordService.Hash(ctx, input.Password)
	if err != nil {
		return err
	}

	cred := auth.NewPasswordCredential(usr.ID(), hash)
	return i.credentialRepo.Save(ctx, cred)
}

func (i *authInteractor) GetIssuer() string {
	return i.issuerURL
}
