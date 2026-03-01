package auth

import (
	"context"
	"errors"

	"example.com/m/internal/domain/auth"
	"example.com/m/internal/domain/user"
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
	// 1. Userドメイン: ユーザー名からユーザーを特定
	usr, err := i.userRepo.FindByUsername(ctx, input.Username)
	if err != nil {
		// セキュリティ上、ユーザーが存在しない場合も「認証失敗」として扱う
		return nil, errors.New("invalid username or password")
	}

	// 2. Authドメイン: そのユーザーに紐づく認証情報（ハッシュ等）を取得
	cred, err := i.credentialRepo.FindByUserID(ctx, usr.ID())
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	// 3. Authドメイン(Service): パスワードが一致するか検証
	// エンティティではなく Service に任せることで計算ロジックを分離
	ok, err := i.passwordService.Verify(ctx, input.Password, cred.PasswordHash())
	if err != nil || !ok {
		return nil, errors.New("invalid username or password")
	}

	// 4. 認証成功。呼び出し元（Handler）はこれを受けてセッションを焼く
	return usr, nil
}

func (i *authInteractor) GetIssuer() string {
	return i.issuerURL
}
