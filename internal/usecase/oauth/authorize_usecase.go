package oauth

import (
	"context"
	"errors"
	"time"

	"example.com/m/internal/domain/oauth"
	"github.com/google/uuid"
)

// [RFC 6749 Section 4.1.2] Authorization Response
// A maximum authorization code lifetime of 10 minutes is RECOMMENDED」
const AuthorizeCodeExpirationTime = 5 * time.Minute

var (
	// [RFC 6749 Section 4.1.2.1] Error Response
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrServerError             = errors.New("server_error")
	ErrTemporarilyUnavailable  = errors.New("temporarily_unavailable")
)

// AuthorizeUseCase は、ブラウザを介したOAuth認可の UseCase
// RFC 6749 の Section 4.1 の (A) (B) (C) に対応する。
type AuthorizeUseCase interface {
	Execute(ctx context.Context, req AuthorizeInput) (*AuthorizeOutput, error)
}

type authorizeInteractor struct {
	clientRepo oauth.ClientRepository
	codeRepo   oauth.AuthorizationCodeRepository
	codeGen    oauth.CodeGenerator
}

func NewAuthorizeInteractor(
	clientRepo oauth.ClientRepository,
	codeRepo oauth.AuthorizationCodeRepository,
	codeGen oauth.CodeGenerator,
) AuthorizeUseCase {
	return &authorizeInteractor{
		clientRepo: clientRepo,
		codeRepo:   codeRepo,
		codeGen:    codeGen,
	}
}

type AuthorizeInput struct {
	// [RFC 6749 Section 4.1.1] Authorization Request
	// Client がブラウザを介して送ってくる認可リクエストのパラメータ
	ResponseType string   // "code" でなくてはならない
	ClientID     string   // クライアントの識別子
	RedirectURI  string   // クライアントが登録したリダイレクトURIのいずれかと完全一致する必要がある
	Scope        []string // クライアントが要求するアクセスの範囲
	State        string   // クライアントが生成したランダムな文字列で、CSRF攻撃を防止するために使用される

	// [RFC 6749 Section 4.1 （B)] 対話によるユーザ認証の結果
	UserID       string // 認証されたユーザの識別子
	IsAuthorized bool   // ユーザがクライアントにアクセスを許可したかどうか

	// OIDC 用
	Nonce string // クライアントが生成したランダムな文字列で、リプレイ攻撃を防止するために使用される
}

type AuthorizeOutput struct {
	// [RFC 6749 Section 4.1.2] Authorization Response
	// 認可リクエストに対するレスポンスのパラメータ
	Code  string // 認可コード。クライアントがアクセストークンを取得するために使用する。
	State string // クライアントがリクエストで送った state と同じ値を返す。CSRF攻撃を防止するために使用される。
}

func (i *authorizeInteractor) Execute(ctx context.Context, req AuthorizeInput) (*AuthorizeOutput, error) {
	// Section 4.1.2.1

	if req.ResponseType != "code" {
		return nil, ErrUnsupportedResponseType
	}

	// クライアントの実在を検証する（A)
	parsedClientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return nil, ErrServerError
	}
	client, err := i.clientRepo.FindByID(ctx, parsedClientID)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}

	// Redirect URI の検証（完全一致）（A)
	if !client.MatchesRedirectURI(req.RedirectURI) {
		return nil, ErrInvalidRequest
	}

	// Scope の検証（A)
	if !client.IsValidScope(req.Scope) {
		return nil, ErrInvalidScope
	}

	// ユーザーの拒否判断（B)
	if !req.IsAuthorized {
		return &AuthorizeOutput{State: req.State}, ErrAccessDenied
	}

	// 認可コードの発行（C)
	code, err := i.codeGen.Generate(ctx)
	if err != nil {
		return nil, ErrServerError
	}

	parsedUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		return nil, ErrServerError
	}
	// 認可コードは Token Endpoint で交換するので、覚えておく
	newAuthorizationCode := oauth.NewAuthorizationCode(
		code,
		parsedClientID,
		parsedUserID,
		req.RedirectURI,
		req.Scope,
		req.State,
		req.Nonce,
		// 現時点から数分後に有効期限が切れるようにする
		time.Now().Add(AuthorizeCodeExpirationTime),
	)
	err = i.codeRepo.Save(ctx, newAuthorizationCode)
	if err != nil {
		return nil, ErrServerError
	}

	return &AuthorizeOutput{
		Code:  code,
		State: req.State,
	}, nil
}
