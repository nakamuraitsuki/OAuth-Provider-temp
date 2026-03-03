package oauth

import "context"

type CodeGenerator interface {
	Generate(ctx context.Context) (string, error)
}

// [RFC6749 Section 4.1.3] Access Token Request
// Token Request において、コードが一致してかつ有効であることを検証する必要がある
type CodeValidator interface {
	Validate(ctx context.Context, inputCode string, stored *AuthorizationCode) error
}