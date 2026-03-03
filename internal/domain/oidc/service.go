package oidc

import "context"

type IdentityService interface {
	Sign(ctx context.Context, token *IDToken) (string, error)
}

