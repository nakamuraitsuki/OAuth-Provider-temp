package oauth

import (
	"context"

	"github.com/google/uuid"
)

type ClientRepository interface {
	// [RFC 6749 Section 2.2] Client Identifier
	// "The authorization server issues a client identifier" より。
	FindByID(ctx context.Context, id uuid.UUID) (*Client, error)
}
