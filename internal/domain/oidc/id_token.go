package oidc

import "time"

// [OpenID Connect Core 1.0 section 2] ID Token
type IDToken struct {
	// REQUIRED
	Issuer string
	Subject string
	Audience []string
	ExpiresAt time.Time
	IssuedAt time.Time
	
	// CONDITIONALLY REQUIRED / OPTIONAL
	Nonce string

	Name string // optional claim: user's full name
	// more claims can be added if needed
}

func NewIDToken(sub, aud, iss, nonce, name string, duration time.Duration) *IDToken {
	now := time.Now()
	return &IDToken{
		Issuer: iss,
		Subject: sub,
		Audience: []string{aud},
		ExpiresAt: now.Add(duration),
		IssuedAt: now,
		Nonce: nonce,
		Name: name,
	}
}
