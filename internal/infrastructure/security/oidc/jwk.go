package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWK は RFC7517で定義されたJSON Web Keyを表す構造体です。
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

func NewJWKSResonse(key *rsa.PrivateKey, kid string) JWKSResponse {
	pub := key.PublicKey

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())

	eBuf := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBuf)

	return JWKSResponse{
		Keys: []JWK{
			{
				Kid: kid,
				Kty: "RSA",
				Use: "sig",
				N:   n,
				E:   e,
			},
		},
	}
}
