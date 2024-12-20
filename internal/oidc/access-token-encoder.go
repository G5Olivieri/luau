package oidc

import (
	"context"
	"time"

	luaujwt "github.com/G5Olivieri/luau/internal/jwt"
	"github.com/G5Olivieri/luau/internal/kms"
)

type AccessTokenRequest struct {
	Sub      string
	Audience []string
}

type AccessTokenPayload struct {
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	Sub      string   `json:"sub"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
}

type AccessTokenEncoder interface {
	ExpiresIn() int64
	Encode(context.Context, AccessTokenRequest) (string, error)
	Decode(context.Context, string) (*AccessTokenPayload, error)
}

type AccessTokenJWTEncoder struct {
	kms       kms.KMS
	issuer    string
	expiresIn int64
	keyID     string
}

func NewAccessTokenJWTEncoder(kmsValue kms.KMS, issuer string, expiresIn int64, keyID string) *AccessTokenJWTEncoder {
	return &AccessTokenJWTEncoder{
		kms:       kmsValue,
		keyID:     keyID,
		issuer:    issuer,
		expiresIn: expiresIn,
	}
}

func (e AccessTokenJWTEncoder) Encode(ctx context.Context, r AccessTokenRequest) (string, error) {
	now := time.Now()
	payload := AccessTokenPayload{
		Issuer:   e.issuer,
		Audience: r.Audience,
		Sub:      r.Sub,
		Iat:      now.Unix(),
		Exp:      now.Add(time.Duration(e.expiresIn) * time.Second).Unix(),
	}
	return luaujwt.EncodeCompact(ctx, e.kms, e.keyID, payload)
}

func (e AccessTokenJWTEncoder) Decode(ctx context.Context, jwtString string) (*AccessTokenPayload, error) {
	var payload *AccessTokenPayload
	err := luaujwt.DecodeCompact(ctx, e.kms, jwtString, payload)
	if err != nil {
		return nil, nil
	}
	return payload, nil
}

func (e AccessTokenJWTEncoder) ExpiresIn() int64 {
	return e.expiresIn
}
