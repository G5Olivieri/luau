package oidc

import (
	"context"
	"time"

	luaujwt "github.com/G5Olivieri/luau/internal/jwt"
	"github.com/G5Olivieri/luau/internal/kms"
)

type RefreshTokenRequest struct {
	Sub      string
	Audience []string
}

type RefreshTokenPayload struct {
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	Sub      string   `json:"sub"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
}

type RefreshTokenEncoder interface {
	Encode(context.Context, RefreshTokenRequest) (string, error)
	Decode(context.Context, string) (*RefreshTokenPayload, error)
}

type RefreshTokenJWTEncoder struct {
	kms       kms.KMS
	issuer    string
	expiresIn int64
	keyID     string
}

func NewRefreshTokenJWTEncoder(kmsValue kms.KMS, issuer string, expiresIn int64, keyID string) *RefreshTokenJWTEncoder {
	return &RefreshTokenJWTEncoder{
		kms:       kmsValue,
		keyID:     keyID,
		issuer:    issuer,
		expiresIn: expiresIn,
	}
}

func (e RefreshTokenJWTEncoder) Encode(ctx context.Context, r RefreshTokenRequest) (string, error) {
	now := time.Now()
	payload := RefreshTokenPayload{
		Issuer:   e.issuer,
		Audience: r.Audience,
		Sub:      r.Sub,
		Iat:      now.Unix(),
		Exp:      now.Add(time.Duration(e.expiresIn) * time.Second).Unix(),
	}
	return luaujwt.EncodeCompact(ctx, e.kms, e.keyID, payload)
}

func (e RefreshTokenJWTEncoder) Decode(ctx context.Context, jwtString string) (*RefreshTokenPayload, error) {
	var payload *RefreshTokenPayload
	err := luaujwt.DecodeCompact(ctx, e.kms, jwtString, payload)
	if err != nil {
		return nil, nil
	}
	return payload, nil
}
