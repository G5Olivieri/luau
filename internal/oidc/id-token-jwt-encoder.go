package oidc

import (
	"context"
	"time"

	luaujwt "github.com/G5Olivieri/luau/internal/jwt"

	"github.com/G5Olivieri/luau/internal/kms"
)

type IDTokenRequest struct {
	Subject  string
	Audience []string
	AuthTime *time.Time
	Nonce    *string
	Acr      *string
	Amr      *[]string
	Azp      *string
}

type IDToken struct {
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  []string  `json:"aud"`
	ExpiresAt int64     `json:"exp"`
	IssuedAt  int64     `json:"iat"`
	AuthTime  *int64    `json:"auth_time,omitempty"`
	Nonce     *string   `json:"nonce,omitempty"`
	Acr       *string   `json:"acr,omitempty"`
	Amr       *[]string `json:"amr,omitempty"`
	Azp       *string   `json:"azp,omitempty"`
	AtHash    *string   `json:"at_hash,omitempty"`
}

type IDTokenJWTEncoder interface {
	Encode(context.Context, IDTokenRequest) (string, error)
	Decode(context.Context, string) (*IDToken, error)
}

type IDTokenJWTEncoderImpl struct {
	kms       kms.KMS
	issuer    string
	expiresIn int64
	keyID     string
}

func NewIDTokenJWTEncoder(kmsValue kms.KMS, issuer string, expiresIn int64, keyID string) IDTokenJWTEncoderImpl {
	return IDTokenJWTEncoderImpl{
		kms:       kmsValue,
		keyID:     keyID,
		issuer:    issuer,
		expiresIn: expiresIn,
	}
}

func (e IDTokenJWTEncoderImpl) Encode(ctx context.Context, r IDTokenRequest) (string, error) {
	var authTime *int64
	if r.AuthTime != nil {
		p := r.AuthTime.Unix()
		authTime = &p
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(e.expiresIn) * time.Second)
	idToken := IDToken{
		Subject:   r.Subject,
		Issuer:    e.issuer,
		Audience:  r.Audience,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		AuthTime:  authTime,
		Nonce:     r.Nonce,
		Amr:       r.Amr,
		// TODO: acr, azp, AtHash
	}

	return luaujwt.EncodeCompact(ctx, e.kms, e.keyID, idToken)
}

func (e IDTokenJWTEncoderImpl) Decode(ctx context.Context, jwtString string) (*IDToken, error) {
	var payload *IDToken
	if err := luaujwt.DecodeCompact(ctx, e.kms, jwtString, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
