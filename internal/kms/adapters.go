package kms

import (
	"context"

	"github.com/G5Olivieri/luau/jose"
	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
)

type JWTSignerAdapter struct {
	kms kms.KMS
	key kms.Key
}

func (s *JWTSignerAdapter) Sign(ctx context.Context, message []byte) ([]byte, error) {
	return s.kms.Sign(ctx, s.key.GetID(), message)
}

func (s *JWTSignerAdapter) GetKeySpec() (*jwk.JWK, error) {
	return s.key.JWK()
}

type JWTVerifierAdapter struct {
	kms kms.KMS
	key kms.Key
}

func (v *JWTVerifierAdapter) Verify(ctx context.Context, header jose.JoseRegisteredHeader, message []byte, signature []byte) (bool, error) {
	if *header.Kid != v.key.GetID() {
		return false, nil
	}
	return v.kms.Verify(ctx, v.key.GetID(), message, signature)
}

func NewJWTSignerAdapterByKeyID(ctx context.Context, kms kms.KMS, id string) (*JWTSignerAdapter, error) {
	key, err := kms.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	return &JWTSignerAdapter{
		kms: kms,
		key: key,
	}, nil
}

func NewJWTVerifierAdapterByKeyID(ctx context.Context, kms kms.KMS, id string) (*JWTVerifierAdapter, error) {
	key, err := kms.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &JWTVerifierAdapter{
		kms: kms,
		key: key,
	}, nil
}
