package kms

import (
	"context"
	"errors"
	"slices"

	"github.com/G5Olivieri/luau/jose/jwk"
)

var (
	ErrInvalidKeyAlg       = errors.New("invalid key alg")
	ErrKeyNotFound         = errors.New("key not found")
	ErrBadStoredKey        = errors.New("bad stored key")
	ErrInvalidKeyOperation = errors.New("invalid key operation")
	ErrInvalidHasher       = errors.New("invalid hasher algorithm")
	ErrInvalidSignature    = errors.New("invalid signature")
)

type KeySpec struct {
	Alg    jwk.KeyAlg
	Type   jwk.KeyType
	KeyOps []jwk.KeyOps
	Use    jwk.KeyUse
}

type Key interface {
	GetID() string
	GetKeySpec() KeySpec
	JWK() jwk.JWK
}

func (spec KeySpec) HasOperation(keyOps jwk.KeyOps) bool {
	return slices.Contains(spec.KeyOps, keyOps)
}

func (spec KeySpec) HasPublicKey() bool {
	sortedSupportedAlgs := []jwk.KeyAlg{
		jwk.KeyAlgES256,
		jwk.KeyAlgES384,
		jwk.KeyAlgES512,
		jwk.KeyAlgPS256,
		jwk.KeyAlgPS384,
		jwk.KeyAlgPS512,
		jwk.KeyAlgRS256,
		jwk.KeyAlgRS384,
		jwk.KeyAlgRS512,
	}

	return slices.Contains(sortedSupportedAlgs, spec.Alg)
}

func (spec KeySpec) IsMAC() bool {
	sortedSupportedAlgs := []jwk.KeyAlg{
		jwk.KeyAlgHS256,
		jwk.KeyAlgHS384,
		jwk.KeyAlgHS512,
	}

	return slices.Contains(sortedSupportedAlgs, spec.Alg)
}

type KMS interface {
	GenerateKey(context.Context, KeySpec) (Key, error)
	GetPublicKey(context.Context, string) (interface{}, error)
	Get(context.Context, string) (Key, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	Verify(context.Context, string, []byte, []byte) (bool, error)
	// TODO: Rotate
}
