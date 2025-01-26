package internal

import (
	"context"
	"errors"

	"github.com/G5Olivieri/luau/kms"
)

var (
	ErrInvalidKeyAlg       = errors.New("invalid key alg")
	ErrKeyNotFound         = errors.New("key not found")
	ErrBadStoredKey        = errors.New("bad stored key")
	ErrInvalidKeyOperation = errors.New("invalid key operation")
	ErrInvalidHasher       = errors.New("invalid hasher algorithm")
	ErrInvalidSignature    = errors.New("invalid signature")
)

type KMS interface {
	GenerateKey(context.Context, kms.KeySpec) (kms.Key, error)
	GetPublicKey(context.Context, string) (kms.Key, error)
	Get(context.Context, string) (kms.Key, error)
	GetPublicKeys(context.Context, int, int) ([]kms.Key, error)
	List(context.Context, int, int) ([]kms.Key, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	Verify(context.Context, string, []byte, []byte) (bool, error)
	// TODO: Rotate
}
