package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/google/uuid"
)

type InMemoryKMS struct {
	keys map[string]Key
}

func NewInMemoryKMS() *InMemoryKMS {
	return &InMemoryKMS{
		keys: make(map[string]Key),
	}
}

func (kms *InMemoryKMS) GenerateKey(ctx context.Context, keySpec KeySpec) (Key, error) {
	// TODO: enc is disabled
	if keySpec.Use != "sig" {
		return nil, ErrInvalidKeyOperation
	}
	// TODO: encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits are disabled
	for _, v := range keySpec.KeyOps {
		if v != "sign" && v != "verify" {
			return nil, ErrInvalidKeyOperation
		}
	}
	switch keySpec.Alg {
	case "HS256", "HS384", "HS512":
		// TODO: secret length from keySpec
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		if err != nil {
			return nil, err
		}
		id := uuid.NewString()
		key := NewHMACKey(id, keySpec, secret)
		kms.keys[id] = key
		return key, nil
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		// TODO: bitsize from keySpec
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		id := uuid.NewString()
		key := NewRSAKey(id, keySpec, privateKey)
		kms.keys[id] = key
		return key, nil
	case "ES256", "ES384", "ES512":
		var (
			privateKey *ecdsa.PrivateKey
			err        error
		)
		switch keySpec.Alg {
		case "ES256":
			privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "ES384":
			privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "ES512":
			privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		}
		if err != nil {
			return nil, err
		}
		id := uuid.NewString()
		key := NewECKey(id, keySpec, privateKey)
		kms.keys[id] = key
		return key, nil
	default:
		return nil, ErrInvalidKeyAlg
	}
}

func (kms *InMemoryKMS) GetPublicKey(ctx context.Context, id string) (interface{}, error) {
	v, ok := kms.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}

	k, ok := v.(symmetric)
	if !ok {
		return nil, ErrInvalidKeyOperation
	}

	return k.GetPublicKey(), nil
}

func (kms InMemoryKMS) Get(ctx context.Context, id string) (Key, error) {
	v, ok := kms.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return v, nil
}

func (kms *InMemoryKMS) Sign(ctx context.Context, id string, message []byte) ([]byte, error) {
	v, ok := kms.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	s, ok := v.(signer)
	if !ok {
		return nil, ErrInvalidKeyOperation
	}
	return s.Sign(message)
}

func (kms InMemoryKMS) Verify(ctx context.Context, id string, message, signature []byte) (bool, error) {
	k, ok := kms.keys[id]
	if !ok {
		return false, ErrKeyNotFound
	}

	v, ok := k.(verifier)
	if !ok {
		return false, ErrInvalidKeyOperation
	}

	return v.Verify(message, signature)
}

func (kms *InMemoryKMS) JWKSPublicKeys() ([]interface{}, error) {
	jwks := make([]interface{}, 0)
	for _, k := range kms.keys {
		if !k.GetKeySpec().HasPublicKey() {
			continue
		}

		e, ok := k.(jwkEncoder)
		if !ok {
			return nil, ErrInvalidKeyOperation
		}

		jwk := e.JWKPublicKey()
		jwks = append(jwks, jwk)
	}
	return jwks, nil
}
