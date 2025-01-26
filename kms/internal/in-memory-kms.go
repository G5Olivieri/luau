package internal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"

	"github.com/G5Olivieri/luau/kms"
	"github.com/google/uuid"
)

var ErrInvalidLimitOffset = errors.New("invalid limit or offset")

type InMemoryKMS struct {
	keys  map[string]kms.Key
	mutex sync.RWMutex
}

func NewInMemoryKMS() *InMemoryKMS {
	return &InMemoryKMS{
		keys:  make(map[string]kms.Key),
		mutex: sync.RWMutex{},
	}
}

func (inkms *InMemoryKMS) GenerateKey(ctx context.Context, keySpec kms.KeySpec) (kms.Key, error) {
	// TODO: enc is disabled
	if keySpec.Use != "sig" {
		return nil, kms.ErrInvalidKeyOperation
	}
	// TODO: encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits are disabled
	for _, v := range keySpec.KeyOps {
		if v != "sign" && v != "verify" {
			return nil, kms.ErrInvalidKeyOperation
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
		inkms.mutex.Lock()
		inkms.keys[id] = key
		inkms.mutex.Unlock()
		return key, nil
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		// TODO: bitsize from keySpec
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		id := uuid.NewString()
		key := NewRSAKey(id, keySpec, privateKey)
		inkms.mutex.Lock()
		inkms.keys[id] = key
		inkms.mutex.Unlock()
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
		inkms.mutex.Lock()
		inkms.keys[id] = key
		inkms.mutex.Unlock()
		return key, nil
	default:
		return nil, kms.ErrInvalidKeyAlg
	}
}

func (inkms *InMemoryKMS) GetPublicKey(ctx context.Context, id string) (kms.Key, error) {
	inkms.mutex.RLock()
	v, ok := inkms.keys[id]
	inkms.mutex.RUnlock()
	if !ok {
		return nil, kms.ErrKeyNotFound
	}

	k, ok := v.(asymmetric)
	if !ok {
		return nil, kms.ErrInvalidKeyOperation
	}

	return k.GetPublicKey(), nil
}

func (inkms *InMemoryKMS) Get(ctx context.Context, id string) (kms.Key, error) {
	inkms.mutex.RLock()
	v, ok := inkms.keys[id]
	inkms.mutex.RUnlock()
	if !ok {
		return nil, kms.ErrKeyNotFound
	}
	return v, nil
}

func (inkms *InMemoryKMS) Sign(ctx context.Context, id string, message []byte) ([]byte, error) {
	inkms.mutex.RLock()
	v, ok := inkms.keys[id]
	inkms.mutex.RUnlock()
	if !ok {
		return nil, kms.ErrKeyNotFound
	}
	s, ok := v.(signer)
	if !ok {
		return nil, kms.ErrInvalidKeyOperation
	}
	return s.Sign(message)
}

func (inkms *InMemoryKMS) Verify(ctx context.Context, id string, message, signature []byte) (bool, error) {
	inkms.mutex.RLock()
	k, ok := inkms.keys[id]
	inkms.mutex.RUnlock()
	if !ok {
		return false, kms.ErrKeyNotFound
	}

	v, ok := k.(verifier)
	if !ok {
		return false, kms.ErrInvalidKeyOperation
	}

	return v.Verify(message, signature)
}

func (imkms *InMemoryKMS) GetPublicKeys(_ context.Context, limit int, offset int) ([]kms.Key, error) {
	if limit < 0 || offset < 0 {
		return nil, ErrInvalidLimitOffset
	}

	if limit == 0 {
		return make([]kms.Key, 0), nil
	}

	if limit > 1024 {
		limit = 1024
	}

	imkms.mutex.RLock()
	defer imkms.mutex.RUnlock()
	keysLen := len(imkms.keys)
	if offset > keysLen {
		return make([]kms.Key, 0), nil
	}
	response := make([]kms.Key, 0, min(limit, keysLen-offset))
	countOffset := 0
	countLimit := 0
	for _, v := range imkms.keys {
		if !v.GetKeySpec().HasPublicKey() {
			continue
		}
		as, ok := v.(asymmetric)
		if !ok {
			return nil, kms.ErrInvalidKeyOperation
		}

		pkey := as.GetPublicKey()
		countOffset += 1
		if countOffset >= offset {
			response = append(response, pkey)
			countLimit += 1
			if countLimit == limit {
				break
			}
		}
	}

	return response, nil
}

func (imkms *InMemoryKMS) List(_ context.Context, limit int, offset int) ([]kms.Key, error) {
	if limit < 0 || offset < 0 {
		return nil, ErrInvalidLimitOffset
	}
	if limit == 0 {
		return make([]kms.Key, 0), nil
	}

	if limit > 1024 {
		limit = 1024
	}

	imkms.mutex.RLock()
	defer imkms.mutex.RUnlock()
	keysLen := len(imkms.keys)
	if offset > keysLen {
		return nil, nil
	}
	response := make([]kms.Key, 0, min(limit, keysLen-offset))
	countOffset := 0
	countLimit := 0
	for _, v := range imkms.keys {
		countOffset += 1
		if countOffset >= offset {
			response = append(response, v)
			countLimit += 1
			if countLimit == limit {
				break
			}
		}
	}

	return response, nil
}
