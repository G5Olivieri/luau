package kms

import (
	"crypto/hmac"

	"github.com/G5Olivieri/luau/internal/jwk"
)

type HMACKey struct {
	id      string
	keySpec KeySpec
	secret  []byte
}

func NewHMACKey(id string, keySpec KeySpec, secret []byte) *HMACKey {
	return &HMACKey{
		id:      id,
		keySpec: keySpec,
		secret:  secret,
	}
}

func (k *HMACKey) GetID() string {
	return k.id
}

func (k *HMACKey) GetKeySpec() KeySpec {
	return k.keySpec
}

func (k *HMACKey) Sign(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, ErrInvalidKeyOperation
	}
	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hasher.New, k.secret)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func (k *HMACKey) Verify(message, signature []byte) (bool, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsVerify) {
		return false, ErrInvalidKeyOperation
	}

	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return false, err
	}
	mac := hmac.New(hasher.New, k.secret)
	mac.Write(message)
	macValue := mac.Sum(nil)
	return hmac.Equal(macValue, signature), nil
}
