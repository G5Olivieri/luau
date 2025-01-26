package internal

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
)

type HMACKey struct {
	id      string
	keySpec kms.KeySpec
	secret  []byte
}

func NewHMACKey(id string, keySpec kms.KeySpec, secret []byte) *HMACKey {
	return &HMACKey{
		id:      id,
		keySpec: keySpec,
		secret:  secret,
	}
}

func (k *HMACKey) GetID() string {
	return k.id
}

func (k *HMACKey) GetKeySpec() kms.KeySpec {
	return k.keySpec
}

func (k *HMACKey) Sign(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, kms.ErrInvalidKeyOperation
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
		return false, kms.ErrInvalidKeyOperation
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

func (key *HMACKey) JWK() (*jwk.JWK, error) {
	keySpec := key.GetKeySpec()
	kid := key.GetID()
	k := base64.RawURLEncoding.EncodeToString(key.secret)

	return &jwk.JWK{
		Kty:    "oct",
		Kid:    &kid,
		Use:    &keySpec.Use,
		Alg:    &keySpec.Alg,
		KeyOps: keySpec.KeyOps,
		K:      &k,
	}, nil
}

func HMACKeyFromJWK(k *jwk.JWK) (*HMACKey, error) {
	if !strings.HasPrefix(k.Alg.String(), "HS") {
		return nil, errors.New("invalid jwk is not hmac alg")
	}

	keySpec := kms.KeySpec{
		Alg:    *k.Alg,
		Type:   k.Kty,
		KeyOps: k.KeyOps,
		Use:    *k.Use,
	}
	secret, err := base64.RawURLEncoding.DecodeString(*k.K)
	if err != nil {
		return nil, err
	}

	return NewHMACKey(*k.Kid, keySpec, secret), nil
}
