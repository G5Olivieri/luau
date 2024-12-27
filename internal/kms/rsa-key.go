package kms

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"

	"github.com/G5Olivieri/luau/internal/jwk"
)

type RSAJWK struct {
	jwk.JWK
	E string `json:"e"`
	N string `json:"n"`
}

type RSAKey struct {
	id         string
	keySpec    KeySpec
	privateKey *rsa.PrivateKey
}

func NewRSAKey(id string, keySpec KeySpec, privateKey *rsa.PrivateKey) *RSAKey {
	return &RSAKey{
		id:         id,
		keySpec:    keySpec,
		privateKey: privateKey,
	}
}

func (k *RSAKey) GetID() string {
	return k.id
}

func (k *RSAKey) GetKeySpec() KeySpec {
	return k.keySpec
}

func (k *RSAKey) GetPublicKey() rsa.PublicKey {
	return k.privateKey.PublicKey
}

func (k *RSAKey) Sign(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, ErrInvalidKeyOperation
	}

	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return nil, err
	}
	h := hasher.New()
	h.Write(message)
	return rsa.SignPKCS1v15(nil, k.privateKey, hasher, h.Sum(nil))
}

func (k *RSAKey) SignPSS(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, ErrInvalidKeyOperation
	}
	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return nil, err
	}
	h := hasher.New()
	h.Write(message)

	return rsa.SignPSS(rand.Reader, k.privateKey, hasher, h.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

func (k *RSAKey) Verify(message, signature []byte) (bool, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsVerify) {
		return false, ErrInvalidKeyOperation
	}
	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return false, err
	}

	h := hasher.New()
	h.Write(message)
	err = rsa.VerifyPKCS1v15(&k.privateKey.PublicKey, hasher, h.Sum(nil), signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (k *RSAKey) VerifyPSS(message, signature []byte) (bool, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsVerify) {
		return false, ErrInvalidKeyOperation
	}
	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return false, err
	}

	h := hasher.New()
	h.Write(message)
	err = rsa.VerifyPSS(&k.privateKey.PublicKey, hasher, h.Sum(nil), signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})

	if err != nil {
		return false, err
	}

	return true, nil
}

func (key *RSAKey) JWKPublicKey() interface{} {
	publicKey := key.GetPublicKey()
	keyByteSize := publicKey.Size()
	eBytes := make([]byte, 8)
	nBytes := make([]byte, keyByteSize)
	binary.BigEndian.PutUint64(eBytes, uint64(publicKey.E))
	publicKey.N.FillBytes(nBytes)
	eBase64 := base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(eBytes, "\x00"))
	nBase64 := base64.RawURLEncoding.EncodeToString(nBytes)

	keySpec := key.GetKeySpec()
	kid := key.GetID()
	return &RSAJWK{
		E: eBase64,
		N: nBase64,
		JWK: jwk.JWK{
			Kty:    "RSA",
			Kid:    &kid,
			Use:    &keySpec.Use,
			Alg:    &keySpec.Alg,
			KeyOps: keySpec.KeyOps,
		},
	}
}
