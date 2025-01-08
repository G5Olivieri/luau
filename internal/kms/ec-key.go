package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"math/big"

	"github.com/G5Olivieri/luau/internal/jwk"
)

type ECJWK struct {
	jwk.JWK
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type ECKey struct {
	id         string
	keySpec    KeySpec
	privateKey *ecdsa.PrivateKey
}

func NewECKey(id string, keySpec KeySpec, privateKey *ecdsa.PrivateKey) *ECKey {
	return &ECKey{
		id:         id,
		keySpec:    keySpec,
		privateKey: privateKey,
	}
}

func (k *ECKey) GetID() string {
	return k.id
}

func (k *ECKey) GetKeySpec() KeySpec {
	return k.keySpec
}

func (k *ECKey) GetPublicKey() ecdsa.PublicKey {
	return k.privateKey.PublicKey
}

func (k *ECKey) Sign(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, ErrInvalidKeyOperation
	}

	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return nil, err
	}

	h := hasher.New()
	h.Write(message)
	r, s, err := ecdsa.Sign(rand.Reader, k.privateKey, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	curveBitSize := k.privateKey.Curve.Params().BitSize
	keyByteSize := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyByteSize += 1
	}
	sig := make([]byte, 2*keyByteSize)
	r.FillBytes(sig[0:keyByteSize])
	s.FillBytes(sig[keyByteSize:])
	return sig, nil
}

func (k *ECKey) Verify(message, signature []byte) (bool, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsVerify) {
		return false, ErrInvalidKeyOperation
	}

	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return false, err
	}

	h := hasher.New()
	h.Write(message)
	curveBitSize := k.privateKey.Curve.Params().BitSize
	keyByteSize := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyByteSize += 1
	}
	if len(signature) != 2*keyByteSize {
		return false, ErrInvalidSignature
	}
	rBytes := new(big.Int)
	sBytes := new(big.Int)

	rBytes.SetBytes(signature[:keyByteSize])
	sBytes.SetBytes(signature[keyByteSize : 2*keyByteSize])

	return ecdsa.Verify(&k.privateKey.PublicKey, h.Sum(nil), rBytes, sBytes), nil
}

func (key *ECKey) JWKPublicKey() interface{} {
	publicKey := key.GetPublicKey()
	curveBitSize := publicKey.Curve.Params().BitSize
	keyByteSize := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyByteSize += 1
	}
	xBytes := make([]byte, keyByteSize)
	yBytes := make([]byte, keyByteSize)
	publicKey.X.FillBytes(xBytes)
	publicKey.Y.FillBytes(yBytes)
	xBase64 := base64.RawURLEncoding.EncodeToString(xBytes)
	yBase64 := base64.RawURLEncoding.EncodeToString(yBytes)
	keySpec := key.GetKeySpec()
	kid := key.GetID()
	return &ECJWK{
		X:     xBase64,
		Y:     yBase64,
		Curve: publicKey.Params().Name,
		JWK: jwk.JWK{
			Kty:    "EC",
			Kid:    &kid,
			Use:    &keySpec.Use,
			Alg:    &keySpec.Alg,
			KeyOps: keySpec.KeyOps,
			// TODO: x5t, x5c, x5u, x5tS256
		},
	}
}
