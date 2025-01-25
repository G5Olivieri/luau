package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"log"
	"math/big"

	"github.com/G5Olivieri/luau/jose/jwk"
)

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

	jwkValue := key.JWK()
	jwkValue.X = &xBase64
	jwkValue.Y = &yBase64
	jwkValue.Curve = &publicKey.Params().Name

	x5c, err := x509.MarshalPKIXPublicKey(&key.privateKey.PublicKey)

	if err != nil {
		log.Printf("error marshall x509 PKIX public key: %v", err)
		return nil
	}
	jwkValue.X5c = []string{base64.StdEncoding.EncodeToString(x5c)}
	x5t := sha1.Sum(x5c)
	x5tBase64 := base64.RawURLEncoding.EncodeToString(x5t[:])
	jwkValue.X5t = &x5tBase64

	x5tS256 := sha256.Sum256(x5c)
	x5tS256Base64 := base64.RawURLEncoding.EncodeToString(x5tS256[:])
	jwkValue.X5tS256 = &x5tS256Base64

	return &jwkValue
}

func (key *ECKey) JWK() jwk.JWK {
	keySpec := key.GetKeySpec()
	kid := key.GetID()

	return jwk.JWK{
		Kty:    "EC",
		Kid:    &kid,
		Use:    &keySpec.Use,
		Alg:    &keySpec.Alg,
		KeyOps: keySpec.KeyOps,
	}
}
