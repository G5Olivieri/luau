package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
)

type ECPrivateKey struct {
	id         string
	keySpec    kms.KeySpec
	privateKey *ecdsa.PrivateKey
}

type ECPublicKey struct {
	id        string
	keySpec   kms.KeySpec
	publicKey *ecdsa.PublicKey
}

func NewECKey(id string, keySpec kms.KeySpec, privateKey *ecdsa.PrivateKey) *ECPrivateKey {
	return &ECPrivateKey{
		id:         id,
		keySpec:    keySpec,
		privateKey: privateKey,
	}
}

func (k *ECPrivateKey) GetID() string {
	return k.id
}

func (k *ECPrivateKey) GetKeySpec() kms.KeySpec {
	return k.keySpec
}

func (k *ECPrivateKey) GetPublicKey() kms.Key {
	return &ECPublicKey{
		id:        k.id,
		keySpec:   k.keySpec,
		publicKey: &k.privateKey.PublicKey,
	}
}

func (k *ECPrivateKey) Sign(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, kms.ErrInvalidKeyOperation
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

func (k *ECPrivateKey) Verify(message, signature []byte) (bool, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsVerify) {
		return false, kms.ErrInvalidKeyOperation
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
		return false, kms.ErrInvalidSignature
	}
	rBytes := new(big.Int)
	sBytes := new(big.Int)

	rBytes.SetBytes(signature[:keyByteSize])
	sBytes.SetBytes(signature[keyByteSize : 2*keyByteSize])

	return ecdsa.Verify(&k.privateKey.PublicKey, h.Sum(nil), rBytes, sBytes), nil
}

func (k *ECPrivateKey) JWK() (*jwk.JWK, error) {
	privateKey := k.privateKey
	curveBitSize := privateKey.Curve.Params().BitSize
	keyByteSize := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyByteSize += 1
	}
	xBytes := make([]byte, keyByteSize)
	yBytes := make([]byte, keyByteSize)
	order := privateKey.Curve.Params().P

	bitLen := order.BitLen()
	dsize := bitLen / 8
	if bitLen%8 != 0 {
		dsize++
	}

	dBytes := make([]byte, dsize)
	privateKey.D.FillBytes(dBytes)
	privateKey.X.FillBytes(xBytes)
	privateKey.Y.FillBytes(yBytes)

	xBase64 := base64.RawURLEncoding.EncodeToString(xBytes)
	yBase64 := base64.RawURLEncoding.EncodeToString(yBytes)
	dBase64 := base64.RawURLEncoding.EncodeToString(dBytes)

	keySpec := k.GetKeySpec()
	kid := k.GetID()

	jwkValue := jwk.JWK{
		Kty:    "EC",
		Kid:    &kid,
		Use:    &keySpec.Use,
		Alg:    &keySpec.Alg,
		KeyOps: keySpec.KeyOps,
	}
	jwkValue.X = &xBase64
	jwkValue.Y = &yBase64
	jwkValue.Curve = &privateKey.PublicKey.Curve.Params().Name
	jwkValue.D = &dBase64

	x5c, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	if err != nil {
		log.Printf("error marshall x509 PKIX public key: %v", err)
		return nil, err
	}
	jwkValue.X5c = []string{base64.StdEncoding.EncodeToString(x5c)}
	x5t := sha1.Sum(x5c)
	x5tBase64 := base64.RawURLEncoding.EncodeToString(x5t[:])
	jwkValue.X5t = &x5tBase64

	x5tS256 := sha256.Sum256(x5c)
	x5tS256Base64 := base64.RawURLEncoding.EncodeToString(x5tS256[:])
	jwkValue.X5tS256 = &x5tS256Base64

	return &jwkValue, nil
}

func (k *ECPublicKey) GetID() string {
	return k.id
}

func (k *ECPublicKey) GetKeySpec() kms.KeySpec {
	return k.keySpec
}

func (k *ECPublicKey) JWK() (*jwk.JWK, error) {
	publicKey := k.publicKey
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

	keySpec := k.GetKeySpec()
	kid := k.GetID()

	jwkValue := jwk.JWK{
		Kty:    "EC",
		Kid:    &kid,
		Use:    &keySpec.Use,
		Alg:    &keySpec.Alg,
		KeyOps: keySpec.KeyOps,
	}
	jwkValue.X = &xBase64
	jwkValue.Y = &yBase64
	jwkValue.Curve = &publicKey.Curve.Params().Name

	x5c, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {
		log.Printf("error marshall x509 PKIX public key: %v", err)
		return nil, err
	}
	jwkValue.X5c = []string{base64.StdEncoding.EncodeToString(x5c)}
	x5t := sha1.Sum(x5c)
	x5tBase64 := base64.RawURLEncoding.EncodeToString(x5t[:])
	jwkValue.X5t = &x5tBase64

	x5tS256 := sha256.Sum256(x5c)
	x5tS256Base64 := base64.RawURLEncoding.EncodeToString(x5tS256[:])
	jwkValue.X5tS256 = &x5tS256Base64

	return &jwkValue, nil
}

func ECKeyFromJWK(k *jwk.JWK) (kms.Key, error) {
	if !strings.HasPrefix(k.Alg.String(), "ES") {
		return nil, errors.New("invalid jwk is not ec alg")
	}

	if k.X == nil || k.Y == nil || k.Curve == nil {
		return nil, fmt.Errorf("missing fields to map to ec: {x:%v, y:%v,crv:%v}", k.X, k.Y, k.Curve)
	}

	keySpec := kms.KeySpec{
		Alg:    *k.Alg,
		Type:   k.Kty,
		KeyOps: k.KeyOps,
		Use:    *k.Use,
	}

	x, err := base64.RawURLEncoding.DecodeString(*k.X)
	if err != nil {
		return nil, err
	}

	y, err := base64.RawURLEncoding.DecodeString(*k.Y)
	if err != nil {
		return nil, err
	}

	xInt := big.NewInt(0).SetBytes(x)
	yInt := big.NewInt(0).SetBytes(y)

	var crv elliptic.Curve
	switch *k.Curve {
	case elliptic.P256().Params().Name:
		crv = elliptic.P256()
	case elliptic.P384().Params().Name:
		crv = elliptic.P384()
	case elliptic.P521().Params().Name:
		crv = elliptic.P521()
	}

	publicKey := ecdsa.PublicKey{
		X:     xInt,
		Y:     yInt,
		Curve: crv,
	}

	if k.D == nil {
		return &ECPublicKey{
			id:        *k.Kid,
			keySpec:   keySpec,
			publicKey: &publicKey,
		}, nil
	}

	d, err := base64.RawURLEncoding.DecodeString(*k.D)
	if err != nil {
		return nil, err
	}

	dInt := big.NewInt(0).SetBytes(d)

	privateKey := ecdsa.PrivateKey{
		PublicKey: publicKey,
		D:         dInt,
	}

	return NewECKey(*k.Kid, keySpec, &privateKey), nil
}
