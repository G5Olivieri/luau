package kms

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"log"

	"github.com/G5Olivieri/luau/jose/jwk"
)

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
	switch k.keySpec.Alg {
	case jwk.KeyAlgRS256, jwk.KeyAlgRS384, jwk.KeyAlgRS512:
		err = rsa.VerifyPKCS1v15(&k.privateKey.PublicKey, hasher, h.Sum(nil), signature)
	case jwk.KeyAlgPS256, jwk.KeyAlgPS384, jwk.KeyAlgPS512:
		err = rsa.VerifyPSS(&k.privateKey.PublicKey, hasher, h.Sum(nil), signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	}

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

	jwkValue := key.JWK()
	jwkValue.E = &eBase64
	jwkValue.N = &nBase64

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

func (key *RSAKey) JWK() jwk.JWK {
	keySpec := key.GetKeySpec()
	kid := key.GetID()
	return jwk.JWK{
		Kty:    "RSA",
		Kid:    &kid,
		Use:    &keySpec.Use,
		Alg:    &keySpec.Alg,
		KeyOps: keySpec.KeyOps,
		// TODO: x5t, x5c, x5u, x5tS256
	}
}
