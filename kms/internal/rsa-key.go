package internal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	"strings"

	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
)

type RSAPrivateKey struct {
	id         string
	keySpec    kms.KeySpec
	privateKey *rsa.PrivateKey
}

type RSAPublicKey struct {
	id      string
	keySpec kms.KeySpec
	public  *rsa.PublicKey
}

func NewRSAKey(id string, keySpec kms.KeySpec, privateKey *rsa.PrivateKey) *RSAPrivateKey {
	return &RSAPrivateKey{
		id:         id,
		keySpec:    keySpec,
		privateKey: privateKey,
	}
}

func (k *RSAPrivateKey) GetID() string {
	return k.id
}

func (k *RSAPrivateKey) GetKeySpec() kms.KeySpec {
	return k.keySpec
}

func (k *RSAPrivateKey) GetPublicKey() kms.Key {
	return &RSAPublicKey{
		id:      k.id,
		keySpec: k.keySpec,
		public:  &k.privateKey.PublicKey,
	}
}

func (k *RSAPrivateKey) Sign(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, kms.ErrInvalidKeyOperation
	}

	hasher, err := getHasherFromString(string(k.keySpec.Alg))
	if err != nil {
		return nil, err
	}
	h := hasher.New()
	h.Write(message)
	return rsa.SignPKCS1v15(nil, k.privateKey, hasher, h.Sum(nil))
}

func (k *RSAPrivateKey) SignPSS(message []byte) ([]byte, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsSign) {
		return nil, kms.ErrInvalidKeyOperation
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

func (k *RSAPrivateKey) Verify(message, signature []byte) (bool, error) {
	if !k.keySpec.HasOperation(jwk.KeyOpsVerify) {
		return false, kms.ErrInvalidKeyOperation
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

func (key *RSAPrivateKey) JWK() (*jwk.JWK, error) {
	privateKey := key.privateKey
	keyByteSize := privateKey.Size()
	eBytes := make([]byte, 8)
	nBytes := make([]byte, keyByteSize)
	dBytes := privateKey.D.Bytes()

	binary.BigEndian.PutUint64(eBytes, uint64(privateKey.E))
	privateKey.N.FillBytes(nBytes)

	eBase64 := base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(eBytes, "\x00"))
	nBase64 := base64.RawURLEncoding.EncodeToString(nBytes)
	dBase64 := base64.RawURLEncoding.EncodeToString(dBytes)

	keySpec := key.GetKeySpec()
	kid := key.GetID()
	jwkValue := jwk.JWK{
		Kty:    "RSA",
		Kid:    &kid,
		Use:    &keySpec.Use,
		Alg:    &keySpec.Alg,
		KeyOps: keySpec.KeyOps,
		// TODO: x5t, x5c, x5u, x5tS256
	}
	jwkValue.E = &eBase64
	jwkValue.N = &nBase64
	jwkValue.D = &dBase64

	if privateKey.Precomputed.Dp != nil {
		dpBytes := privateKey.Precomputed.Dp.Bytes()
		dpBase64 := base64.RawURLEncoding.EncodeToString(dpBytes)
		jwkValue.Dp = &dpBase64
	}
	if privateKey.Precomputed.Dq != nil {
		dqBytes := privateKey.Precomputed.Dq.Bytes()
		dqBase64 := base64.RawURLEncoding.EncodeToString(dqBytes)
		jwkValue.Dq = &dqBase64
	}
	if privateKey.Precomputed.Qinv != nil {
		qiBytes := privateKey.Precomputed.Qinv.Bytes()
		qiBase64 := base64.RawURLEncoding.EncodeToString(qiBytes)
		jwkValue.Qi = &qiBase64
	}

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

func (k *RSAPublicKey) GetID() string {
	return k.id
}

func (k *RSAPublicKey) GetKeySpec() kms.KeySpec {
	return k.keySpec
}

func (k *RSAPublicKey) GetPublicKey() kms.Key {
	return k
}

func (key *RSAPublicKey) JWK() (*jwk.JWK, error) {
	publicKey := key.public
	keyByteSize := publicKey.Size()
	eBytes := make([]byte, 8)
	nBytes := make([]byte, keyByteSize)
	binary.BigEndian.PutUint64(eBytes, uint64(publicKey.E))
	publicKey.N.FillBytes(nBytes)
	eBase64 := base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(eBytes, "\x00"))
	nBase64 := base64.RawURLEncoding.EncodeToString(nBytes)

	keySpec := key.GetKeySpec()
	kid := key.GetID()
	jwkValue := jwk.JWK{
		Kty:    "RSA",
		Kid:    &kid,
		Use:    &keySpec.Use,
		Alg:    &keySpec.Alg,
		KeyOps: keySpec.KeyOps,
		// TODO: x5t, x5c, x5u, x5tS256
	}
	jwkValue.E = &eBase64
	jwkValue.N = &nBase64

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

func RSAKeyFromJWK(k *jwk.JWK) (kms.Key, error) {
	if !strings.HasPrefix(k.Alg.String(), "RS") {
		return nil, errors.New("invalid jwk is not rsa alg")
	}

	keySpec := kms.KeySpec{
		Alg:    *k.Alg,
		Type:   k.Kty,
		KeyOps: k.KeyOps,
		Use:    *k.Use,
	}

	e, err := base64.RawURLEncoding.DecodeString(*k.E)
	if err != nil {
		return nil, err
	}
	n, err := base64.RawURLEncoding.DecodeString(*k.N)
	if err != nil {
		return nil, err
	}
	nInt := big.NewInt(0).SetBytes(n)

	pad := make([]byte, 8-len(e))
	ebytes := append(pad, e...)
	eint := binary.BigEndian.Uint64(ebytes)

	publicKey := rsa.PublicKey{
		N: nInt,
		E: int(eint),
	}

	if k.D == nil {
		return &RSAPublicKey{
			id:      *k.Kid,
			keySpec: keySpec,
			public:  &publicKey,
		}, nil
	}
	d, err := base64.RawURLEncoding.DecodeString(*k.D)
	if err != nil {
		return nil, err
	}

	dInt := big.NewInt(0).SetBytes(d)
	privateKey := rsa.PrivateKey{
		PublicKey: publicKey,
		D:         dInt,
	}

	var dp []byte
	if k.Dp != nil {
		dp, err = base64.RawURLEncoding.DecodeString(*k.Dp)
		if err != nil {
			return nil, err
		}
	}

	var dq []byte
	if k.Dq != nil {
		dq, err = base64.RawURLEncoding.DecodeString(*k.Dq)
		if err != nil {
			return nil, err
		}
	}

	var qi []byte
	if k.Qi != nil {
		qi, err = base64.RawURLEncoding.DecodeString(*k.Qi)
		if err != nil {
			return nil, err
		}
	}

	if dp != nil && dq != nil && qi != nil {
		dpInt := big.NewInt(0).SetBytes(dp)
		dqInt := big.NewInt(0).SetBytes(dq)
		qiInt := big.NewInt(0).SetBytes(qi)

		privateKey.Precomputed = rsa.PrecomputedValues{
			Dp:   dpInt,
			Dq:   dqInt,
			Qinv: qiInt,
		}
	}

	return NewRSAKey(*k.Kid, keySpec, &privateKey), nil
}
