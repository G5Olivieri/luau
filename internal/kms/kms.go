package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
)

var (
	ErrInvalidKeyAlg       = errors.New("invalid key alg")
	ErrKeyNotFound         = errors.New("key not found")
	ErrBadStoredKey        = errors.New("bad stored key")
	ErrInvalidKeyOperation = errors.New("invalid key operation")
)

type JWK struct {
	Type   string    `json:"kty"`
	ID     string    `json:"kid"`
	Alg    *string   `json:"alg,omitempty"`
	Use    *string   `json:"use,omitempty"`
	KeyOps *[]string `json:"key_ops,omitempty"`
}

type RSAJWK struct {
	JWK
	E string `json:"e"`
	N string `json:"n"`
}

type ECJWK struct {
	JWK
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type KeySpec struct {
	Alg    string
	Type   string
	KeyOps []string
	Use    string
}

type Key struct {
	ID      string
	KeySpec KeySpec
}

type KMS interface {
	GenerateKey(context.Context, KeySpec) (*Key, error)
	GetPublicKey(context.Context, string) (interface{}, error)
	Get(context.Context, string) (*Key, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	Verify(context.Context, string, []byte, []byte) (bool, error)
	GenerateMAC(context.Context, string, []byte) ([]byte, error)
	VerifyMAC(context.Context, string, []byte, []byte) (bool, error)
}

type internalKey struct {
	key    *Key
	secret interface{}
}

type InMemoryKMS struct {
	keys map[string]*internalKey
}

func NewInMemoryKMS() *InMemoryKMS {
	return &InMemoryKMS{
		keys: make(map[string]*internalKey),
	}
}

func (kms *InMemoryKMS) GenerateKey(ctx context.Context, keySpec KeySpec) (*Key, error) {
	key := &Key{
		ID:      uuid.NewString(),
		KeySpec: keySpec,
	}
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
		kms.keys[key.ID] = &internalKey{key: key, secret: secret}
		return key, nil
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		// TODO: bitsize from keySpec
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		kms.keys[key.ID] = &internalKey{key: key, secret: privateKey}
		return key, nil
	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		kms.keys[key.ID] = &internalKey{key: key, secret: privateKey}
		return key, nil
	case "ES384":
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		kms.keys[key.ID] = &internalKey{key: key, secret: privateKey}
		return key, nil
	case "ES512":
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
		kms.keys[key.ID] = &internalKey{key: key, secret: privateKey}
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
	switch v.key.KeySpec.Alg {
	case "HS256", "HS384", "HS512":
		return nil, ErrInvalidKeyOperation
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		privateKey, ok := v.secret.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrBadStoredKey
		}
		return privateKey.PublicKey, nil
	case "ES256", "ES384", "ES512":
		privateKey, ok := v.secret.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrBadStoredKey
		}
		return privateKey.PublicKey, nil
	default:
		return nil, ErrInvalidKeyAlg
	}
}

func (kms InMemoryKMS) Get(ctx context.Context, id string) (*Key, error) {
	v, ok := kms.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return v.key, nil
}

func (kms *InMemoryKMS) Sign(ctx context.Context, id string, message []byte) ([]byte, error) {
	v, ok := kms.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	switch v.key.KeySpec.Alg {
	case "HS256", "HS384", "HS512":
		return nil, ErrInvalidKeyOperation
	case "RS256":
		return kms.rsaSign(v.secret, crypto.SHA256, message)
	case "RS384":
		return kms.rsaSign(v.secret, crypto.SHA384, message)
	case "RS512":
		return kms.rsaSign(v.secret, crypto.SHA512, message)
	case "PS256":
		return kms.rsaSignPSS(v.secret, crypto.SHA256, message)
	case "PS384":
		return kms.rsaSignPSS(v.secret, crypto.SHA384, message)
	case "PS512":
		return kms.rsaSignPSS(v.secret, crypto.SHA512, message)
	case "ES256":
		return kms.ecdsaSign(v.secret, crypto.SHA256, message)
	case "ES384":
		return kms.ecdsaSign(v.secret, crypto.SHA384, message)
	case "ES512":
		return kms.ecdsaSign(v.secret, crypto.SHA512, message)
	default:
		return nil, ErrInvalidKeyAlg
	}
}

func (kms InMemoryKMS) rsaSign(secret interface{}, hasher crypto.Hash, message []byte) ([]byte, error) {
	privateKey, ok := secret.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrBadStoredKey
	}
	h := hasher.New()
	h.Write(message)
	return rsa.SignPKCS1v15(nil, privateKey, hasher, h.Sum(nil))
}

func (kms InMemoryKMS) rsaSignPSS(secret interface{}, hasher crypto.Hash, message []byte) ([]byte, error) {
	privateKey, ok := secret.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrBadStoredKey
	}
	h := hasher.New()
	h.Write(message)
	return rsa.SignPSS(rand.Reader, privateKey, hasher, h.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

func (kms InMemoryKMS) ecdsaSign(secret interface{}, hasher crypto.Hash, message []byte) ([]byte, error) {
	privateKey, ok := secret.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrBadStoredKey
	}
	h := hasher.New()
	h.Write(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	curveBitSize := privateKey.Curve.Params().BitSize
	keyByteSize := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyByteSize += 1
	}
	sig := make([]byte, 2*keyByteSize)
	r.FillBytes(sig[0:keyByteSize])
	s.FillBytes(sig[keyByteSize:])
	return sig, nil
}

func (kms InMemoryKMS) Verify(context.Context, string, []byte, []byte) (bool, error) {
	return false, nil
}

func (kms *InMemoryKMS) GenerateMAC(ctx context.Context, id string, message []byte) ([]byte, error) {
	key, ok := kms.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	var hash crypto.Hash
	switch key.key.KeySpec.Alg {
	case "HS256":
		hash = crypto.SHA256
	case "HS384":
		hash = crypto.SHA384
	case "HS512":
		hash = crypto.SHA512
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return nil, ErrInvalidKeyOperation
	default:
		return nil, ErrInvalidKeyAlg
	}

	v, ok := key.secret.([]byte)
	if !ok {
		return nil, ErrBadStoredKey
	}
	mac := hmac.New(hash.New, v)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func (kms *InMemoryKMS) VerifyMAC(ctx context.Context, id string, message, signature []byte) (bool, error) {
	key, ok := kms.keys[id]
	if !ok {
		return false, ErrKeyNotFound
	}
	var hash crypto.Hash
	switch key.key.KeySpec.Alg {
	case "HS256":
		hash = crypto.SHA256
	case "HS384":
		hash = crypto.SHA384
	case "HS512":
		hash = crypto.SHA512
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return false, ErrInvalidKeyOperation
	default:
		return false, ErrInvalidKeyAlg
	}
	v, ok := key.secret.([]byte)
	if !ok {
		return false, ErrBadStoredKey
	}
	mac := hmac.New(hash.New, v)
	mac.Write(message)
	macValue := mac.Sum(nil)
	return hmac.Equal(macValue, signature), nil
}

func (kms *InMemoryKMS) JWK(id string) (interface{}, error) {
	key, ok := kms.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}

	switch key.key.KeySpec.Alg {
	case "HS256", "HS384", "HS512":
		return nil, ErrInvalidKeyOperation
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return kms.rsaJWK(key)
	case "ES256", "ES384", "ES512":
		return kms.ecJWK(key)
	default:
		return nil, ErrInvalidKeyAlg
	}
}

func (kms *InMemoryKMS) rsaJWK(key *internalKey) (interface{}, error) {
	privateKey, ok := key.secret.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrBadStoredKey
	}

	publicKey := privateKey.PublicKey
	keyByteSize := publicKey.Size()
	eBytes := make([]byte, 8)
	nBytes := make([]byte, keyByteSize)
	binary.BigEndian.PutUint64(eBytes, uint64(publicKey.E))
	publicKey.N.FillBytes(nBytes)
	eBase64 := base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(eBytes, "\x00"))
	nBase64 := base64.RawURLEncoding.EncodeToString(nBytes)
	return &RSAJWK{
		E: eBase64,
		N: nBase64,
		JWK: JWK{
			Type:   "RSA",
			ID:     key.key.ID,
			Use:    &key.key.KeySpec.Use,
			Alg:    &key.key.KeySpec.Alg,
			KeyOps: &key.key.KeySpec.KeyOps,
		},
	}, nil
}

func (kms *InMemoryKMS) ecJWK(key *internalKey) (interface{}, error) {
	privateKey, ok := key.secret.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrBadStoredKey
	}

	publicKey := privateKey.PublicKey
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
	return &ECJWK{
		X:     xBase64,
		Y:     yBase64,
		Curve: publicKey.Params().Name,
		JWK: JWK{
			Type:   "EC",
			ID:     key.key.ID,
			Use:    &key.key.KeySpec.Use,
			Alg:    &key.key.KeySpec.Alg,
			KeyOps: &key.key.KeySpec.KeyOps,
		},
	}, nil
}

func (kms *InMemoryKMS) JWKS() (interface{}, error) {
	jwks := make([]interface{}, 0)
	for i, _ := range kms.keys {
		jwk, err := kms.JWK(i)
		if errors.Is(err, ErrInvalidKeyOperation) {
			continue
		}
		if err != nil {
			return nil, err
		}
		jwks = append(jwks, jwk)
	}
	return jwks, nil
}
