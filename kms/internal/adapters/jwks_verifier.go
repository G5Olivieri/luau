package adapters

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"

	"github.com/G5Olivieri/luau/jose"
	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/jose/jwt"
)

var (
	ErrJWTKidNotFound   = errors.New("jwt kid not found")
	ErrJWTInvalidAlg    = errors.New("jwt alg is invalid")
	ErrInvalidHasher    = errors.New("invalid hasher algorithm")
	ErrInvalidSignature = errors.New("invalid signature")
)

type JWKSVerifier struct {
	jwks []*jwk.JWK
}

type JWKS struct {
	Jwks []*jwk.JWK `json:"jwks"`
}

func NewJWKSVerifierFromUri(ctx context.Context, uri string) (*JWKSVerifier, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var jwks JWKS
	if err = json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	return NewJWKSVerifier(jwks.Jwks), nil
}

func NewJWKSVerifier(jwks []*jwk.JWK) *JWKSVerifier {
	return &JWKSVerifier{
		jwks: jwks,
	}
}

func (v *JWKSVerifier) Verify(ctx context.Context, header jose.JoseRegisteredHeader, message []byte, signature []byte) (bool, error) {
	var jwkKey *jwk.JWK
	for _, v := range v.jwks {
		if *v.Kid == *header.Kid {
			jwkKey = v
			break
		}
	}

	if jwkKey == nil {
		return false, ErrJWTKidNotFound
	}

	if *jwkKey.Alg != jwk.KeyAlg(header.Alg) {
		return false, ErrJWTInvalidAlg
	}

	var err error

	hasher, err := getHasherFromString(string(*jwkKey.Alg))

	if err != nil {
		return false, err
	}

	switch *jwkKey.Alg {
	case jwk.KeyAlgRS256, jwk.KeyAlgRS384, jwk.KeyAlgRS512, jwk.KeyAlgPS256, jwk.KeyAlgPS384, jwk.KeyAlgPS512:
		if jwkKey.N == nil || jwkKey.E == nil {
			return false, ErrJWTInvalidAlg
		}

		n, err := base64.RawURLEncoding.DecodeString(*jwkKey.N)
		if err != nil {
			return false, ErrJWTInvalidAlg
		}

		e, err := base64.RawURLEncoding.DecodeString(*jwkKey.E)
		if err != nil {
			return false, ErrJWTInvalidAlg
		}
		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}

		h := hasher.New()
		h.Write(message)

		switch *jwkKey.Alg {
		case jwk.KeyAlgRS256, jwk.KeyAlgRS384, jwk.KeyAlgRS512:
			err = rsa.VerifyPKCS1v15(publicKey, hasher, h.Sum(nil), signature)
		case jwk.KeyAlgPS256, jwk.KeyAlgPS384, jwk.KeyAlgPS512:
			err = rsa.VerifyPSS(publicKey, hasher, h.Sum(nil), signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
			})
		}
		if err != nil {
			return false, err
		}
		return true, nil

	case jwk.KeyAlgES256, jwk.KeyAlgES384, jwk.KeyAlgES512:
		if jwkKey.Curve == nil || jwkKey.X == nil || jwkKey.Y == nil {
			return false, ErrJWTInvalidAlg
		}

		x, err := base64.RawURLEncoding.DecodeString(*jwkKey.X)
		if err != nil {
			return false, ErrJWTInvalidAlg
		}

		y, err := base64.RawURLEncoding.DecodeString(*jwkKey.Y)
		if err != nil {
			return false, ErrJWTInvalidAlg
		}

		var curve elliptic.Curve
		switch *jwkKey.Curve {
		case elliptic.P256().Params().Name:
			curve = elliptic.P256()
		case elliptic.P384().Params().Name:
			curve = elliptic.P384()
		case elliptic.P521().Params().Name:
			curve = elliptic.P521()
		}

		publicKey := ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		h := hasher.New()
		h.Write(message)
		curveBitSize := curve.Params().BitSize
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

		return ecdsa.Verify(&publicKey, h.Sum(nil), rBytes, sBytes), nil
	}

	return false, ErrJWTInvalidAlg
}

var _ jwt.Verifier = &JWKSVerifier{}

func getHasherFromString(alg string) (crypto.Hash, error) {
	if strings.HasSuffix(alg, "S256") {
		return crypto.SHA256, nil
	}
	if strings.HasSuffix(alg, "S384") {
		return crypto.SHA384, nil
	}
	if strings.HasSuffix(alg, "S512") {
		return crypto.SHA512, nil
	}
	return crypto.SHA256, ErrInvalidHasher
}
