// https://datatracker.ietf.org/doc/html/rfc7519
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type RegisteredClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

type JWTEncoder interface {
	EncodeCompact(claims RegisteredClaims) (string, error)
}

type JWTHMAC256 struct {
	secret []byte
}

func NewJWTHMAC256(secret []byte) JWTHMAC256 {
	return JWTHMAC256{
		secret: secret,
	}
}

func (j JWTHMAC256) EncodeCompact(claims RegisteredClaims) (string, error) {
	header := "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerBase64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payload)
	signature := headerBase64 + "." + payloadBase64
	mac := hmac.New(sha256.New, j.secret)
	_, err = mac.Write([]byte(signature))
	if err != nil {
		return "", err
	}
	signatureMac := mac.Sum(nil)
	signatureMacBase64 := base64.RawURLEncoding.EncodeToString(signatureMac)

	return headerBase64 + "." + payloadBase64 + "." + signatureMacBase64, nil
}

type JWTRSA256 struct {
	key *rsa.PrivateKey
}

func NewJWTRSA256(key *rsa.PrivateKey) JWTRSA256 {
	return JWTRSA256{
		key: key,
	}
}

func (j JWTRSA256) EncodeCompact(claims RegisteredClaims) (string, error) {
	header := "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerBase64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payload)
	signatureStr := headerBase64 + "." + payloadBase64
	hasher := crypto.SHA256.New()
	_, err = hasher.Write([]byte(signatureStr))
	if err != nil {
		return "", err
	}
	signature, err := rsa.SignPKCS1v15(nil, j.key, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		return "", err
	}
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	return headerBase64 + "." + payloadBase64 + "." + signatureBase64, nil
}

type JWTPSS256 struct {
	key *rsa.PrivateKey
}

func NewJWTPSS256(key *rsa.PrivateKey) JWTPSS256 {
	return JWTPSS256{
		key: key,
	}
}

func (j JWTPSS256) EncodeCompact(claims RegisteredClaims) (string, error) {
	header := "{\"alg\":\"PS256\",\"typ\":\"JWT\"}"
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerBase64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payload)
	signatureStr := headerBase64 + "." + payloadBase64
	hasher := crypto.SHA256.New()
	_, err = hasher.Write([]byte(signatureStr))
	if err != nil {
		return "", err
	}
	signature, err := rsa.SignPSS(rand.Reader, j.key, crypto.SHA256, hasher.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		return "", err
	}
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	return headerBase64 + "." + payloadBase64 + "." + signatureBase64, nil
}
