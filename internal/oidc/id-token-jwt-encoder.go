package oidc

import (
	"github.com/golang-jwt/jwt/v5"
)

type IDTokenJWTEncoder interface {
	Encode(claims jwt.Claims) (string, error)
	Decode(jwtString string) (*jwt.Token, error)
}

type IDTokenJWTEncoderImpl struct {
	signingMethod jwt.SigningMethod
	keyFunc       func(token *jwt.Token) (interface{}, error)
}

func NewIDTokenJWTEncoder(signingMethod jwt.SigningMethod, keyFunc func(token *jwt.Token) (interface{}, error)) IDTokenJWTEncoderImpl {
	return IDTokenJWTEncoderImpl{
		signingMethod: signingMethod,
		keyFunc:       keyFunc,
	}
}

func (e IDTokenJWTEncoderImpl) Encode(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(e.signingMethod, claims)
	signingKey, err := e.keyFunc(nil)
	if err != nil {
		return "", err
	}
	return token.SignedString(signingKey)
}

func (e IDTokenJWTEncoderImpl) Decode(jwtString string) (*jwt.Token, error) {
	return jwt.Parse(jwtString, e.keyFunc)
}
