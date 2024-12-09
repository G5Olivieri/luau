package oidc

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type AuthorizationCodeEncoder interface {
	Encode(authorizationCode AuthorizationCode) (string, error)
	Decode(code string) (AuthorizationCode, error)
}

type JWTAuthorizationCodeEncoder struct {
	signingMethod jwt.SigningMethod
	keyFunc       func(token *jwt.Token) (interface{}, error)
}

type AuthorizationCodeClaims struct {
	jwt.RegisteredClaims
}

func NewJWTAuthorizationCodeEncoder(signingMethod jwt.SigningMethod, keyFunc func(token *jwt.Token) (interface{}, error)) JWTAuthorizationCodeEncoder {
	return JWTAuthorizationCodeEncoder{
		signingMethod: signingMethod,
		keyFunc:       keyFunc,
	}
}

func (e JWTAuthorizationCodeEncoder) Encode(authorizationCode AuthorizationCode) (string, error) {
	token := jwt.NewWithClaims(e.signingMethod, jwt.RegisteredClaims{
		Subject:   authorizationCode.UserID,
		ExpiresAt: jwt.NewNumericDate(authorizationCode.Exp),
	})
	signingKey, err := e.keyFunc(nil)
	if err != nil {
		return "", err
	}
	return token.SignedString(signingKey)
}

func (e JWTAuthorizationCodeEncoder) Decode(code string) (AuthorizationCode, error) {
	token, err := jwt.ParseWithClaims(code, &AuthorizationCodeClaims{}, e.keyFunc)
	if err != nil {
		return AuthorizationCode{}, err
	}
	claims, ok := token.Claims.(*AuthorizationCodeClaims)

	if !ok {
		return AuthorizationCode{}, fmt.Errorf("cannot convert jwt claims to authorization code claims")
	}

	return AuthorizationCode{
		UserID: claims.Subject,
		Exp:    claims.ExpiresAt.Time,
	}, nil
}
