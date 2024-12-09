package oidc

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type IDToken struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	AuthTime  *time.Time
	Nonce     *string
	Acr       *string
	Amr       *string
	Azp       *string
	AtHash    *string
}

type IDTokenAdapter struct {
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	Nonce    *string          `json:"nonce,omitempty"`
	Acr      *string          `json:"acr,omitempty"`
	Amr      *string          `json:"amr,omitempty"`
	Azp      *string          `json:"azp,omitempty"`
	AtHash   *string          `json:"at_hash,omitempty"`
	jwt.RegisteredClaims
}

type IDTokenJWTEncoder interface {
	Encode(idToken IDToken) (string, error)
	Decode(jwtString string) (*IDToken, error)
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

func (e IDTokenJWTEncoderImpl) Encode(idToken IDToken) (string, error) {
	var authTime *jwt.NumericDate
	authTime = nil
	if idToken.AuthTime != nil {
		authTime = jwt.NewNumericDate(*idToken.AuthTime)
	}
	idTokenAdapter := IDTokenAdapter{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   idToken.Subject,
			Issuer:    idToken.Issuer,
			IssuedAt:  jwt.NewNumericDate(idToken.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(idToken.ExpiresAt),
		},
		AuthTime: authTime,
		Nonce:    idToken.Nonce,
		Acr:      idToken.Acr,
		Amr:      idToken.Amr,
		Azp:      idToken.Azp,
		AtHash:   idToken.AtHash,
	}
	token := jwt.NewWithClaims(e.signingMethod, idTokenAdapter)
	signingKey, err := e.keyFunc(nil)
	if err != nil {
		return "", err
	}
	return token.SignedString(signingKey)
}

func (e IDTokenJWTEncoderImpl) Decode(jwtString string) (*IDToken, error) {
	jwtToken, err := jwt.ParseWithClaims(jwtString, &IDTokenAdapter{}, e.keyFunc)
	if err != nil {
		return nil, err
	}
	if claims, ok := jwtToken.Claims.(*IDTokenAdapter); ok {
		issuer, err := claims.GetIssuer()
		if err != nil {
			return nil, err
		}
		subject, err := claims.GetSubject()
		if err != nil {
			return nil, err
		}

		audience, err := claims.GetAudience()
		if err != nil {
			return nil, err
		}

		expiresAt, err := claims.GetExpirationTime()
		if err != nil {
			return nil, err
		}

		issuedAt, err := claims.GetIssuedAt()
		if err != nil {
			return nil, err
		}

		var authTime *time.Time
		authTime = nil
		if claims.AuthTime != nil {
			authTime = &claims.AuthTime.Time
		}

		return &IDToken{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  audience,
			ExpiresAt: expiresAt.Time,
			IssuedAt:  issuedAt.Time,
			AuthTime:  authTime,
			Nonce:     claims.Nonce,
			Acr:       claims.Acr,
			Amr:       claims.Amr,
			Azp:       claims.Azp,
			AtHash:    claims.AtHash,
		}, nil
	}
	return nil, nil
}
