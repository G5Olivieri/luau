package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
)

type Generator interface {
	Generate() (string, string, error)
	Validate(csrfTokenForm string, csrfTokenCookie string) (bool, error)
}

type HMACGenerator struct {
	secret []byte
}

func NewHMACGenerator(secret []byte) HMACGenerator {
	return HMACGenerator{
		secret: secret,
	}
}

func (g HMACGenerator) Generate() (string, string, error) {
	randomValue := make([]byte, 32)
	_, err := rand.Read(randomValue)
	if err != nil {
		return "", "", err
	}
	mac := hmac.New(sha256.New, g.secret)
	mac.Write(randomValue)
	randomValueMAC := mac.Sum(nil)
	randomValueMACBase64 := base64.RawURLEncoding.EncodeToString(randomValueMAC)
	randomValueBase64 := base64.RawURLEncoding.EncodeToString(randomValue)
	return randomValueBase64, randomValueMACBase64, nil
}

func (g HMACGenerator) Validate(csrfTokenForm string, csrfTokenCookie string) (bool, error) {
	log.Printf("validate %s %s\n", csrfTokenForm, csrfTokenCookie)
	csrfTokenMAC, err := base64.RawURLEncoding.DecodeString(csrfTokenCookie)
	if err != nil {
		return false, err
	}

	csrfTokenMessage, err := base64.RawURLEncoding.DecodeString(csrfTokenForm)
	if err != nil {
		return false, err
	}

	return validateMAC(csrfTokenMessage, csrfTokenMAC, g.secret), nil
}

func validateMAC(message, messageMAC, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(expectedMAC, messageMAC)
}
