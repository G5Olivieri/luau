package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

type Generator interface {
	Generate() (string, error)
	Validate(csrfToken string) (bool, error)
}

type HMACGenerator struct {
	secret []byte
}

func NewHMACGenerator(secret []byte) HMACGenerator {
	return HMACGenerator{
		secret: secret,
	}
}

func (g HMACGenerator) Generate() (string, error) {
	randomValue := make([]byte, 32)
	_, err := rand.Read(randomValue)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, g.secret)
	mac.Write(randomValue)
	randomValueMAC := mac.Sum(nil)
	randomValueMACBase64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomValueMAC)
	randomValueBase64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomValue)
	// TODO: add session_id https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#pseudo-code-for-implementing-hmac-csrf-tokens
	return randomValueMACBase64 + "." + randomValueBase64, nil
}

func (g HMACGenerator) Validate(csrfToken string) (bool, error) {
	csrfTokenSplitted := strings.Split(csrfToken, ".")
	if len(csrfTokenSplitted) < 2 {
		return false, fmt.Errorf("Malformatted csrf")
	}
	csrfTokenMACBase64 := csrfTokenSplitted[0]
	csrfTokenMessageBase64 := csrfTokenSplitted[1]
	csrfTokenMAC, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(csrfTokenMACBase64)
	if err != nil {
		return false, err
	}

	csrfTokenMessage, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(csrfTokenMessageBase64)
	if err != nil {
		return false, err
	}

	return validateMAC([]byte(csrfTokenMessage), []byte(csrfTokenMAC), g.secret), nil
}

func validateMAC(message, messageMAC, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(expectedMAC, messageMAC)
}
