package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/G5Olivieri/luau/internal/session"
)

var ErrInvalidSessionType = errors.New("invalid type for csrf in session")

type HMACDoubleSubmit struct {
	secret     []byte
	cookieName string
	expiresIn  time.Duration
}

func (s HMACDoubleSubmit) Generate(w http.ResponseWriter) (string, error) {
	randomValue := make([]byte, 32)
	_, err := rand.Read(randomValue)

	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(randomValue)
	randomValueMAC := mac.Sum(nil)
	randomValueMACBase64 := base64.RawURLEncoding.EncodeToString(randomValueMAC)
	randomValueBase64 := base64.RawURLEncoding.EncodeToString(randomValue)

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    randomValueMACBase64,
		Expires:  time.Now().Add(s.expiresIn),
		HttpOnly: true,
		Secure:   true,
	})

	return randomValueBase64, nil
}

func (s HMACDoubleSubmit) Validate(value string, r *http.Request) (bool, error) {
	cookieCsrfToken, err := r.Cookie("csrf")

	if err != nil {
		return false, err
	}

	csrfTokenMAC, err := base64.RawURLEncoding.DecodeString(cookieCsrfToken.Value)
	if err != nil {
		return false, err
	}

	csrfTokenMessage, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return false, err
	}

	return validateMAC(csrfTokenMessage, csrfTokenMAC, s.secret), nil
}

func validateMAC(message, messageMAC, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(expectedMAC, messageMAC)
}

type SynchronizerTokenPattern struct {
	httpSession     session.HTTPSession
	csrfSessionName string
}

func NewSynchronizerTokenPattern(
	httpSession session.HTTPSession,
	csrfSessionName string,
) *SynchronizerTokenPattern {
	return &SynchronizerTokenPattern{
		httpSession:     httpSession,
		csrfSessionName: csrfSessionName,
	}
}

func (s *SynchronizerTokenPattern) Generate(sessionValue *session.Session) (string, error) {
	if v, ok := sessionValue.Data[s.csrfSessionName]; ok {
		stringValue, ok := v.(string)
		if !ok {
			return "", ErrInvalidSessionType
		}

		return stringValue, nil
	}

	value := make([]byte, 32)
	_, err := rand.Read(value)
	if err != nil {
		return "", err
	}
	encodedValue := base64.RawURLEncoding.EncodeToString(value)
	sessionValue.Data[s.csrfSessionName] = encodedValue

	return encodedValue, nil
}

func (s *SynchronizerTokenPattern) Validate(value string, sessionValue *session.Session) (bool, error) {
	if sessionValue.Data[s.csrfSessionName] != value {
		return false, nil
	}

	return true, nil
}
