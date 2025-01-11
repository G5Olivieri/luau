// https://datatracker.ietf.org/doc/html/rfc7519
package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/G5Olivieri/luau/jose"
	"github.com/G5Olivieri/luau/jose/jwk"
)

var (
	ErrMalFormedJWT     = errors.New("mal formed jwt")
	ErrKeyIDNotProvided = errors.New("key id not provided")
	ErrInvalidSignature = errors.New("invalid signature")
)

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
	GetKeySpec() jwk.JWK
}

type Verifier interface {
	Verify(context.Context, jose.JoseRegisteredHeader, []byte, []byte) (bool, error)
}

func EncodeCompact(ctx context.Context, signer Signer, claims any) (string, error) {
	// TODO: verify more field in header
	header := fmt.Sprintf("{\"alg\":\"%s\",\"typ\":\"JWT\",\"kid\":\"%s\"}", *signer.GetKeySpec().Alg, *signer.GetKeySpec().Kid)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerBase64 := encodePart([]byte(header))
	payloadBase64 := encodePart(payload)
	messageToSign := headerBase64 + "." + payloadBase64

	signature, err := signer.Sign(ctx, []byte(messageToSign))
	if err != nil {
		return "", err
	}

	signatureBase64 := encodePart(signature)
	return messageToSign + "." + signatureBase64, nil
}

func DecodeCompact(ctx context.Context, verifier Verifier, token string, payload any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrMalFormedJWT
	}

	decodedHeader, err := decodePart(parts[0])
	if err != nil {
		return err
	}

	var header jose.JoseRegisteredHeader
	if err = json.Unmarshal(decodedHeader, &header); err != nil {
		return err
	}

	decodedPayload, err := decodePart(parts[0])
	if err != nil {
		return err
	}

	if header.Kid == nil {
		return ErrKeyIDNotProvided
	}

	messageToVerify := parts[0] + "." + parts[1]
	signature, err := decodePart(parts[2])
	if err != nil {
		return err
	}

	valid, err := verifier.Verify(ctx, header, []byte(messageToVerify), signature)

	if err != nil {
		return err
	}

	if !valid {
		return ErrInvalidSignature
	}

	if err = json.Unmarshal(decodedPayload, payload); err != nil {
		return err
	}

	return nil
}

func VerifySignatureCompact(ctx context.Context, verifier Verifier, token string) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, ErrMalFormedJWT
	}

	decodedHeader, err := decodePart(parts[0])
	if err != nil {
		return false, err
	}

	var header jose.JoseRegisteredHeader
	if err = json.Unmarshal(decodedHeader, &header); err != nil {
		return false, err
	}

	if header.Kid == nil {
		return false, ErrKeyIDNotProvided
	}

	messageToVerify := parts[0] + "." + parts[1]
	signature, err := decodePart(parts[2])
	if err != nil {
		return false, err
	}

	return verifier.Verify(ctx, header, []byte(messageToVerify), signature)
}

func encodePart(part []byte) string {
	return base64.RawURLEncoding.EncodeToString(part)
}

func decodePart(part string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(part)
}
