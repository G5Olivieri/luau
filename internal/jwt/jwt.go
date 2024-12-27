// https://datatracker.ietf.org/doc/html/rfc7519
package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/G5Olivieri/luau/internal/kms"
)

var (
	ErrMalFormedJWT     = errors.New("mal formed jwt")
	ErrKeyIDNotProvided = errors.New("key id not provided")
	ErrInvalidSignature = errors.New("invalid signature")
)

func EncodeCompact(ctx context.Context, kmsValue kms.KMS, id string, claims any) (string, error) {
	key, err := kmsValue.Get(ctx, id)
	if err != nil {
		return "", err
	}
	header := fmt.Sprintf("{\"alg\":\"%s\",\"typ\":\"JWT\",\"kid\":\"%s\"}", key.GetKeySpec().Alg, id)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerBase64 := encodePart([]byte(header))
	payloadBase64 := encodePart(payload)
	messageToSign := headerBase64 + "." + payloadBase64

	signature, err := kmsValue.Sign(ctx, id, []byte(messageToSign))
	if err != nil {
		return "", err
	}

	signatureBase64 := encodePart(signature)
	return messageToSign + "." + signatureBase64, nil
}

func DecodeCompact(ctx context.Context, kmsValue kms.KMS, token string, payload any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrMalFormedJWT
	}

	decodedHeader, err := decodePart(parts[0])
	if err != nil {
		return err
	}

	var header JoseRegisteredHeader
	if err = json.Unmarshal(decodedHeader, &header); err != nil {
		return err
	}

	decodedPayload, err := decodePart(parts[0])
	if err != nil {
		return err
	}

	if header.Kid != nil {
		return ErrKeyIDNotProvided
	}

	messageToVerify := parts[0] + "." + parts[1]
	signature, err := decodePart(parts[2])
	if err != nil {
		return err
	}

	valid, err := kmsValue.Verify(ctx, *header.Kid, []byte(messageToVerify), signature)

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

func encodePart(part []byte) string {
	return base64.RawURLEncoding.EncodeToString(part)
}

func decodePart(part string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(part)
}
