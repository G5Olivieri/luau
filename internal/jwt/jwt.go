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

func EncodeCompact(ctx context.Context, kmsValue kms.KMS, id string, claims interface{}) (string, error) {
	key, err := kmsValue.Get(ctx, id)
	if err != nil {
		return "", err
	}
	header := fmt.Sprintf("{\"alg\":\"%s\",\"typ\":\"JWT\",\"kid\":\"%s\"}", key.KeySpec.Alg, id)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerBase64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payload)
	messageToSign := headerBase64 + "." + payloadBase64
	var signature []byte
	if strings.HasPrefix(key.KeySpec.Alg, "H") {
		signature, err = kmsValue.GenerateMAC(ctx, id, []byte(messageToSign))
	} else {
		signature, err = kmsValue.Sign(ctx, id, []byte(messageToSign))
	}
	if err != nil {
		return "", err
	}
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)
	return messageToSign + "." + signatureBase64, nil
}

func DecodeCompact(ctx context.Context, kmsValue kms.KMS, token string, payload any) error {
	splitted := strings.Split(token, ".")
	if len(splitted) != 3 {
		return ErrMalFormedJWT
	}

	decodedHeader, err := base64.RawURLEncoding.DecodeString(splitted[0])
	if err != nil {
		return err
	}
	var header JoseRegisteredHeader
	if err = json.Unmarshal(decodedHeader, &header); err != nil {
		return err
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(splitted[0])
	if err != nil {
		return err
	}

	if header.Kid != nil {
		return ErrKeyIDNotProvided
	}

	var (
		valid bool
	)

	messageToVerify := splitted[0] + "." + splitted[1]
	signature, err := base64.RawURLEncoding.DecodeString(splitted[2])
	if err != nil {
		return err
	}

	if strings.HasPrefix(header.Alg, "H") {
		valid, err = kmsValue.VerifyMAC(ctx, *header.Kid, []byte(messageToVerify), signature)
	} else {
		valid, err = kmsValue.Verify(ctx, *header.Kid, []byte(messageToVerify), signature)
	}

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
