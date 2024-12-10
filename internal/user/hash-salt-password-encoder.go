package user

import (
	"encoding/base64"
	"errors"
	"strings"
)

var ErrMalFormed = errors.New("mal formed")

type HashSaltPasswordEncoder struct {
	hasher HashSaltPasswordHasher
}

func (e HashSaltPasswordEncoder) EncodeToString(password HashSaltPassword) (string, error) {
	return "", nil
}

func (e HashSaltPasswordEncoder) DecodeFromString(encoded string) (*HashSaltPassword, error) {
	decoded := strings.Split(encoded, ":")
	if len(decoded) != 2 {
		return nil, ErrMalFormed
	}
	salt := decoded[0]
	hash := decoded[1]
	saltDecoded, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, err
	}

	hashDecoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return nil, err
	}

	return &HashSaltPassword{
		hash:   hashDecoded,
		salt:   saltDecoded,
		hasher: e.hasher,
	}, nil
}
