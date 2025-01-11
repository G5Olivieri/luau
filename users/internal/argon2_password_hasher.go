package internal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

var ErrMalFormed = errors.New("mal formed")

type Argon2PasswordHasher struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func (ph Argon2PasswordHasher) Hash(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, ph.time, ph.memory, ph.threads, ph.keyLen)
}

func (ph Argon2PasswordHasher) Verify(password, hash, salt []byte) bool {
	providedPwdHashed := argon2.IDKey(password, salt, ph.time, ph.memory, ph.threads, ph.keyLen)
	return subtle.ConstantTimeCompare(providedPwdHashed, hash) == 1
}

func NewArgon2PasswordHasher(time, memory uint32, threads uint8, keyLen uint32) Argon2PasswordHasher {
	return Argon2PasswordHasher{
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
	}
}

type EncodedArgon2PasswordHasher struct {
	h Argon2PasswordHasher
}

func NewEncodedArgon2PasswordHasher(h Argon2PasswordHasher) EncodedArgon2PasswordHasher {
	return EncodedArgon2PasswordHasher{
		h: h,
	}
}

func (ph EncodedArgon2PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	encodedPassword := base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(ph.h.Hash([]byte(password), salt))
	return encodedPassword, nil
}

func (ph EncodedArgon2PasswordHasher) Verify(password, hash string) (bool, error) {
	decodedHash, salt, err := decodeFromString(hash)

	if err != nil {
		return false, err
	}

	return ph.h.Verify([]byte(password), decodedHash, salt), nil
}

func decodeFromString(encoded string) ([]byte, []byte, error) {
	decoded := strings.Split(encoded, ":")
	if len(decoded) != 2 {
		return nil, nil, ErrMalFormed
	}
	salt := decoded[0]
	hash := decoded[1]
	saltDecoded, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, nil, err
	}

	hashDecoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return nil, nil, err
	}

	return hashDecoded, saltDecoded, nil
}
