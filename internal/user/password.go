package user

import (
	"crypto/rand"
)

type Password struct {
	hash   []byte
	salt   []byte
	hasher PasswordHasher
}

func NewPassword(password []byte, hasher PasswordHasher) (Password, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return Password{}, err
	}
	hash := hasher.Hash(password, salt)
	return Password{
		hash:   hash,
		salt:   salt,
		hasher: hasher,
	}, nil
}

func (p Password) Verify(password []byte) bool {
	return p.hasher.Verify([]byte(password), p.hash, p.salt)
}
