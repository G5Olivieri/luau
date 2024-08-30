package user

import (
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

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
