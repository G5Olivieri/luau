package user

type Password interface {
	Verify(password []byte) bool
}

type HashSaltPassword struct {
	hash   []byte
	salt   []byte
	hasher HashSaltPasswordHasher
}

func NewHashSaltPassword(password, salt []byte, hasher HashSaltPasswordHasher) (Password, error) {
	hash := hasher.Hash(password, salt)
	return HashSaltPassword{
		hash:   hash,
		salt:   salt,
		hasher: hasher,
	}, nil
}

func (p HashSaltPassword) Verify(password []byte) bool {
	return p.hasher.Verify([]byte(password), p.hash, p.salt)
}
