package user

type HashSaltPasswordHasher interface {
	Hash(password, salt []byte) []byte
	Verify(password, hash, salt []byte) bool
}
