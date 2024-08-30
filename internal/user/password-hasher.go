package user

type PasswordHasher interface {
	Hash(password, salt []byte) []byte
	Verify(password, hash, salt []byte) bool
}
