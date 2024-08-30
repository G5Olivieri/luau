package user

type DummyPasswordHasher struct{}

func (h DummyPasswordHasher) Hash(password, salt []byte) []byte {
	return make([]byte, 0)
}

func (h DummyPasswordHasher) Verify(password, hash, salt []byte) bool {
	return false
}

func NewDummyPasswordHasher() DummyPasswordHasher {
	return DummyPasswordHasher{}
}

func NewDummyPassword() Password {
	return Password{
		hash:   make([]byte, 0),
		salt:   make([]byte, 0),
		hasher: NewDummyPasswordHasher(),
	}
}
