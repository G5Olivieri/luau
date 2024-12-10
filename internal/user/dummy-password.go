package user

type DummyPassword struct{}

func NewDummyPassword() Password {
	return DummyPassword{}
}

func (h DummyPassword) Verify(password []byte) bool {
	return false
}
