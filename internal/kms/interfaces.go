package kms

type signer interface {
	Sign([]byte) ([]byte, error)
}

type verifier interface {
	Verify([]byte, []byte) (bool, error)
}

type symmetric interface {
	GetPublicKey() interface{}
}

type jwkEncoder interface {
	JWKPublicKey() interface{}
}
