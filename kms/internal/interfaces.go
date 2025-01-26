package internal

import "github.com/G5Olivieri/luau/kms"

type signer interface {
	Sign([]byte) ([]byte, error)
}

type verifier interface {
	Verify([]byte, []byte) (bool, error)
}

type asymmetric interface {
	GetPublicKey() kms.Key
}
