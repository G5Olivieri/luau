package kms

import (
	"crypto"
	"strings"
)

func getHasherFromString(alg string) (crypto.Hash, error) {
	if strings.HasSuffix(alg, "S256") {
		return crypto.SHA256, nil
	}
	if strings.HasSuffix(alg, "S384") {
		return crypto.SHA384, nil
	}
	if strings.HasSuffix(alg, "S512") {
		return crypto.SHA512, nil
	}
	return crypto.SHA256, ErrInvalidHasher
}
