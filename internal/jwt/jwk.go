// https://datatracker.ietf.org/doc/html/rfc7517
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

type JWK struct {
	Kty     string   `json:"kty"`
	Use     *string  `json:"use"`
	KeyOps  []string `json:"key_ops"`
	Alg     *string  `json:"alg"`
	Kid     *string  `json:"kid"`
	X5u     *URI     `json:"x5u"`
	X5c     []string `json:"x5c"`
	X5t     *string  `json:"x5t"`
	X5tS256 *string  `json:"x5t#S256"`
}

type KeyUsage []string

type KeySpec struct {
	Name  string
	Usage KeyUsage
}

type Key[T interface{}] struct {
	ID      string
	KeySpec KeySpec
	Value   T
}

type RSAPublicKeyHash string

type RSAPublicKeySpec struct {
	KeySpec
	Hash      RSAPublicKeyHash
	KeyLength int
}

type RSAPublicKey = Key[*rsa.PublicKey]

func EncodeRSAPublicKey() (string, error) {

	template := &x509.Certificate{
		// TODO: I don't know how I should fill these fields. Study more!
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"{\"kid\": \"%s\",\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"%s\",\"alg\":\"%s\",\"x5c\":[\"%s\"]}",
		id,
		alg,
		base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		base64.RawURLEncoding.EncodeToString(certDer),
	), nil
}
