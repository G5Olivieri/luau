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

func EncodeRSAPublicKey(rsaKey *rsa.PrivateKey, name, id, alg string) (string, error) {
	template := &x509.Certificate{
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
