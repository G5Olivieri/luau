// https://datatracker.ietf.org/doc/html/rfc7517
package jwk

import "net/url"

type KeyOps string
type KeyAlg string
type KeyUse string
type KeyType string

var (
	KeyOpsSign       KeyOps = "sign"
	KeyOpsVerify     KeyOps = "verify"
	KeyOpsEncrypt    KeyOps = "encrypt"
	KeyOpsDecrypt    KeyOps = "decrypt"
	KeyOpsWrapKey    KeyOps = "wrapKey"
	KeyOpsUnwrapKey  KeyOps = "unwrapKey"
	KeyOpsDeriveKey  KeyOps = "deriveKey"
	KeyOpsDeriveBits KeyOps = "deriveBits"

	KeyAlgHS256 KeyAlg = "HS256"
	KeyAlgHS384 KeyAlg = "HS384"
	KeyAlgHS512 KeyAlg = "HS512"

	KeyAlgRS256 KeyAlg = "RS256"
	KeyAlgRS384 KeyAlg = "RS384"
	KeyAlgRS512 KeyAlg = "RS512"

	KeyAlgPS256 KeyAlg = "PS256"
	KeyAlgPS384 KeyAlg = "PS384"
	KeyAlgPS512 KeyAlg = "PS512"

	KeyAlgES256 KeyAlg = "ES256"
	KeyAlgES384 KeyAlg = "ES384"
	KeyAlgES512 KeyAlg = "ES512"

	KeyUseSig KeyUse = "sig"
	KeyUseEnc KeyUse = "enc"

	KeyTypeOct KeyType = "oct"
	KeyTypeEC  KeyType = "EC"
	KeyTypeRSA KeyType = "RSA"
)

type JWK struct {
	Kty     KeyType  `json:"kty"`
	Use     *KeyUse  `json:"use,omitempty"`
	KeyOps  []KeyOps `json:"key_ops"`
	Alg     *KeyAlg  `json:"alg,omitempty"`
	Kid     *string  `json:"kid,omitempty"`
	X5u     *url.URL `json:"x5u,omitempty"`
	X5c     []string `json:"x5c,omitempty"`
	X5t     *string  `json:"x5t,omitempty"`
	X5tS256 *string  `json:"x5t#S256,omitempty"`

	// RSA Public Key
	E *string `json:"e,omitempty"`
	N *string `json:"n,omitempty"`

	// EC Public Key
	Curve *string `json:"crv,omitempty"`
	X     *string `json:"x,omitempty"`
	Y     *string `json:"y,omitempty"`
}
